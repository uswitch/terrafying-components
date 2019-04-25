
import json
import os

from datetime import datetime, timezone
from hashlib import md5
from tempfile import mkdtemp
from urllib.parse import urlparse

import boto3
import certbot.main

from jwcrypto.jwk import JWK

def certificate_directories(client, bucket, prefix):
    paginator = client.get_paginator('list_objects')
    operation_parameters = {
        "Bucket": bucket,
        "Prefix": prefix,
    }

    page_iterator = paginator.paginate(**operation_parameters)

    return [
        obj["Key"][len(prefix)+1:-5]
        for page in page_iterator
        for obj in page["Contents"]
        if obj["Key"].endswith("/cert")
    ]

def renew_certificate(email, url, config_path, work_path, logs_path, csr_path, key_path, cert_path):
    return certbot.main.main([
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--config-dir", config_path,
        "--work-dir", work_path,
        "--logs-dir", logs_path,
        "--email", email,
        "--server", url,
        "--dns-route53",
        "--csr", csr_path,
        "--cert-path", cert_path,
        "--key-path", key_path,
    ])

# setup account based on https://github.com/certbot/certbot/blob/v0.33.1/certbot/account.py
def setup_account(url, key_pem, config_path):
    key_hash = md5(key_pem).hexdigest()
    key_jwk = JWK.from_pem(key_pem).export()

    acme_url = urlparse(config["url"])
    acme_host = acme_url.hostname

    account_path = os.path.join(config_path, "accounts", acme_host, "directory", key_hash)

    os.makedirs(account_path, exist_ok=True)

    with open(os.path.join(account_path, "regr.json"), "w") as regr_file:
        json.dump({
            "body": {},
            "uri": config["id"],
        }, regr_file)

    with open(os.path.join(account_path, "meta.json"), "w") as meta_file:
        json.dump({
            "creation_dt": datetime.now(timezone.utc).astimezone().isoformat(),
            "creation_host": "wibble",
        }, meta_file)

    with open(os.path.join(account_path, "private_key.json"), "w") as jwk_file:
        jwk_file.write(key_jwk)


def handler(event, context):
    ca_bucket = os.environ["CA_BUCKET"]
    ca_prefix = os.environ["CA_PREFIX"]

    working_dir = mkdtemp()
    config_path = os.path.join(working_dir, "config")
    work_path = os.path.join(working_dir, "work")
    logs_path = os.path.join(working_dir, "logs")

    account_key_key = os.path.join(ca_prefix, "account.key")
    config_json_key = os.path.join(ca_prefix, "config.json")

    obj = client.get_object(Bucket=ca_bucket, Key=config_json_key)
    config = json.loads(obj['Body'].read().decode('utf-8'))

    client = boto3.client('s3')

    obj = client.get_object(Bucket=ca_bucket, Key=account_key_key)
    key_pem = json.loads(obj['Body'].read().decode('utf-8'))

    setup_account(config["url"], key_pem, config_path)

    for certificate_directory in certificate_directories(client, ca_bucket, ca_prefix):
        cert_working_dir = os.path.join(working_dir, certificate_directory)

        os.mkdir(cert_working_dir)

        key_key = os.path.join(ca_prefix, certificate_directory, "key")
        key_path = os.path.join(cert_working_dir, "key")

        client.download_file(ca_bucket, key_key, key_path)

        csr_key = os.path.join(ca_prefix, certificate_directory, "csr")
        csr_path = os.path.join(cert_working_dir, "csr")

        client.download_file(ca_bucket, csr_key, csr_path)

        cert_path = os.path.join(cert_working_dir, "cert")

        renew_certificate(config["email_address"], config["url"], config_path, work_path, logs_path, csr_path, key_path, cert_path)

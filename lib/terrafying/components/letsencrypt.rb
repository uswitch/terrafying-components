# frozen_string_literal: true

require 'terrafying/components/ca'
require 'terrafying/generator'
require 'open-uri'
module Terrafying
  module Components
    class LetsEncrypt < Terrafying::Context

      attr_reader :name, :source

      include CA

      def self.create(name, bucket, options={})
        LetsEncrypt.new.create name, bucket, options
        LetsEncrypt.new.renew name, bucket, options
      end

      def initialize
        super
        @acme_providers = setup_providers
      end

      def setup_providers
        {
          staging: {
            url: 'https://acme-staging-v02.api.letsencrypt.org/directory',
            ref: provider(:acme, alias: :staging, server_url: 'https://acme-staging-v02.api.letsencrypt.org/directory'),
            ca_cert: 'https://letsencrypt.org/certs/fakeleintermediatex1.pem'
          },
          live: {
            url: 'https://acme-v02.api.letsencrypt.org/directory',
            ref: provider(:acme, alias: :live, server_url: 'https://acme-v02.api.letsencrypt.org/directory'),
            ca_cert: 'https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt'
          }
        }
      end

      def create(name, bucket, options={})
        options = {
          prefix: "",
          provider: :staging,
          email_address: "cloud@uswitch.com",
          public_certificate: false,
          curve: "P384",
        }.merge(options)

        @name = name
        @bucket = bucket
        @prefix = options[:prefix]
        @acme_provider = @acme_providers[options[:provider]]

        provider :tls, {}

        resource :tls_private_key, "#{@name}-account", {
                   algorithm: "RSA",
                 }

        resource :acme_registration, "#{@name}-reg", {
          provider: @acme_provider[:ref],
          account_key_pem: output_of(:tls_private_key, "#{@name}-account", "private_key_pem"),
          email_address: options[:email_address],
        }

        @account_key = output_of(:acme_registration, "#{@name}-reg", 'account_key_pem')

        resource :aws_s3_bucket_object, "#{@name}-account", {
          bucket: @bucket,
          key: File.join('', @prefix, @name, "account.key"),
          content: @account_key,
        }

        resource :aws_s3_bucket_object, "#{@name}-config", {
          bucket: @bucket,
          key: File.join('', @prefix, @name, "config.json"),
          content: {
            id: output_of(:acme_registration, "#{@name}-reg", "id"),
            url: @acme_provider[:url],
            email_address: options[:email_address],
          }.to_json,
        }

        @ca_cert_acl = options[:public_certificate] ? 'public-read' : 'private'

        open(@acme_provider[:ca_cert], 'rb') do |cert|
          @ca_cert = cert.read
        end

        resource :aws_s3_bucket_object, object_name(@name, :cert), {
          bucket: @bucket,
          key: object_key(@name, :cert),
          content: @ca_cert,
          acl: @ca_cert_acl
        }

        @source = object_url(@name, :cert)

        self
      end

      def create_keypair_in(ctx, name, options={})
        options = {
          common_name: name,
          organization: "uSwitch Limited",
          dns_names: [],
          ip_addresses: [],
          curve: "P384",
        }.merge(options)

        key_ident = "#{@name}-#{tf_safe(name)}"

        ctx.resource :tls_private_key, key_ident, {
                       algorithm: "ECDSA",
                       ecdsa_curve: options[:curve],
                     }

        ctx.resource :tls_cert_request, key_ident, {
                       key_algorithm: "ECDSA",
                       private_key_pem: output_of(:tls_private_key, key_ident, :private_key_pem),
                       subject: {
                         common_name: options[:common_name],
                         organization: options[:organization],
                       },
                       dns_names: options[:dns_names],
                       ip_addresses: options[:ip_addresses],
                     }

        ctx.resource :acme_certificate, key_ident, {
                       provider: @acme_provider[:ref],
                       account_key_pem: @account_key,
                       min_days_remaining: 0, # the lambda will take over renewal
                       dns_challenge: {
                         provider: "route53",
                       },
                       certificate_request_pem: output_of(:tls_cert_request, key_ident, :cert_request_pem),
                     }

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-key", {
                       bucket: @bucket,
                       key: File.join('', @prefix, @name, name, "key"),
                       content: output_of(:tls_private_key, key_ident, :private_key_pem),
                     }

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-csr", {
                       bucket: @bucket,
                       key: File.join('', @prefix, @name, name, "csr"),
                       content: output_of(:tls_cert_request, key_ident, :cert_request_pem),
                     }

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-cert", {
                       bucket: @bucket,
                       key: File.join('', @prefix, @name, name, "cert"),
                       content: output_of(:acme_certificate, key_ident, :certificate_pem).to_s + @ca_cert,
                       lifecycle: { ignore_changes: [ "content" ] }, # the lambda will be updating it
                     }

        reference_keypair(ctx, name)
      end

      def renew(name, bucket, options={})
        options = {
          prefix: "",
          provider: :staging,
        }.merge(options)

        @name = name
        @bucket = bucket
        @prefix = options[:prefix]

        resource :aws_lambda_function, "#{@name}-lambda", {
          s3_bucket: "uswitch-certbot-lambda",
          s3_key: "certbot-lambda.zip",
          handler: "main.handler",
          # The filebase64sha256() function is available in Terraform 0.11.12 and later
          # For Terraform 0.11.11 and earlier, use the base64sha256() function and the file() function:
          # source_code_hash = "${base64sha256(file("lambda_function_payload.zip"))}"
          source_code_hash: "${filebase64sha256(\"certbot-lambda.zip\")}",
          runtime: "python3.7",
          role: "${aws_iam_role.certbot_lambda_execution.arn}", # do this bit
          environment:{
            variables: {
              CA_BUCKET: @bucket,
              CA_PREFIX: @prefix,
            }
          }
        }
        # Lambda execution role
        aws_iam_role :certbot_lambda_execution, {
          name: "certbot_lambda_execution",
          assume_role_policy: IAM::AssumePolicy.new
                              .service_principal('lambda.amazonaws.com')
                              .policy.to_json
        }

        # Lambda execution role policy to read/write certs to S3
        add! S3::Policy.create('certbot-lambda-execution_s3')
                       .bucket('uswitch-letsencrypt')
                         .prefix('yggdrasil').allow(:read, :write)
                       .attach_to_roles('certbot_lambda_execution')
        end

    end
  end
end

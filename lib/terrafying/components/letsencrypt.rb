# frozen_string_literal: true

require 'terrafying/components/ca'
require 'terrafying/generator'
require 'open-uri'
module Terrafying
  module Components
    class LetsEncrypt < Terrafying::Context
      attr_reader :name, :source

      include CA

      def self.create(name, bucket, options = {})
        LetsEncrypt.new.create name, bucket, options
      end
      def self.find(name, bucket, options = {})
        LetsEncrypt.new.find name, bucket, options
      end

      def initialize
        super
        @acme_providers = setup_providers
        @zones = []
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

      def create(name, bucket, options = {})
        options = {
          prefix: '',
          provider: :staging,
          email_address: 'cloud@uswitch.com',
          public_certificate: false,
          curve: 'P384',
          rsa_bits: '3072',
          use_external_dns: false,
          renewing: false
        }.merge(options)

        @name = name
        @bucket = bucket
        @prefix = options[:prefix]
        @acme_provider = @acme_providers[options[:provider]]
        @use_external_dns = options[:use_external_dns]
        @renewing = options[:renewing]
        @prefix_path = [@prefix, @name].reject(&:empty?).join("/")

        renew() if @renewing

        provider :tls, {}

        resource :tls_private_key, "#{@name}-account",
                  algorithm: "RSA",
                  rsa_bits: options[:rsa_bits]

        resource :acme_registration, "#{@name}-reg",
                 provider: @acme_provider[:ref],
                 account_key_pem: output_of(:tls_private_key, "#{@name}-account", 'private_key_pem'),
                 email_address: options[:email_address]

        @account_key = output_of(:acme_registration, "#{@name}-reg", 'account_key_pem')

        resource :aws_s3_bucket_object, "#{@name}-account",
                 bucket: @bucket,
                 key: File.join('', @prefix, @name, 'account.key'),
                 content: @account_key

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

        resource :aws_s3_bucket_object, object_name(@name, :cert),
                 bucket: @bucket,
                 key: object_key(@name, :cert),
                 content: @ca_cert,
                 acl: @ca_cert_acl

        @source = object_url(@name, :cert)

        resource :aws_s3_bucket_object, "#{@name}-metadata",
                 bucket: @bucket,
                 key: File.join('', @prefix, @name, '.metadata'),
                 content: {
                   provider: options[:provider].to_s,
                   public_certificate: options[:public_certificate],
                   use_external_dns: options[:use_external_dns],
                 }.to_json

        self
      end

      def find(name, bucket, prefix: "")
        @name = name
        @bucket = bucket
        @prefix = prefix

        # load the rest of the config from an s3 metadata file
        metadata_obj = aws.s3_object(@bucket, [@prefix, @name, '.metadata'].compact.reject(&:empty?).join('/'))
        metadata = JSON.parse(metadata_obj, symbolize_names: true)

        @acme_provider = @acme_providers[metadata[:provider].to_sym]
        @use_external_dns = metadata[:use_external_dns]
        @ca_cert_acl = metadata[:public_certificate] ? 'public-read' : 'private'

        account_key_obj = data :aws_s3_bucket_object, "#{@name}-account",
                               bucket: @bucket,
                               key: File.join('', @prefix, @name, 'account.key')

        @account_key = account_key_obj["body"]

        open(@acme_provider[:ca_cert], 'rb') do |cert|
          @ca_cert = cert.read
        end

        @source = object_url(@name, :cert)

        self
      end

      def create_keypair_in(ctx, name, options = {})
        options = {
          common_name: name,
          organization: "uSwitch Limited",
          dns_names: [],
          ip_addresses: [],
          curve: "P384"
        }.merge(options)

        @zones << options[:zone] if options[:zone]

        key_ident = "#{@name}-#{tf_safe(name)}"

        ctx.resource :tls_private_key, key_ident,
                     algorithm: 'ECDSA',
                     ecdsa_curve: options[:curve]

        ctx.resource :tls_cert_request, key_ident,
                     key_algorithm: 'ECDSA',
                     private_key_pem: output_of(:tls_private_key, key_ident, :private_key_pem),
                     subject: {
                       common_name: options[:common_name],
                       organization: options[:organization]
                     },
                     dns_names: options[:dns_names],
                     ip_addresses: options[:ip_addresses]

        cert_options = {}
        cert_options[:recursive_nameservers] = ['1.1.1.1:53', '8.8.8.8:53', '8.8.4.4:53'] if @use_external_dns

        ctx.resource :acme_certificate, key_ident, {
                     provider: @acme_provider[:ref],
                     account_key_pem: @account_key,
                     min_days_remaining: 21,
                     dns_challenge: {
                       provider: 'route53'
                     },
                     certificate_request_pem: output_of(:tls_cert_request, key_ident, :cert_request_pem)
                   }.merge(cert_options)

        csr_version = "${sha256(tls_cert_request.#{key_ident}.cert_request_pem)}"

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-csr",
                     bucket: @bucket,
                     key: object_key(name, :csr, csr_version),
                     content: output_of(:tls_cert_request, key_ident, :cert_request_pem)

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-csr-latest",
                     bucket: @bucket,
                     key: object_key(name, :csr, 'latest'),
                     content: csr_version

        key_version = "${sha256(tls_private_key.#{key_ident}.private_key_pem)}"

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-key",
                     bucket: @bucket,
                     key: object_key(name, :key, key_version),
                     content: output_of(:tls_private_key, key_ident, :private_key_pem)

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-key-latest",
                     bucket: @bucket,
                     key: object_key(name, :key, 'latest'),
                     content: key_version

        cert_version = "${sha256(acme_certificate.#{key_ident}.certificate_pem)}"

        cert_config = {
                     bucket: @bucket,
                     key: object_key(name, :cert, cert_version),
                     content: output_of(:acme_certificate, key_ident, :certificate_pem).to_s + @ca_cert,
        }
        cert_config[:lifecycle] = { ignore_changes: [ "content" ] } if @renewing

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-cert", cert_config

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-cert-latest",
                     bucket: @bucket,
                     key: object_key(name, :cert, 'latest'),
                     content: cert_version

        reference_keypair(ctx, name, key_version: key_version, cert_version: cert_version)
      end

      def output_with_children
        iam_policy = {}
        if @renewing
          iam_policy = resource :aws_iam_policy, "#{@name}_lambda_execution_policy", {
          name: "#{@name}_lambda_execution_policy",
          description: "A policy for the #{@name}_lambda function to access S3 and R53",
          policy: JSON.pretty_generate(
                {
                  Version: "2012-10-17",
                  Statement: [
                    {
                      Action: [
                        "s3:Put*",
                        "s3:Get*",
                        "s3:DeleteObject"
                      ],
                      Resource: [
                        "arn:aws:s3:::#{@bucket}/#{@prefix_path}/*"
                      ],
                      Effect: "Allow"
                    },
                    {
                      Action: [
                        "s3:ListBucket"
                      ],
                      Resource: [
                        "arn:aws:s3:::#{@bucket}"
                      ],
                      Effect: "Allow"
                    },
                    {
                      Action: [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                      ],
                      Resource: [
                        "arn:aws:logs:*:*:*"
                      ],
                      Effect: "Allow"
                    },
                    {
                      Action: [
                        "route53:ListHostedZones",
                      ],
                      Resource: [
                        "*"
                      ],
                      Effect: "Allow"
                    },
                    {
                      Action: [
                        "route53:GetChange",
                      ],
                      Resource: [
                        "arn:aws:route53:::change/*"
                      ],
                      Effect: "Allow"
                    },
                    {
                      Action: [
                        "route53:ChangeResourceRecordSets",
                      ],
                      Resource:
                        @zones.compact.map { | zone |
                          "arn:aws:route53:::#{zone.id[1..-1]}"
                        },
                      Effect: "Allow"
                    }
                  ]
                }
              )
            }
          end
        super
      end

      def renew
        execution_role = resource :aws_iam_role, "#{@name}_lambda_execution", {
          name: "#{@name}_lambda_execution",
          assume_role_policy: JSON.pretty_generate(
                {
                  Version: "2012-10-17",
                  Statement: [
                    {
                      Action: "sts:AssumeRole",
                      Principal: {
                        Service: "lambda.amazonaws.com"
                        },
                      Effect: "Allow",
                      Sid: ""
                    }
                  ]
                }
              )
            }

        lamda_function = resource :aws_lambda_function, "#{@name}_lambda", {
          function_name: "#{@name}_lambda",
          s3_bucket: "uswitch-certbot-lambda",
          s3_key: "certbot-lambda.zip",
          handler: "main.handler",
          runtime: "python3.7",
          timeout: "900",
          role: execution_role["arn"],
          environment:{
            variables: {
              CA_BUCKET: @bucket,
              CA_PREFIX: @prefix_path
            }
          }
        }

        resource :aws_iam_role_policy_attachment, "#{@name}_lambda_policy_attachment", {
          role: execution_role["name"],
          policy_arn: "${aws_iam_policy.#{@name}_lambda_execution_policy.arn}"
        }

        rand_hour = rand(0..23).to_s
        event_rule = resource :aws_cloudwatch_event_rule, "once_per_day", {
          name: "once-per-day",
          description: "Fires once per day",
          schedule_expression: "cron(0 #{rand_hour} * * ? *)"
        }

        resource :aws_cloudwatch_event_target, "#{@name}_lambda_event_target", {
          rule: event_rule["name"],
          target_id: lamda_function["id"],
          arn: lamda_function["arn"]
        }

        resource :aws_lambda_permission, "allow_cloudwatch_to_invoke_#{@name}_lambda", {
          statement_id: "AllowExecutionFromCloudWatch",
          action: "lambda:InvokeFunction",
          function_name: lamda_function["function_name"],
          principal: "events.amazonaws.com",
          source_arn: event_rule["arn"]
        }
        self
      end

    end
  end
end

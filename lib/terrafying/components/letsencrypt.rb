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

      def initialize
        super
        @acme_providers = setup_providers
      end

      def setup_providers
        {
          staging: {
            ref: provider(:acme, alias: :staging, server_url: 'https://acme-staging-v02.api.letsencrypt.org/directory'),
            ca_cert: 'https://letsencrypt.org/certs/fakeleintermediatex1.pem'
          },
          live: {
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
          curve: 'P384'
        }.merge(options)

        @name = name
        @bucket = bucket
        @prefix = options[:prefix]
        @acme_provider = @acme_providers[options[:provider]]

        provider :tls, {}

        resource :tls_private_key, "#{@name}-account",
                 algorithm: 'ECDSA',
                 ecdsa_curve: options[:curve]

        resource :acme_registration, "#{@name}-reg",
                 provider: @acme_provider[:ref],
                 account_key_pem: output_of(:tls_private_key, "#{@name}-account", 'private_key_pem'),
                 email_address: options[:email_address]

        @account_key = output_of(:acme_registration, "#{@name}-reg", 'account_key_pem')

        resource :aws_s3_bucket_object, "#{@name}-account",
                 bucket: @bucket,
                 key: File.join('', @prefix, @name, 'account.key'),
                 content: @account_key

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

        self
      end

      def create_keypair_in(ctx, name, options = {})
        options = {
          common_name: name,
          organization: 'uSwitch Limited',
          validity_in_hours: 24 * 365,
          allowed_uses: %w[
            nonRepudiation
            digitalSignature
            keyEncipherment
          ],
          dns_names: [],
          ip_addresses: [],
          min_days_remaining: 21,
          curve: 'P384'
        }.merge(options)

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

        ctx.resource :acme_certificate, key_ident,
                     provider: @acme_provider[:ref],
                     account_key_pem: @account_key,
                     min_days_remaining: options[:min_days_remaining],
                     dns_challenge: {
                       provider: 'route53'
                     },
                     certificate_request_pem: output_of(:tls_cert_request, key_ident, :cert_request_pem)

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-key",
                     bucket: @bucket,
                     key: File.join('', @prefix, @name, name, "${sha256(tls_private_key.#{key_ident}.private_key_pem)}", 'key'),
                     content: output_of(:tls_private_key, key_ident, :private_key_pem)

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-cert",
                     bucket: @bucket,
                     key: File.join('', @prefix, @name, name, "${sha256(acme_certificate.#{key_ident}.certificate_pem)}", 'cert'),
                     content: output_of(:acme_certificate, key_ident, :certificate_pem).to_s + @ca_cert

        reference_keypair(ctx, name)
      end
    end
  end
end


require 'terrafying/components/ca'
require 'terrafying/generator'
require 'open-uri'
module Terrafying

  module Components

    class LetsEncrypt < Terrafying::Context

      attr_reader :name, :source

      PROVIDERS = {
        staging: {
          server_url: 'https://acme-staging.api.letsencrypt.org/directory',
          ca_cert:    'https://letsencrypt.org/certs/fakeleintermediatex1.pem'
        },
        live:    {
          server_url: 'https://acme-v01.api.letsencrypt.org/directory',
          ca_cert:    'https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt'
        }
      }.freeze

      include CA

      def self.create(name, bucket, options={})
        LetsEncrypt.new.create name, bucket, options
      end

      def initialize()
        super
      end

      def create(name, bucket, options={})
        options = {
          prefix: "",
          provider: :staging,
          email_address: "cloud@uswitch.com",
          public_certificate: false,
        }.merge(options)

        @name = name
        @bucket = bucket
        @prefix = options[:prefix]
        @provider = PROVIDERS[options[:provider].to_sym]

        provider :acme, {}
        provider :tls, {}

        resource :tls_private_key, "#{@name}-account", {
                   algorithm: "ECDSA",
                   ecdsa_curve: "P384",
                 }

        @account_key = output_of(:tls_private_key, "#{@name}-account", "private_key_pem")

        @registration_url = resource :acme_registration, "#{@name}-reg", {
                                       server_url: @provider[:server_url],
                                       account_key_pem: @account_key,
                                       email_address: options[:email_address],
                                     }

        resource :aws_s3_bucket_object, "#{@name}-account", {
                   bucket: @bucket,
                   key: File.join(@prefix, @name, "account.key"),
                   content: @account_key,
                 }

        @ca_cert_acl = options[:public_certificate] ? 'public-read' : 'private'

        open(@provider[:ca_cert], 'rb') do |cert|
          @ca_cert = cert.read
        end

        resource :aws_s3_bucket_object, "#{@name}-cert", {
            bucket: @bucket,
            key: File.join(@prefix, @name, "ca.cert"),
            content: @ca_cert,
            acl: @ca_cert_acl
        }

        @source = File.join("s3://", @bucket, @prefix, @name, "ca.cert")

        self
      end

      def create_keypair_in(ctx, name, options={})
        options = {
          common_name: name,
          organization: "uSwitch Limited",
          validity_in_hours: 24 * 365,
          allowed_uses: [
            "nonRepudiation",
            "digitalSignature",
            "keyEncipherment"
          ],
          dns_names: [],
          ip_addresses: [],
          min_days_remaining: 21,
        }.merge(options)

        key_ident = "#{@name}-#{tf_safe(name)}"

        ctx.resource :tls_private_key, key_ident, {
                       algorithm: "ECDSA",
                       ecdsa_curve: "P384",
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
                       server_url: @provider[:server_url],
                       account_key_pem: @account_key,
                       registration_url: @registration_url,
                       min_days_remaining: options[:min_days_remaining],
                       dns_challenge: {
                         provider: "route53",
                       },
                       certificate_request_pem: output_of(:tls_cert_request, key_ident, :cert_request_pem),
                     }

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-key", {
                       bucket: @bucket,
                       key: File.join(@prefix, @name, name, "key"),
                       content: output_of(:tls_private_key, key_ident, :private_key_pem),
                     }

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-cert", {
                       bucket: @bucket,
                       key: File.join(@prefix, @name, name, "cert"),
                       content: output_of(:acme_certificate, key_ident, :certificate_pem).to_s + '\n' + @ca_cert,
                     }

        reference_keypair(ctx, name)
      end

    end
  end
end

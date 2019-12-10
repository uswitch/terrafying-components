# frozen_string_literal: true

require 'terrafying/components/ca'
require 'terrafying/generator'

module Terrafying
  module Components
    class SelfSignedCA < Terrafying::Context
      attr_reader :name, :source, :ca_key

      include CA

      def self.create(name, bucket, options = {})
        SelfSignedCA.new.create name, bucket, options
      end

      def initialize
        super
      end

      def create(name, bucket, options = {})
        options = {
          prefix: '',
          common_name: name,
          organization: 'uSwitch Limited',
          public_certificate: false,
          curve: 'P384'
        }.merge(options)

        @name = name
        @bucket = bucket
        @prefix = options[:prefix]
        @algorithm = options[:algorithm] || 'ECDSA'

        @ident = "#{name}-ca"

        cert_acl = if options[:public_certificate]
                     'public-read'
                   else
                     'private'
                   end

        @source = object_url(@name, :cert)

        if options[:ca_key] && options[:ca_cert]
          @ca_key = options[:ca_key]
          @ca_cert = options[:ca_cert]
          resource :aws_s3_bucket_object, "#{@name}-cert",
                   bucket: @bucket,
                   key: object_key(@name, :cert),
                   content: @ca_cert,
                   acl: cert_acl
          return self
        end

        if options.key? :depends_on
          depends_on = options[:depends_on]
        else

        provider :tls, {}

        resource :tls_private_key, @ident,
                 algorithm: @algorithm,
                 ecdsa_curve: options[:curve],
                 depends_on: depends_on

        resource :tls_self_signed_cert, @ident,
                 key_algorithm: @algorithm,
                 private_key_pem: output_of(:tls_private_key, @ident, :private_key_pem),
                 subject: {
                   common_name: options[:common_name],
                   organization: options[:organization]
                 },
                 is_ca_certificate: true,
                 validity_period_hours: 24 * 365,
                 allowed_uses: %w[
                   certSigning
                   digitalSignature
                 ],
                 depends_on: depends_on

        @ca_key = output_of(:tls_private_key, @ident, :private_key_pem)
        @ca_cert = output_of(:tls_self_signed_cert, @ident, :cert_pem)

        resource :aws_s3_bucket_object, object_name(@name, :cert),
                 bucket: @bucket,
                 key: object_key(@name, :cert),
                 content: @ca_cert,
                 acl: cert_acl

        self
      end

      def keypair
        @ca_key_ref ||= resource :aws_s3_bucket_object, object_name(@name, :key),
                                 bucket: @bucket,
                                 key: File.join('', @prefix, @name, 'ca.key'),
                                 content: @ca_key

        {
          ca: self,
          path: {
            cert: File.join('/etc/ssl', @name, 'ca.cert'),
            key: File.join('/etc/ssl', @name, 'ca.key')
          },
          source: {
            cert: object_url(@name, :cert),
            key: object_url(@name, :key)
          },
          resources: [
            "aws_s3_bucket_object.#{object_name(@name, :key)}",
            "aws_s3_bucket_object.#{object_name(@name, :cert)}"
          ],
          iam_statement: {
            Effect: 'Allow',
            Action: [
              's3:GetObjectAcl',
              's3:GetObject'
            ],
            Resource: [
              object_arn(@name, :cert),
              object_arn(@name, :key)
            ]
          }
        }
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
          curve: 'P384'
        }.merge(options)

        key_ident = object_ident(name)

        ctx.resource :tls_private_key, key_ident,
                     algorithm: @algorithm,
                     ecdsa_curve: options[:curve]

        ctx.resource :tls_cert_request, key_ident,
                     key_algorithm: @algorithm,
                     private_key_pem: output_of(:tls_private_key, key_ident, :private_key_pem),
                     subject: {
                       common_name: options[:common_name],
                       organization: options[:organization]
                     },
                     dns_names: options[:dns_names],
                     ip_addresses: options[:ip_addresses]

        ctx.resource :tls_locally_signed_cert, key_ident,
                     cert_request_pem: output_of(:tls_cert_request, key_ident, :cert_request_pem),
                     ca_key_algorithm: @algorithm,
                     ca_private_key_pem: @ca_key,
                     ca_cert_pem: @ca_cert,
                     validity_period_hours: options[:validity_in_hours],
                     allowed_uses: options[:allowed_uses]

        key_version = "${sha256(tls_private_key.#{key_ident}.private_key_pem)}"
        ctx.resource :aws_s3_bucket_object, object_name(name, :key),
                     bucket: @bucket,
                     key: object_key(name, :key, key_version),
                     content: output_of(:tls_private_key, key_ident, :private_key_pem)
        ctx.resource :aws_s3_bucket_object, "#{key_ident}-key-latest",
                     bucket: @bucket,
                     key: object_key(name, :key, 'latest'),
                     content: key_version

        cert_version = "${sha256(tls_locally_signed_cert.#{key_ident}.cert_pem)}"
        ctx.resource :aws_s3_bucket_object, object_name(name, :cert),
                     bucket: @bucket,
                     key: object_key(name, :cert, cert_version),
                     content: output_of(:tls_locally_signed_cert, key_ident, :cert_pem)
        ctx.resource :aws_s3_bucket_object, "#{key_ident}-cert-latest",
                     bucket: @bucket,
                     key: object_key(name, :cert, 'latest'),
                     content: cert_version

        reference_keypair(ctx, name, key_version: key_version, cert_version: cert_version)
      end
    end
  end
end

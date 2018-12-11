@algorithm
require 'terrafying/components/ca'
require 'terrafying/generator'

module Terrafying

  module Components

    class SelfSignedCA < Terrafying::Context

      attr_reader :name, :source, :ca_key

      include CA

      def self.create(name, bucket, options={})
        SelfSignedCA.new.create name, bucket, options
      end

      def initialize()
        super
      end

      def create(name, bucket, options={})
        options = {
          prefix: "",
          common_name: name,
          organization: "uSwitch Limited",
          public_certificate: false,
        }.merge(options)

        @name = name
        @bucket = bucket
        @prefix = options[:prefix]
        @algorithm = options[:algorithm] || "ECDSA"

        @ident = "#{name}-ca"

        if options[:public_certificate]
          cert_acl = "public-read"
        else
          cert_acl = "private"
        end

        if options[:ca_key] && options[:ca_cert]
          @ca_key = options[:ca_key]
          @ca_cert = options[:ca_cert]
          resource :aws_s3_bucket_object, "#{@name}-cert", {
                     bucket: @bucket,
                     key: File.join(@prefix, @name, "ca.cert"),
                     content: @ca_cert,
                     acl: cert_acl,
                   }
          return self
        end

        provider :tls, {}

        resource :tls_private_key, @ident, {
                   algorithm: @algorithm,
                   ecdsa_curve: "P384",
                 }

        resource :tls_self_signed_cert, @ident, {
                   key_algorithm: @algorithm,
                   private_key_pem: output_of(:tls_private_key, @ident, :private_key_pem),
                   subject: {
                     common_name: options[:common_name],
                     organization: options[:organization],
                   },
                   is_ca_certificate: true,
                   validity_period_hours: 24 * 365,
                   allowed_uses: [
                     "certSigning",
                     "digitalSignature",
                   ],
                 }

        @source = File.join("s3://", @bucket, @prefix, @name, "ca.cert")

        @ca_key = output_of(:tls_private_key, @ident, :private_key_pem)
        @ca_cert = output_of(:tls_self_signed_cert, @ident, :cert_pem)

        resource :aws_s3_bucket_object, "#{@name}-cert", {
                   bucket: @bucket,
                   key: File.join(@prefix, @name, "ca.cert"),
                   content: @ca_cert,
                   acl: cert_acl,
                 }

        self
      end

      def keypair
        resource :aws_s3_bucket_object, "#{@name}-key", {
                   bucket: @bucket,
                   key: File.join(@prefix, @name, "ca.key"),
                   content: @ca_key,
                 }

        {
          ca: self,
          path: {
            cert: File.join("/etc/ssl", @name, "ca.cert"),
            key: File.join("/etc/ssl", @name, "ca.key"),
          },
          source: {
            cert: File.join("s3://", @bucket, @prefix, @name, "ca.cert"),
            key: File.join("s3://", @bucket, @prefix, @name, "ca.key"),
          },
          resources: [
            "aws_s3_bucket_object.#{@name}-key",
            "aws_s3_bucket_object.#{@name}-cert"
          ],
          iam_statement: {
            Effect: "Allow",
            Action: [
              "s3:GetObjectAcl",
              "s3:GetObject",
            ],
            Resource: [
              "arn:aws:s3:::#{File.join(@bucket, @prefix, @name, "ca.cert")}",
              "arn:aws:s3:::#{File.join(@bucket, @prefix, @name, "ca.key")}",
            ]
          }
        }
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
        }.merge(options)

        key_ident = "#{@name}-#{tf_safe(name)}"

        ctx.resource :tls_private_key, key_ident, {
                       algorithm: @algorithm,
                       ecdsa_curve: "P384",
                     }

        ctx.resource :tls_cert_request, key_ident, {
                       key_algorithm: @algorithm,
                       private_key_pem: output_of(:tls_private_key, key_ident, :private_key_pem),
                       subject: {
                         common_name: options[:common_name],
                         organization: options[:organization],
                       },
                       dns_names: options[:dns_names],
                       ip_addresses: options[:ip_addresses],
                     }

        ctx.resource :tls_locally_signed_cert, key_ident, {
                       cert_request_pem: output_of(:tls_cert_request, key_ident, :cert_request_pem),
                       ca_key_algorithm: @algorithm,
                       ca_private_key_pem: @ca_key,
                       ca_cert_pem: @ca_cert,
                       validity_period_hours: options[:validity_in_hours],
                       allowed_uses: options[:allowed_uses],
                     }

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-key", {
                       bucket: @bucket,
                       key: File.join(@prefix, @name, name, "key"),
                       content: output_of(:tls_private_key, key_ident, :private_key_pem),
                     }

        ctx.resource :aws_s3_bucket_object, "#{key_ident}-cert", {
                       bucket: @bucket,
                       key: File.join(@prefix, @name, name, "cert"),
                       content: output_of(:tls_locally_signed_cert, key_ident, :cert_pem),
                     }

        reference_keypair(ctx, name)
      end

    end

  end

end

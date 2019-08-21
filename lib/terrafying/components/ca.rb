# frozen_string_literal: true

module Terrafying
  module Components
    module CA
      def create_keypair(name, options = {})
        create_keypair_in(self, name, options)
      end

      def ca?(name)
        name == @name
      end

      def object_ident(name)
        (ca? name) ? @name : "#{@name}-#{tf_safe(name)}"
      end

      def object_name(name, type)
        "#{object_ident(name)}-#{type}"
      end

      def object_key(name, type, version = '')
        if ca? name
          File.join('', @prefix, @name, "ca.#{type}")
        else
          raise 'A non-ca object must have a version' if version.empty?

          File.join('', @prefix, @name, name, version, type.to_s)
        end
      end

      def object_arn(name, type, version = '*')
        key = object_key(name, type, version)

        "arn:aws:s3:::#{@bucket}#{key}"
      end

      def object_url(name, type, version: '')
        key = object_key(name, type, version)

        File.join('s3://', "#{@bucket}#{key}")
      end

      def find_keypair(name)
        reference_keypair(
          nil, name,
          key_version: aws.s3_object(@bucket, object_key(name, :key, 'latest')[1..-1]),
          cert_version: aws.s3_object(@bucket, object_key(name, :cert, 'latest')[1..-1]),
        )
      end

      def reference_keypair(ctx, name, key_version:, cert_version:)
        resources = []

        if ctx != nil
          resources += [
            "aws_s3_bucket_object.#{object_name(name, :key)}",
            "aws_s3_bucket_object.#{object_name(name, :cert)}"
          ]
          if ctx == self
            resources << "aws_s3_bucket_object.#{object_name(@name, :cert)}"
          end
        end

        ref = {
          name: name,
          ca: self,
          path: {
            cert: File.join('/etc/ssl', @name, name, 'cert'),
            key: File.join('/etc/ssl', @name, name, 'key')
          },
          source: {
            cert: object_url(name, :cert, version: cert_version),
            key: object_url(name, :key, version: key_version)
          },
          resources: resources,
          iam_statement: {
            Effect: 'Allow',
            Action: [
              's3:GetObjectAcl',
              's3:GetObject'
            ],
            Resource: [
              object_arn(@name, :cert),
              object_arn(name, :cert),
              object_arn(name, :key)
            ]
          }
        }

        ref
      end

      def <=>(other)
        @name <=> other.name
      end
    end
  end
end

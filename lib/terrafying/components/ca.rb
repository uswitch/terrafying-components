
module Terrafying

  module Components

    module CA

      def create_keypair(name, options={})
        create_keypair_in(self, name, options)
      end

      def ca?(name)
        name == @name
      end

      def object_ident(name)
        (ca? name) ? @name : "#{@name}-#{tf_safe(name)}"
      end

      def object_name(name, type)
        "#{object_ident(name)}-#{type.to_s}"
      end

      def object_key(name, type, version='')
        if (ca? name)
          File.join('', @prefix, @name, "ca.#{type.to_s}")
        else
          File.join('', @prefix, @name, name, type.to_s)
        end
      end

      def object_arn(name, type, version="*")
        key = object_key(name, type, version)

        "arn:aws:s3:::#{@bucket}#{key}"
      end

      def object_url(name, type)
        name = object_name(name, type)
        key = output_of(:aws_s3_bucket_object, name, :key).to_s

        File.join("s3://", "#{@bucket}#{key}")
      end

      def reference_keypair(ctx, name)
        ref = {
          name: name,
          ca: self,
          path: {
            cert: File.join("/etc/ssl", @name, name, "cert"),
            key: File.join("/etc/ssl", @name, name, "key"),
          },
          source: {
            cert: object_url(name, :cert),
            key: object_url(name, :key),
          },
          resources: [
            "aws_s3_bucket_object.#{object_name(name, :key)}",
            "aws_s3_bucket_object.#{object_name(name, :cert)}"
          ],
          iam_statement: {
            Effect: "Allow",
            Action: [
              "s3:GetObjectAcl",
              "s3:GetObject",
            ],
            Resource: [
              object_arn(@name, :cert),
              object_arn(name, :cert),
              object_arn(name, :key),
            ]
          }
        }

        if self == ctx
          ref[:resources] << "aws_s3_bucket_object.#{object_name(@name, :cert)}"
        end

        ref
      end

      def <=>(other)
        @name <=> other.name
      end

    end

  end

end

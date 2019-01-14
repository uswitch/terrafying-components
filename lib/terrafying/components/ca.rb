
module Terrafying

  module Components

    module CA

      def create_keypair(name, options={})
        create_keypair_in(self, name, options)
      end

      def path(object)
        output_of(:aws_s3_bucket_object, object, :bucket).to_s + output_of(:aws_s3_bucket_object, object, :key).to_s
      end

      def reference_keypair(ctx, name, key, cert)
        ref = {
          name: name,
          ca: self,
          path: {
            cert: File.join("/etc/ssl", @name, name, "cert"),
            key: File.join("/etc/ssl", @name, name, "key"),
          },
          source: {
            cert: File.join("s3://", path(cert)),
            key: File.join("s3://", path(key)),
          },
          resources: [
            "aws_s3_bucket_object.#{key}",
            "aws_s3_bucket_object.#{cert}"
          ],
          iam_statement: {
            Effect: "Allow",
            Action: [
              "s3:GetObjectAcl",
              "s3:GetObject",
            ],
            Resource: [
              "arn:aws:s3:::#{path(@name + '-cert')}",
              "arn:aws:s3:::#{path(cert)}",
              "arn:aws:s3:::#{path(key)}",
            ]
          }
        }

        if self == ctx
          ref[:resources] << "aws_s3_bucket_object.#{@name}-cert"
        end

        ref
      end

      def <=>(other)
        @name <=> other.name
      end

    end

  end

end

# frozen_string_literal: true

require 'terrafying'

module Terrafying

  module Components

    module Security

      class Store < Terrafying::Context

        attr_reader :name, :arn, :key_arn

        def self.create(name, **args)
          Store.new.create(name, **args)
        end

        def create(
              name,
              bucket_policy: nil,
              key_policy: nil
            )

          ident = tf_safe(name)

          @name = name
          @key = resource :aws_kms_key, ident, { policy: key_policy }
          @key_arn = @key["arn"]

          resource :aws_kms_alias, ident, {
                     name: "alias/#{name}",
                     target_key_id: @key["id"],
                   }

          @bucket = resource :aws_s3_bucket, ident, {
                               bucket: name,
                               acl: "private",
                               force_destroy: false,
                               versioning: {
                                 enabled: true,
                               },
                               policy: bucket_policy,
                               server_side_encryption_configuration: {
                                 rule: {
                                   apply_server_side_encryption_by_default: {
                                     kms_master_key_id: @key["arn"],
                                     sse_algorithm: "aws:kms",
                                   }
                                 }
                               },
                               tags: {
                                 Name: name,
                               }
                             }

          @arn = @bucket["arn"]

          self
        end

        def read_statements(prefix: "*")
          bucket_glob = [@bucket["arn"], prefix].join("/")

          [
            {
              Effect: "Allow",
              Action: [
                "s3:ListBucket",
                "s3:GetBucketAcl",
              ],
              Resource: @bucket["arn"],
            },
            {
              Effect: "Allow",
              Action: [
                "s3:GetObject*",
              ],
              Resource: bucket_glob,
            },
            {
              Effect: "Allow",
              Action: [
                "kms:Decrypt",
              ],
              Resource: @key["arn"],
            }
          ]
        end

        def write_statements(prefix: "*")
          bucket_glob = [@bucket["arn"], prefix].join("/")

          [
            {
              Effect: "Allow",
              Action: [
                "s3:ListBucket",
                "s3:GetBucketAcl",
              ],
              Resource: @bucket["arn"],
            },
            {
              Effect: "Allow",
              Action: [
                "s3:GetObject*",
                "s3:PutObject*",
              ],
              Resource: bucket_glob,
            },
            {
              Effect: "Allow",
              Action: [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey"
              ],
              Resource: @key["arn"],
            }
          ]
        end

      end

    end
  end
end

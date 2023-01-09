# frozen_string_literal: true

require 'terrafying'

module Terrafying

  module Components

    module Security

      class Config < Terrafying::Context

        def self.create(*args)
          Config.new.create(*args)
        end

        def self.bucket_statements(bucket_name)
          [
            {
              Sid: "AWSConfigAclCheck",
              Effect: "Allow",
              Principal: {
                Service: "config.amazonaws.com"
              },
              Action: "s3:GetBucketAcl",
              Resource: "arn:aws:s3:::#{bucket_name}"
            },
            {
              Sid: "AWSConfigWrite",
              Effect: "Allow",
              Principal: {
                Service: "config.amazonaws.com"
              },
              Action: "s3:PutObject",
              Resource: "arn:aws:s3:::#{bucket_name}/*",
              Condition: {
                StringEquals: {
                  "s3:x-amz-acl" => "bucket-owner-full-control"
                }
              }
            }
          ]
        end


        def create(
              name,
              provider:,
              store:,
              include_global:
            )

          ident = tf_safe(name)

          @name = name
          @ident = ident
          @provider = provider
          @include_global = include_global

          role = resource :aws_iam_role, ident, {
                            provider: @provider,
                            name: name,
                            assume_role_policy: {
                              Version: "2012-10-17",
                              Statement: [
                                {
                                  Action: "sts:AssumeRole",
                                  Principal: {
                                    Service: "config.amazonaws.com"
                                  },
                                  Effect: "Allow",
                                  Sid: ""
                                }
                              ]
                            }.to_json,
                          }

          policy = resource :aws_iam_policy, ident, {
                              provider: @provider,
                              policy: {
                                Version: "2012-10-17",
                                Statement: store.write_statements,
                              }.to_json,
                            }

          resource :aws_iam_role_policy_attachment, ident, {
                     provider: @provider,
                     role: role["name"],
                     policy_arn: policy["arn"],
                   }

          resource :aws_iam_role_policy_attachment, "#{ident}-config-policy", {
                     provider: @provider,
                     role: role["name"],
                     policy_arn: "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
                   }

          recorder = resource :aws_config_configuration_recorder, ident, {
                                provider: @provider,
                                name: name,
                                role_arn: role["arn"],
                                recording_group: {
                                  include_global_resource_types: include_global,
                                },
                              }

          resource :aws_config_delivery_channel, ident, {
                     provider: @provider,
                     s3_bucket_name: store.name,
                     s3_key_prefix: "config",
                     depends_on: [ "aws_config_configuration_recorder.#{ident}" ],
                   }

          resource :aws_config_configuration_recorder_status, ident, {
                     provider: @provider,
                     name: recorder["name"],
                     is_enabled: true,
                     depends_on: [ "aws_config_delivery_channel.#{ident}" ],
                   }

          self
        end

        def rule!(name:, source:, input: nil)
          ident = tf_safe("#{@name}-#{name}")

          if source.is_a? Symbol
            source_config = {
              owner: "AWS",
              source_identifier: source.to_s,
            }
          else
            raise "Can't support a non-AWS source at the moment"
          end

          resource :aws_config_config_rule, ident, {
                     provider: @provider,
                     name: name,
                     source: source_config,
                     input_parameters: input,
                   }
        end

        def cis_benchmark!

          if @include_global #IAM is a global resource, so the rules are only applicable where they are collected

            # 1.2	Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password
            rule!(
              name: "AllUsersMFA",
              source: :IAM_USER_MFA_ENABLED,
            )
            rule!(
              name: "AllConsoleUsersMFA",
              source: :MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS,
            )

            # 1.3	Ensure credentials unused for 90 days or greater are disabled
            rule!(
              name: "CredentialsOlder90Disabled",
              source: :IAM_USER_UNUSED_CREDENTIALS_CHECK,
              input: {
                "maxCredentialUsageAge" => "90",
              }.to_json,
            )

            # 1.4	Ensure access keys are rotated every 90 days or less
            rule!(
              name: "AccessKeysRotated",
              source: :ACCESS_KEYS_ROTATED,
              input: {
                "maxAccessKeyAge" => "90",
              }.to_json,
            )

            # 1.12	Ensure no root account access key exists
            rule!(
              name: "NoRootAccessKey",
              source: :IAM_ROOT_ACCESS_KEY_CHECK,
            )

            # 1.13	Ensure MFA is enabled for the "root" account
            rule!(
              name: "RootMFA",
              source: :ROOT_ACCOUNT_MFA_ENABLED,
            )

            # 1.14	Ensure hardware MFA is enabled for the "root" account
            rule!(
              name: "RootHardwareMFA",
              source: :ROOT_ACCOUNT_MFA_ENABLED,
            )

            # 1.16	Ensure IAM policies are attached only to groups or roles
            #rule!(
            #       name: "
            #     )


            # 1.22	Ensure IAM policies that allow full "*:*" administrative privileges are not created
            rule!(
              name: "NoIAMAdminAccess",
              source: :IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS,
            )

          end

          # 2.8	Ensure rotation for customer created CMKs is enabled
          #rule!(
          #       name: "EnsureCMKRotationEnabled",
          #       source: lamba,
          #     )

          # 2.9	Ensure VPC flow logging is enabled in all VPCs
          #rule!(
          #       name: "EnsureFlowLoggingEnabled",
          #       source: lamba,
          #     )


          # 4.1	Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
          # 4.2	Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
          rule!(
            name: "NoNaughtyIncomingTraffic",
            source: :RESTRICTED_INCOMING_TRAFFIC,
            input: {
              "blockedPort1" => "22",
              "blockedPort2" => "3389",
            }.to_json
          )

        end

      end

    end
  end
end

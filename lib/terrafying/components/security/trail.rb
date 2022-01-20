# frozen_string_literal: true

require 'terrafying'

module Terrafying

  module Components

    module Security

      class Trail < Terrafying::Context

        def self.create(*args)
          Trail.new.create(*args)
        end

        def self.bucket_statements(bucket_name)
          [
            {
              Sid: "AWSCloudTrailAclCheck",
              Effect: "Allow",
              Principal: {
                Service: "cloudtrail.amazonaws.com"
              },
              Action: "s3:GetBucketAcl",
              Resource: "arn:aws:s3:::#{bucket_name}"
            },
            {
              Sid: "AWSCloudTrailWrite",
              Effect: "Allow",
              Principal: {
                Service: "cloudtrail.amazonaws.com"
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

        def self.key_statements
          [
            {
              Sid: "Allow CloudTrail to encrypt logs",
              Effect: "Allow",
              Principal: {"Service": ["cloudtrail.amazonaws.com"]},
              Action: "kms:GenerateDataKey*",
              Resource: "*",
              Condition: {"StringLike": {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:#{aws.account_id}:trail/*"}}
            },
            {
              Sid: "Allow CloudTrail to describe key",
              Effect: "Allow",
              Principal: {"Service": ["cloudtrail.amazonaws.com"]},
              Action: "kms:DescribeKey",
              Resource: "*"
            },
            {
              Sid: "Allow principals in the account to decrypt log files",
              Effect: "Allow",
              Principal: {"AWS": "*"},
              Action: [
                "kms:Decrypt",
                "kms:ReEncryptFrom"
              ],
              Resource: "*",
              Condition: {
                StringEquals: {"kms:CallerAccount": aws.account_id},
                StringLike: {"kms:EncryptionContext:aws:cloudtrail:arn": "arn:aws:cloudtrail:*:#{aws.account_id}:trail/*"}
              }
            },
          ]
        end

        def create(
              name,
              store:,
              topic:,
              include_all_regions: true,
              include_all_organisation: true,
              ignore_buckets: []
            )

          @name = name
          @topic = topic

          @log_group = resource :aws_cloudwatch_log_group, "cloudtrail-#{name}", {
                                  name: "cloudtrail-#{name}",
                                }

          log_role = resource :aws_iam_role, "cloudtrail-#{name}-logs", {
                                name: "cloudtrail-#{name}-logs",
                                assume_role_policy: {
                                  Version: "2012-10-17",
                                  Statement: [
                                    {
                                      Sid: "",
                                      Effect: "Allow",
                                      Principal: {
                                        Service: "cloudtrail.amazonaws.com"
                                      },
                                      Action: "sts:AssumeRole",
                                    },
                                  ],
                                }.to_json,
                              }

          log_role_policy = resource :aws_iam_policy, "cloudtrail-#{name}-logs", {
                                       name: "cloudtrail-#{name}-logs",
                                       policy: {
                                         Version: "2012-10-17",
                                         Statement: [
                                           {
                                             Sid: "AWSCloudTrailCreateLogStream2014110",
                                             Effect: "Allow",
                                             Action: [
                                               "logs:CreateLogStream"
                                             ],
                                             Resource: [
                                               "#{@log_group["arn"]}:*",
                                             ]
                                           },
                                           {
                                             Sid: "AWSCloudTrailPutLogEvents20141101",
                                             Effect: "Allow",
                                             Action: [
                                               "logs:PutLogEvents"
                                             ],
                                             Resource: [
                                               "#{@log_group["arn"]}:*",
                                             ]
                                           }
                                         ]
                                       }.to_json
                                     }

          resource :aws_iam_role_policy_attachment, "cloudtrail-#{name}-logs", {
                     role: log_role["name"],
                     policy_arn: log_role_policy["arn"],
                   }

          data_event_selectors = event_selector(ignore_buckets)

          resource :aws_cloudtrail, "#{name}", {
                     name: "#{name}",
                     s3_bucket_name: store.name,
                     s3_key_prefix: "cloudtrail",
                     include_global_service_events: true,
                     is_multi_region_trail: include_all_regions,
                     is_organization_trail: include_all_organisation,
                     enable_log_file_validation: true,
                     kms_key_id: store.key_arn,

                     cloud_watch_logs_group_arn: "#{@log_group["arn"]}:*",
                     cloud_watch_logs_role_arn: log_role["arn"],

                   }.deep_merge(data_event_selectors)
          self
        end

        def event_selector(buckets)
          buckets = Array(buckets)

          return basic_selector if buckets.empty?

          {
            advanced_event_selector: [
              ignore_buckets_selectors(buckets),
              management_events_selector,
              lambda_events
            ]
          }
        end

        def basic_selector
          {
            event_selector: [
              {
                read_write_type: "All",
                include_management_events: true,

                data_resource: {
                  type: "AWS::S3::Object",
                  values: ["arn:aws:s3:::"],
                }
              },
              {
                read_write_type: "All",
                include_management_events: true,

                data_resource: {
                  type: "AWS::Lambda::Function",
                  values: ["arn:aws:lambda"],
                },
              }
            ]
          }
        end

        def ignore_buckets_selectors(buckets)
          ignore_bucket_arns = Array(buckets).map { |bucket|
            data_name = Digest::SHA256.hexdigest("#{@name}-#{bucket}")[0..16]
            arn = data(:aws_s3_bucket, "ct-ignore-#{data_name}", bucket: bucket)['arn']
            "#{arn}/"
          }

          {
            name: 'Log all S3 buckets objects events except these',

            field_selector: [
              {
                field: 'eventCategory',
                equals: ['Data']
              },
              {
                field: 'resources.type',
                equals: ['AWS::S3::Object']
              },
              {
                field: 'resources.ARN',
                not_starts_with: ignore_bucket_arns
              }
            ],
          }
        end

        def management_events_selector
          {
            name: 'Log readOnly and writeOnly management events',

            field_selector: [
              {
                field: "eventCategory",
                equals: ["Management"]
              }
            ]
          }
        end

        def lambda_events
          {
            name: 'Log Lambda data events',

            field_selector: [
              {
                field: 'eventCategory',
                equals: ['Data']
              },
              {
                field: 'resources.type',
                equals: ['AWS::Lambda::Function']
              }
            ]
          }
        end

        def alert!(name:, pattern:, threshold: 1, topic: @topic)

          ident = "cloudwatch-#{@name}-#{name}"

          resource :aws_cloudwatch_log_metric_filter, ident, {
                     name: name,
                     pattern: pattern,
                     log_group_name: @log_group["name"],

                     metric_transformation: {
                       name: "EventCount",
                       namespace: "CloudTrail/#{name}",
                       value: "1",
                     },
                   }

          resource :aws_cloudwatch_metric_alarm, ident, {
                     alarm_name: name,
                     comparison_operator: "GreaterThanOrEqualToThreshold",
                     evaluation_periods: "1",
                     metric_name: "EventCount",
                     namespace: "CloudTrail/#{name}",
                     period: "300",
                     statistic: "Sum",
                     threshold: "#{threshold}",
                     alarm_actions: [ topic ],
                   }

        end

        def cis_benchmark!

          # 3.1	Ensure a log metric filter and alarm exist for unauthorized API calls
          alert!(
            name: "UnauthorizedAPICalls",
            pattern: "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }",
          )

          # 3.2	Ensure a log metric filter and alarm exist for Management Console sign-in without MFA
          alert!(
            name: "NoMFAConsoleSignin",
            pattern: "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }",
          )

          # 3.3	Ensure a log metric filter and alarm exist for usage of "root" account
          alert!(
            name: "RootUsage",
            pattern: "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }",
          )

          # 3.4	Ensure a log metric filter and alarm exist for IAM policy changes
          alert!(
            name: "IAMChanges",
            pattern: "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}",
          )

          # 3.5	Ensure a log metric filter and alarm exist for CloudTrail configuration changes
          alert!(
            name: "CloudTrailCfgChanges",
            pattern: "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }",
          )

          # 3.6	Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
          alert!(
            name: "ConsoleSigninFailures",
            pattern: "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }",
          )

          # 3.7	Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
          alert!(
            name: "DisableOrDeleteCMK",
            pattern: "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }",
          )

          # 3.8	Ensure a log metric filter and alarm exist for S3 bucket policy changes
          alert!(
            name: "S3BucketPolicyChanges",
            pattern: "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }",
          )

          # 3.9	Ensure a log metric filter and alarm exist for AWS Config configuration changes
          alert!(
            name: "AWSConfigChanges",
            pattern: "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }",
          )

          # 3.10	Ensure a log metric filter and alarm exist for security group changes
          alert!(
            name: "SecurityGroupChanges",
            pattern: "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}",
          )

          # 3.11	Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)
          alert!(
            name: "NACLChanges",
            pattern: "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }",
          )

          # 3.12	Ensure a log metric filter and alarm exist for changes to network gateways
          alert!(
            name: "NetworkGWChanges",
            pattern: "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }",
          )

          # 3.13	Ensure a log metric filter and alarm exist for route table changes
          alert!(
            name: "RouteTableChanges",
            pattern: "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }",
          )

          # 3.14	Ensure a log metric filter and alarm exist for VPC changes
          alert!(
            name: "VPCChanges",
            pattern: "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }",
          )

        end

      end

    end
  end
end

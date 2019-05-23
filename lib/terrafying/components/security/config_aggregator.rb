# frozen_string_literal: true

require 'terrafying'

module Terrafying

  module Components

    module Security

      class ConfigAggregator < Terrafying::Context

        def self.create(*args)
          ConfigAggregator.new.create(*args)
        end

        def create(
              name,
              whole_organisation: false
            )

          ident = tf_safe(name)

          role = resource :aws_iam_role, ident, {
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

          resource :aws_iam_role_policy_attachment, "#{ident}-config-org-policy", {
                     provider: @provider,
                     role: role["name"],
                     policy_arn: "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations",
                   }

          source = {}

          if whole_organisation
            source[:organization_aggregation_source] = {
              all_regions: true,
              role_arn: role["arn"],
            }
          else
            source[:account_aggregation_source] = {
              account_ids: [ aws.account_id ],
              all_regions: true,
            }
          end

          resource :aws_config_configuration_aggregator, ident, {
                     depends_on: [ "aws_iam_role_policy_attachment.#{ident}-config-org-policy" ],
                     name: name,
                   }.merge(source)

          self
        end

      end
    end
  end
end

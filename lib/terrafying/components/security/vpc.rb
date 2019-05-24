
require 'terrafying'

module Terrafying

  module Component

    module Security

      class VPC < Terrafying::Context

        def self.create(*args)
          VPC.new.create(*args)
        end

        def create(
              region:,
              provider:,
              store:
            )

          ident = tf_safe("default-vpc-#{region}")

          log_group = resource :aws_cloudwatch_log_group, ident, {
                                  name: "default-vpc-#{region}",
                                }

          default_vpc = resource :aws_default_vpc, ident, {
                                   provider: provider,
                                   tags: { Name: "Default VPC" },
                                 }

          resource :aws_default_route_table, ident, {
                     provider: provider,
                     default_route_table_id: default_vpc["default_route_table_id"],
                     tags: { Name: "Default Route Table" },
                   }

          resource :aws_default_network_acl, ident, {
                     provider: provider,
                     lifecycle: {
                       ignore_changes: [ "subnet_ids"],
                     },

                     default_network_acl_id: default_vpc["default_network_acl_id"],

                     tags: { Name: "Default Network ACL" },
                   }

          resource :aws_default_security_group, ident, {
                     provider: provider,
                     vpc_id: default_vpc["id"],
                     tags: { Name: "Default Security Group" },
                   }

          resource :aws_flow_log, ident, {
                     vpc_id: default_vpc["id"],
                     traffic_type: "ALL",
                     log_destination: "#{store.arn}/flow-logs/",
                     log_destination_type: "s3",
                   }

          self
        end

      end

    end

  end

end

# frozen_string_literal: true

require 'terrafying'

module Terrafying

  module Components

    module Security

      class PagerdutyTopic < Terrafying::Context

        attr_reader :arn

        def self.create(*args)
          PagerdutyTopic.new.create(*args)
        end

        def create(
              name,
              escalation_policy_id:
            )

          ident = tf_safe(name)

          service = resource :pagerduty_service, ident, {
                               name: name,
                               auto_resolve_timeout: 14400,
                               acknowledgement_timeout: 600,
                               escalation_policy: escalation_policy_id,
                             }

          vendor = data :pagerduty_vendor, ident, {
                          name: "Amazon CloudWatch",
                        }

          integration = resource :pagerduty_service_integration, ident, {
                                   name: "SNS",
                                   vendor: vendor["id"],
                                   service: service["id"],
                                 }

          topic = resource :aws_sns_topic, ident, {}

          @arn = topic["arn"]

          resource :aws_sns_topic_subscription, ident, {
                     topic_arn: @arn,
                     protocol: "https",
                     endpoint: "https://events.pagerduty.com/integration/#{integration["integration_key"]}/enqueue",
                     endpoint_auto_confirms: true,
                   }

          self
        end

      end

    end
  end
end

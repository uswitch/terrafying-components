
require 'terrafying'

module Terrafying

  module Components

    module Security

      class IAM < Terrafying::Context

        def self.create(*args)
          IAM.new.create(*args)
        end

        def create(
              support_assume_policy:,
              password_policy: {}
            )

          # 1.5	Ensure IAM password policy requires at least one uppercase letter
          # 1.6	Ensure IAM password policy require at least one lowercase letter
          # 1.7	Ensure IAM password policy require at least one symbol
          # 1.8	Ensure IAM password policy require at least one number
          # 1.9	Ensure IAM password policy requires minimum length of 14 or greater
          # 1.10	Ensure IAM password policy prevents password reuse
          # 1.11	Ensure IAM password policy expires passwords within 90 days or less
          resource :aws_iam_account_password_policy, "strict", {
                     require_uppercase_characters: true,
                     require_lowercase_characters: true,
                     require_symbols: true,
                     require_numbers: true,
                     minimum_password_length: 14,
                     allow_users_to_change_password: true,
                     password_reuse_prevention: true,
                     max_password_age: 90,
                   }.merge(password_policy)

          # 1.20	Ensure a support role has been created to manage incidents with AWS Support
          support_role = resource :aws_iam_role, "support", {
                                    name: "support",
                                    assume_role_policy: support_assume_policy,
                                  }

          resource :aws_iam_role_policy_attachment, "support_policy", {
                     role: support_role,
                     policy_arn: "arn:aws:iam::aws:policy/AWSSupportAccess",
                   }

          self
        end

      end

    end

  end

end

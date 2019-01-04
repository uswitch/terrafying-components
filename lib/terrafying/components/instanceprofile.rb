
module Terrafying

  module Components

    class InstanceProfile < Terrafying::Context

      attr_reader :id, :resource_name, :role_arn, :role_resource

      def self.create(name, options={})
        InstanceProfile.new.create name, options
      end

      def self.find(name)
        InstanceProfile.new.find name
      end

      def initialize()
        super
      end

      def find(name)
        raise 'unimplemented'
      end

      def create(name, options={})
        options = {
          statements: [],
        }.merge(options)

        resource :aws_iam_role, name, {
                   name: name,
                   assume_role_policy: JSON.pretty_generate(
                     {
                       Version: "2012-10-17",
                       Statement: [
                         {
                           Effect: "Allow",
                           Principal: { "Service": "ec2.amazonaws.com"},
                           Action: "sts:AssumeRole"
                         }
                       ]
                     }
                   )
                 }

        @id = resource :aws_iam_instance_profile, name, {
                         name: name,
                         role: output_of(:aws_iam_role, name, :name),
                       }
        @name = name
        @resource_name = "aws_iam_instance_profile.#{name}"

        @role_arn = output_of(:aws_iam_role, name, :arn)
        @role_resource = "aws_iam_role.#{name}"

        @statements = [
                         {
                           Sid: "Stmt1442396947000",
                           Effect: "Allow",
                           Action: [
                             "iam:GetGroup",
                             "iam:GetSSHPublicKey",
                             "iam:GetUser",
                             "iam:ListSSHPublicKeys"
                           ],
                           Resource: [
                             "arn:aws:iam::*"
                           ]
                         }
        ].push(*options[:statements])

        @policy_config = {
          name: @name,
          policy: policy,
          role: output_of(:aws_iam_role, @name, :name),
        }

        resource :aws_iam_role_policy, @name, @policy_config

        self
      end

      def policy
        JSON.pretty_generate(
          {
            Version: "2012-10-17",
            Statement: @statements,
          }
        )
      end

      def add_statement!(statement)
        @statements << statement
        @policy_config[:policy] = policy
      end

    end
  end
end

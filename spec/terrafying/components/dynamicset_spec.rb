# frozen_string_literal: true

require 'terrafying'
require 'terrafying/components/dynamicset'
require 'terrafying/components/instanceprofile'

RSpec.describe Terrafying::Components::DynamicSet do
  it_behaves_like 'a usable resource'

  before do
    @aws = double('AWS')
    @vpc = stub_vpc('a-vpc', '10.0.0.0/16', aws: @aws)
  end

  it 'should just create a single asg template by default' do
    dynamic_set = Terrafying::Components::DynamicSet.create_in(@vpc, 'foo')

    expect(dynamic_set.output['resource']['aws_cloudformation_stack'].count).to eq(1)
  end

  it 'should add a depend_on for the instance profile' do
    instance_profile = Terrafying::Components::InstanceProfile.create('foo')
    dynamic_set = Terrafying::Components::DynamicSet.create_in(@vpc, 'foo', instance_profile: instance_profile)

    output = dynamic_set.output_with_children

    expect(output['resource']['aws_launch_configuration'].count).to eq(1)

    launch_config = output['resource']['aws_launch_configuration'].values.first

    expect(launch_config[:depends_on]).to include(instance_profile.resource_name)
  end

  context 'cloudformation template' do
    it 'should not set update policy if rollig_update is false' do
      dynamic_set = Terrafying::Components::DynamicSet.create_in(@vpc, 'foo', rolling_update: false)
      output = dynamic_set.output_with_children
      template_body = JSON.parse(output['resource']['aws_cloudformation_stack'].values.first[:template_body])
      expect(template_body['Resources']['AutoScalingGroup']['UpdatePolicy']).to be_nil
    end

    it 'should set update policy by default' do
      dynamic_set = Terrafying::Components::DynamicSet.create_in(@vpc, 'foo')
      output = dynamic_set.output_with_children
      template_body = JSON.parse(output['resource']['aws_cloudformation_stack'].values.first[:template_body])
      expect(template_body['Resources']['AutoScalingGroup']['UpdatePolicy']['AutoScalingRollingUpdate']).not_to be_nil
      expect(template_body['Resources']['AutoScalingGroup']['UpdatePolicy']['AutoScalingRollingUpdate']['WaitOnResourceSignals']).to be_falsey
    end

    it 'should suspend asg processes while doing a rolling update by default' do
      dynamic_set = Terrafying::Components::DynamicSet.create_in(@vpc, 'foo')

      output = dynamic_set.output_with_children
      template_body = JSON.parse(output['resource']['aws_cloudformation_stack'].values.first[:template_body], symbolize_names: true)
      update_policy = template_body[:Resources][:AutoScalingGroup][:UpdatePolicy]

      expect(update_policy).to include(
        AutoScalingRollingUpdate: a_hash_including(
          SuspendProcesses: a_collection_including(
            'HealthCheck', 'ReplaceUnhealthy', 'AZRebalance', 'AlarmNotification', 'ScheduledActions'
          )
        )
      )
    end

    it 'should suspend asg processes while doing a rolling update with a signal' do
      dynamic_set = Terrafying::Components::DynamicSet.create_in(@vpc, 'foo', rolling_update: :signal)

      output = dynamic_set.output_with_children
      template_body = JSON.parse(output['resource']['aws_cloudformation_stack'].values.first[:template_body], symbolize_names: true)
      update_policy = template_body[:Resources][:AutoScalingGroup][:UpdatePolicy]

      expect(update_policy).to include(
        AutoScalingRollingUpdate: a_hash_including(
          SuspendProcesses: a_collection_including(
            'HealthCheck', 'ReplaceUnhealthy', 'AZRebalance', 'AlarmNotification', 'ScheduledActions'
          )
        )
      )
    end

    it 'should expect a signal when configured' do
      dynamic_set = Terrafying::Components::DynamicSet.create_in(@vpc, 'foo', rolling_update: :signal)

      output = dynamic_set.output_with_children
      template_body = JSON.parse(output['resource']['aws_cloudformation_stack'].values.first[:template_body])

      expect(template_body['Resources']['AutoScalingGroup']['UpdatePolicy']['AutoScalingRollingUpdate']['WaitOnResourceSignals']).to be true
    end

    it 'should track what the ASG is configured as' do
      asg = Aws::AutoScaling::Types::AutoScalingGroup.new(min_size: 3, max_size: 10, desired_capacity: 6)
      allow(@aws).to receive(:asgs_by_tags).and_return([asg])

      dynamic_set = Terrafying::Components::DynamicSet.create_in(@vpc, 'foo', instances: { min: 1, max: 1, desired: 1, track: true, tags: {} })

      output = dynamic_set.output_with_children
      template_body = JSON.parse(output['resource']['aws_cloudformation_stack'].values.first[:template_body])

      expect(template_body['Resources']['AutoScalingGroup']['Properties']['MaxSize']).to eq(asg.max_size.to_s)
      expect(template_body['Resources']['AutoScalingGroup']['Properties']['MinSize']).to eq(asg.min_size.to_s)
      expect(template_body['Resources']['AutoScalingGroup']['Properties']['DesiredCapacity']).to eq(asg.desired_capacity.to_s)
    end
  end

  context 'security_groups' do
    it 'should define no rules directly on the egress group' do
      set = described_class.create_in(@vpc, 'foo')

      rules = set.output['resource']['aws_security_group']['a-vpc-foo']

      expect(rules.keys).to not_include(:egress, :ingress)
    end

    it 'should add a default egress rule to 0.0.0.0/0' do
      set = described_class.create_in(@vpc, 'foo')

      rules = set.output['resource']['aws_security_group_rule'].values

      expect(rules).to include(
        a_hash_including(
          security_group_id: set.egress_security_group,
          type: 'egress',
          from_port: 0,
          to_port: 0,
          protocol: -1,
          cidr_blocks: ['0.0.0.0/0']
        )
      )
    end
  end
end

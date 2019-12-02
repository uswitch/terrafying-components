# frozen_string_literal: true

require 'terrafying/components/auditd'

def a_tag_matching(k, v)
  a_file_matching(
    '20_auditd_filter_ec2.conf',
    a_string_matching(/#{k}\s+\$\{#{v}\}/)
  )
end

def a_file_matching(file, content)
  a_hash_including(
    path: "/etc/fluentd/conf.d/#{file}",
    contents: a_string_matching(content)
  )
end

RSpec.describe Terrafying::Components::Auditd, '#fluentd_conf' do
  context('audit log forwarding') do
    it('should read from the journal') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'

      expect(conf[:files]).to include(
        a_file_matching('10_auditd_input_systemd.conf', '@type systemd')
      )
    end

    it('should add ec2 metadata') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'

      expect(conf[:files]).to include(
        a_file_matching('20_auditd_filter_ec2.conf', '@type ec2_metadata')
      )
    end

    it('should output to s3') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'

      expect(conf[:files]).to include(
        a_file_matching('30_auditd_output_s3.conf', '@type s3')
      )
    end

    it('should output to s3 with a role assumed') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'

      expect(conf[:files]).to include(
        a_file_matching('30_auditd_output_s3.conf', 'role_arn a-role')
      )
    end
  end

  context('default ec2 metadata tags') do
    it('should add name tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'
      expect(conf[:files]).to include(a_tag_matching('name', 'tagset_name'))
    end

    it('should add instance_id tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'
      expect(conf[:files]).to include(a_tag_matching('instance_id', 'instance_id'))
    end

    it('should add instance_type tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'
      expect(conf[:files]).to include(a_tag_matching('instance_type', 'instance_type'))
    end

    it('should add private_ip tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'
      expect(conf[:files]).to include(a_tag_matching('private_ip', 'private_ip'))
    end

    it('should add az tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'
      expect(conf[:files]).to include(a_tag_matching('az', 'availability_zone'))
    end

    it('should add vpc_id tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'
      expect(conf[:files]).to include(a_tag_matching('vpc_id', 'vpc_id'))
    end

    it('should add ami_id tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'
      expect(conf[:files]).to include(a_tag_matching('ami_id', 'image_id'))
    end

    it('should add account_id tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'
      expect(conf[:files]).to include(a_tag_matching('account_id', 'account_id'))
    end

    it('should add a custom tag with a string key') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role', ['custom']
      expect(conf[:files]).to include(a_tag_matching('custom', 'tagset_custom'))
    end

    it('should add a custom tag with a symbol key') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role', [:custom]
      expect(conf[:files]).to include(a_tag_matching('custom', 'tagset_custom'))
    end
  end

  context('custom ec2 metadata tags') do
    it('should add my_tag tag') do
      conf = Terrafying::Components::Auditd.fluentd_conf('a-role', ['my_tag'])

      expect(conf[:files]).to include(a_tag_matching('my_tag', 'tagset_my_tag'))
    end
  end

  context('iam roles') do
    it('should allow the instance to assume the audit role') do
      conf = Terrafying::Components::Auditd.fluentd_conf('a-role', ['my_tag'])

      expect(conf[:iam_policy_statements]).to include(
        a_hash_including(
          Effect: 'Allow',
          Action: ['sts:AssumeRole'],
          Resource: ['a-role']
        )
      )
    end

    it('should allow the instance to describe instances') do
      conf = Terrafying::Components::Auditd.fluentd_conf('a-role', ['my_tag'])

      expect(conf[:iam_policy_statements]).to include(
        a_hash_including(
          Effect: 'Allow',
          Action: a_collection_including('ec2:DescribeInstances'),
          Resource: ['*']
        )
      )
    end

    it('should allow the instance to describe tags') do
      conf = Terrafying::Components::Auditd.fluentd_conf('a-role', ['my_tag'])

      expect(conf[:iam_policy_statements]).to include(
        a_hash_including(
          Effect: 'Allow',
          Action: a_collection_including('ec2:DescribeTags'),
          Resource: ['*']
        )
      )
    end

    it('should allow the instance to describe routes') do
      conf = Terrafying::Components::Auditd.fluentd_conf('a-role', ['my_tag'])

      expect(conf[:iam_policy_statements]).to include(
        a_hash_including(
          Effect: 'Allow',
          Action: a_collection_including('ec2:DescribeRouteTables'),
          Resource: ['*']
        )
      )
    end
  end
end

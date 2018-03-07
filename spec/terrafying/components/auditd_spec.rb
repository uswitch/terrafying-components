# frozen_string_literal: true

require 'terrafying/components/auditd'

RSpec.describe Terrafying::Components::Auditd, '#fluentd_conf' do
  context('setting up auditd forwarding') do
    it('should configure fluentd to read from the journal') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'

      expect(conf[:files]).to include(
        a_hash_including(
          {
            path: '/etc/fluentd/conf.d/10_auditd_input_systemd.conf',
            contents: a_string_matching('@type systemd')
          }
        )
      )
    end

    it('should configure fluentd to add ec2 metadata') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'

      expect(conf[:files]).to include(
        a_hash_including(
          {
            path: '/etc/fluentd/conf.d/20_auditd_filter_ec2.conf',
            contents: a_string_matching('@type ec2_metadata')
          }
        )
      )
    end

    it('should configure fluentd to output to s3') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'

      expect(conf[:files]).to include(
        a_hash_including(
          {
            path: '/etc/fluentd/conf.d/30_auditd_output_s3.conf',
            contents: a_string_matching('@type s3')
          }
        )
      )
    end

    it('should configure fluentd to output to s3 with a role assumed') do
      conf = Terrafying::Components::Auditd.fluentd_conf 'a-role'

      expect(conf[:files]).to include(
        a_hash_including(
          {
            path: '/etc/fluentd/conf.d/30_auditd_output_s3.conf',
            contents: a_string_matching('role_arn a-role')
          }
        )
      )
    end
  end
end

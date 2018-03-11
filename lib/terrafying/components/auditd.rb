# frozen_string_literal: true

module Terrafying
  module Components
    class Auditd
      def self.fluentd_conf(role, tags = [])
        new.fluentd_conf(role, tags)
      end

      def fluentd_conf(role, tags)
        tags = default_tags.merge(
          custom_tags(tags)
        )

        {
          files: [
            systemd_input,
            ec2_filter(tags),
            s3_output(role)
          ]
        }
      end

      def custom_tags(tags)
        tags.map { |t| [t, wrap_tag(t)] }.to_h
      end

      def wrap_tag(t)
        t = "tagset_#{t}" unless t.start_with? 'tagset_'
        t.downcase
      end

      def default_tags
        {
          name:          'tagset_name',
          instance_id:   'instance_id',
          instance_type: 'instance_type',
          private_ip:    'private_ip',
          az:            'availability_zone',
          vpc_id:        'vpc_id',
          ami_id:        'image_id',
          account_id:    'account_id'
        }
      end

      def file_of(name, content)
        {
          path: "/etc/fluentd/conf.d/#{name}.conf",
          mode: 0o644,
          contents: content
        }
      end

      def systemd_input
        file_of(
          '10_auditd_input_systemd',
          <<~'SYSTEMD_INPUT'
            <source>
              @type systemd
              tag auditd
              filters [{ "_TRANSPORT": "audit" }, { "_COMM": "sshd" }]
              path /fluentd/log/journal
              read_from_head false
              <storage>
                @type local
                persistent false
                path /fluentd/var/audit.pos
              </storage>
              <entry>
                field_map {
                  "MESSAGE": "log",
                  "_PID": ["process", "pid"],
                  "_CMDLINE": "process",
                  "_COMM": "cmd",
                  "_AUDIT_SESSION": "audit_session",
                  "_AUDIT_LOGINUID": "audit_loginuid"
                }
                fields_strip_underscores true
                fields_lowercase true
              </entry>
            </source>
          SYSTEMD_INPUT
        )
      end

      def ec2_filter(tags)
        file_of(
          '20_auditd_filter_ec2',
          <<~EC2_FILTER
            <filter auditd>
              @type ec2_metadata
              metadata_refresh_seconds 300
              <record>
                #{map_tags(tags)}
              </record>
            </filter>
          EC2_FILTER
        )
      end

      def map_tags(tags)
        tags.map { |k, v| "#{k} ${#{v}}" }
            .reduce { |out, e| +out << "\n    #{e}" }
      end

      def s3_output(audit_role)
        file_of(
          '30_auditd_output_s3',
          <<~S3_OUTPUT
            <match auditd>
              @type s3
              <assume_role_credentials>
                role_arn #{audit_role}
                role_session_name "auditd-logging-\#{Socket.gethostname}"
              </assume_role_credentials>
              auto_create_bucket false
              s3_bucket uswitch-auditd-logs
              s3_region eu-west-1
              acl bucket-owner-full-control
              path auditd/%Y/%m/%d/
              s3_object_key_format "\%{path}\%{time_slice}_\#{Socket.gethostname}.\%{file_extension}"
              <buffer time>
                @type file
                path /fluent/var/s3
                timekey 300 # 5 minute partitions
                timekey_wait 0s
                timekey_use_utc true
              </buffer>
              <format>
                @type json
              </format>
            </match>
          S3_OUTPUT
        )
      end
    end
  end
end

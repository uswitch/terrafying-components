# frozen_string_literal: true

require 'digest'
require 'terrafying'
require 'terrafying/components'

module Terrafying
  module Components
    class Prometheus < Terrafying::Context
      attr_reader :prometheus, :security_group

      def self.create_in(options)
        new(**options).tap(&:create)
      end

      def self.find_in(options)
        new(**options).tap(&:find)
      end

      def initialize(
        vpc:,
        thanos_name: 'thanos',
        thanos_version: 'v0.8.1',
        prom_name: 'prometheus',
        prom_version: 'v2.12.0',
        instances: 2,
        instance_type: 't3a.small',
        thanos_instance_type: 't3a.small',
        prometheus_tsdb_retention: '1d',
        prometheus_data_dir: '/var/lib/prometheus',
        prometheus_data_size: 20
      )
        super()
        @vpc = vpc
        @thanos_name = thanos_name
        @thanos_version = thanos_version
        @prom_name = prom_name
        @prom_version = prom_version
        @instances = instances
        @prometheus_instance_type = instance_type
        @thanos_instance_type = thanos_instance_type
        @prometheus_tsdb_retention = prometheus_tsdb_retention
        @prometheus_data_dir = prometheus_data_dir
        @prometheus_data_size = prometheus_data_size
      end

      def find
        @security_group = aws.security_group_in_vpc(
          @vpc.id,
          "staticset-#{@vpc.name}-#{@prom_name}"
        )
      end

      def create
        prometheus_thanos_sidecar_hostname = tf_safe(@prom_name)
        prometheus_thanos_sidecar_srv_fqdn = "_grpc._tcp.#{@vpc.zone.qualify prometheus_thanos_sidecar_hostname}"
        @prometheus_instance_vcpu_count = aws.instance_type_vcpu_count(@prometheus_instance_type)
        @thanos_instance_vcpu_count = aws.instance_type_vcpu_count(@thanos_instance_type)
        @thanos = create_thanos(prometheus_thanos_sidecar_srv_fqdn)
        create_thanos_cloudwatch_alert(@thanos)

        @prometheus = create_prom

        @security_group = @prometheus.egress_security_group

        # Form SRV record with thanos-sidecars
        @vpc.zone.add_srv_in(self, prometheus_thanos_sidecar_hostname, 'grpc', 10_901, 'tcp', @prom_service.domain_names.drop(1))

        # Allow Prometheus to scrape Thanos Query
        @thanos.used_by(@prometheus) { |port| port[:upstream_port] == 10_902 }
        # Allow Thanos Query instance to reach Prometheus running Thanos Sidecar
        @prometheus.used_by(@thanos) { |port| port[:upstream_port] == 10_901 }
        # Allow connections from VPC to Thanos Query services
        @thanos.used_by_cidr(@vpc.cidr) { |port| [10_902, 10_901].include? port[:upstream_port] }
      end

      def create_prom
        @prom_service = add! Terrafying::Components::Service.create_in(
          @vpc, @prom_name,
          ports: [
            {
              type: 'tcp',
              number: 9090
            },
            {
              type: 'tcp',
              number: 10_902
            },
            {
              type: 'tcp',
              number: 10_901
            }
          ],
          instance_type: @prometheus_instance_type,
          iam_policy_statements: thanos_store_access,
          instances: [{}] * @instances,
          units: [prometheus_unit, thanos_sidecar_unit],
          files: [prometheus_conf, thanos_bucket],
          volumes: [prometheus_data_volume],
          tags: {
            prometheus_port: 9090,
            prometheus_path: '/metrics',
            prometheus_port_0: 10_902,
            prometheus_path_0: '/metrics'
          }
        )
      end

      def create_thanos(prometheus_thanos_sidecar_srv_fqdn)
        @thanos_service = add! Terrafying::Components::Service.create_in(
          @vpc, @thanos_name,
          ports: [
            {
              type: 'tcp',
              number: 10_902,
              health_check: {
                protocol: 'HTTP',
                path: '/-/healthy'
              }
            },
            {
              type: 'tcp',
              number: 10_901,
              health_check: {
                protocol: 'TCP'
              }
            }
          ],
          instance_type: @thanos_instance_type,
          units: [thanos_unit(prometheus_thanos_sidecar_srv_fqdn)],
          instances: [{}] * @instances,
          loadbalancer: true,
          tags: {
            prometheus_port: 10_902,
            prometheus_path: '/metrics'
          }
        )
      end

      def prometheus_data_volume

        {
          name: 'prometheus_data',
          mount: @prometheus_data_dir,
          device: '/dev/xvdl',
          size: @prometheus_data_size,
        }
      end

      def prometheus_unit
        {
          name: 'prometheus.service',
          contents: <<~PROM_UNIT
            [Install]
            WantedBy=multi-user.target

            [Unit]
            Description=Prometheus Service
            After=docker.service
            Requires=docker.service

            [Service]
            ExecStartPre=-/usr/bin/docker network create --driver bridge prom
            ExecStartPre=-/usr/bin/docker kill prometheus
            ExecStartPre=-/usr/bin/docker rm prometheus
            ExecStartPre=/usr/bin/docker pull quay.io/prometheus/prometheus:#{@prom_version}
            ExecStartPre=-/usr/bin/sed -i "s/{{HOST}}/%H/" /opt/prometheus/prometheus.yml
            ExecStartPre=/usr/bin/install -d -o nobody -g nobody -m 0755 #{@prometheus_data_dir}
            ExecStart=/usr/bin/docker run --name prometheus \
              -p 9090:9090 \
              --network=prom \
              -v /opt/prometheus:/opt/prometheus \
              -v #{@prometheus_data_dir}:/var/lib/prometheus \
              quay.io/prometheus/prometheus:#{@prom_version} \
              --storage.tsdb.path=/var/lib/prometheus/tsdb \
              --storage.tsdb.retention.time=#{@prometheus_tsdb_retention} \
              --storage.tsdb.min-block-duration=2h \
              --storage.tsdb.max-block-duration=2h \
              --storage.tsdb.no-lockfile \
              --storage.remote.read-concurrent-limit=#{@prometheus_instance_vcpu_count} \
              --query.max-concurrency=#{@prometheus_instance_vcpu_count} \
              --config.file=/opt/prometheus/prometheus.yml \
              --web.console.templates=/etc/prometheus/consoles \
              --web.console.libraries=/etc/prometheus/console_libraries \
              --web.enable-lifecycle \
              --log.level=warn
            Restart=always
            RestartSec=30
          PROM_UNIT
        }
      end

      def thanos_sidecar_unit
        {
          name: 'thanos.service',
          contents: <<~THANOS_SIDE
            [Install]
            WantedBy=multi-user.target

            [Unit]
            Description=Thanos Service
            After=docker.service prometheus.service
            Requires=docker.service prometheus.service

            [Service]
            ExecStartPre=-/usr/bin/docker kill thanos
            ExecStartPre=-/usr/bin/docker rm thanos
            ExecStartPre=/usr/bin/docker pull quay.io/thanos/thanos:#{@thanos_version}
            ExecStart=/usr/bin/docker run --name thanos \
              -p 10901-10902:10901-10902 \
              -v #{@prometheus_data_dir}:/var/lib/prometheus \
              -v /opt/thanos:/opt/thanos \
              --network=prom \
              quay.io/thanos/thanos:#{@thanos_version} \
              sidecar \
              --prometheus.url=http://prometheus:9090 \
              --tsdb.path=/var/lib/prometheus/tsdb \
              --objstore.config-file=/opt/thanos/bucket.yml \
              --log.level=warn
            Restart=always
            RestartSec=30
          THANOS_SIDE
        }
      end

      def prometheus_conf
        {
          path: '/opt/prometheus/prometheus.yml',
          mode: 0o644,
          contents: ERB.new(<<~'END', 0, '-', '_').result(binding)
            global:
              external_labels:
                monitor: prometheus
                cluster: <%= @vpc.name %>
                replica: {{HOST}}
              scrape_interval: 15s
            scrape_configs:
            # While AWS EC2 instance support up to 50 tags, we wouldn't be able
            # to fit such a long configuration file into user_data of the
            # instance; user_data is limited to just 16k.
            # This configuration support scraping up to 5 ports per instance:
            <%- prom_tag_name_suffixes = [''] + (0..3).map {|i| "_#{i}"} -%>
            <%- prom_tag_name_suffixes.each do |suffix| -%>
            - job_name: ec2<%= suffix %>
              params:
                format: ["prometheus"]
              ec2_sd_configs:
              - region: eu-west-1
                filters:
                - name: vpc-id
                  values: ["<%= @vpc.id %>"]
                - # by using the same ec2_sd_configs we are able to share single
                  # provider instance thanks to SD configuration coalescing
                  # therefore "prometheus_port" tag must always be present on
                  # the instance to be discovered (i. e. "prometheus_port_*" tag
                  # would not be sufficient if "  " tag is missing)
                  name: tag-key
                  values: ["prometheus_port"]
              relabel_configs:
              - source_labels: [__meta_ec2_tag_prometheus_port<%= suffix %>]
                regex: (.+)
                action: keep
              - source_labels: [__meta_ec2_private_ip, __meta_ec2_tag_prometheus_port<%= suffix %>]
                target_label: __address__
                separator: ':'
              - source_labels: [__meta_ec2_tag_prometheus_path<%= suffix %>]
                target_label: __metrics_path__
                regex: (.+)
              - source_labels: [__meta_ec2_instance_id]
                target_label: instance_id
              - source_labels: [__meta_ec2_tag_envoy_cluster]
                target_label: envoy_cluster
            <%- end -%>
          END
        }
      end

      def thanos_unit(prometheus_thanos_sidecar_srv_fqdn)
        {
          name: 'thanos.service',
          contents: <<~THANOS_UNIT
            [Install]
            WantedBy=multi-user.target

            [Unit]
            Description=Thanos Service
            After=docker.service
            Requires=docker.service

            [Service]
            ExecStartPre=-/usr/bin/docker kill thanos
            ExecStartPre=-/usr/bin/docker rm thanos
            ExecStartPre=/usr/bin/docker pull quay.io/thanos/thanos:#{@thanos_version}
            ExecStart=/usr/bin/docker run --name thanos \
              -p 10901-10902:10901-10902 \
              quay.io/thanos/thanos:#{@thanos_version} \
              query \
              --query.replica-label=replica \
              --query.max-concurrent=#{@thanos_instance_vcpu_count} \
              --store=dnssrv+#{prometheus_thanos_sidecar_srv_fqdn} \
              --log.level=warn
            Restart=always
            RestartSec=30
          THANOS_UNIT
        }
      end

      def thanos_bucket
        {
          path: '/opt/thanos/bucket.yml',
          mode: 0o644,
          contents: <<~S3CONF
            type: S3
            config:
                bucket: uswitch-thanos-store
                endpoint: s3.eu-west-1.amazonaws.com
          S3CONF
        }
      end

      def thanos_store_access
        [
          {
            Action: ['ec2:DescribeInstances'],
            Effect: 'Allow',
            Resource: '*'
          },
          {
            Action: [
              's3:ListBucket',
              's3:GetObject',
              's3:DeleteObject',
              's3:PutObject'
            ],
            Effect: 'Allow',
            Resource: [
              'arn:aws:s3:::uswitch-thanos-store/*',
              'arn:aws:s3:::uswitch-thanos-store'
            ]
          }
        ]
      end

      def expose_in(vpc)
        @endpoint_service ||= @thanos.with_endpoint_service(acceptance_required: false)

        options = {}
        endpoint = add! @endpoint_service.expose_in(vpc, options)
        endpoint.used_by_cidr(vpc.cidr)

        endpoint
      end

      def cloudwatch_alarm(name, namespace, dimensions)
        resource 'aws_cloudwatch_metric_alarm', name,
                 alarm_name: name,
                 comparison_operator: 'GreaterThanOrEqualToThreshold',
                 evaluation_periods: '1',
                 metric_name: 'UnHealthyHostCount',
                 namespace: namespace,
                 period: '180',
                 threshold: '1',
                 statistic: 'Minimum',
                 alarm_description: "Monitoring #{name} target group host health",
                 dimensions: dimensions,
                 alarm_actions: ['arn:aws:sns:eu-west-1:136393635417:prometheus_cloudwatch_topic'],
                 ok_actions: ['arn:aws:sns:eu-west-1:136393635417:prometheus_cloudwatch_topic']
      end

      def create_thanos_cloudwatch_alert(service)
        service.load_balancer.targets.each_with_index do |target, i|
          cloudwatch_alarm "#{service.name}_#{i}", 'AWS/NetworkELB',
                           LoadBalancer: output_of('aws_lb', service.load_balancer.name, 'arn_suffix'),
                           TargetGroup: target.target_group.to_s.gsub(/id/, 'arn_suffix')
        end
      end
    end
  end
end

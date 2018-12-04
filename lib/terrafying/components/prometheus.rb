# frozen_string_literal: true

require 'digest'
require 'terrafying'
require 'terrafying/components'

module Terrafying
  module Components
    class Prometheus < Terrafying::Context
      attr_reader :service

      def self.create_in(options)
        new(**options).tap(&:create)
      end

      def self.find_in(vpc)
        new(vpc: vpc).find

      end

      def initialize(
        vpc:,
        thanos_version: 'master-2018-10-29-8f247d6',
        prom_version: 'v2.4.3'
      )
        super()
        @vpc = vpc
        @thanos_version = thanos_version
        @prom_version = prom_version
      end

      def find
        @security_group = aws.security_groups_in_vpc(
          vpc.id,
          "dynamicset-#{vpc.name}-prometheus"
        )
      end

      def create
        thanos_peers = @vpc.qualify('thanos')

        @service = create_prom(thanos_peers)
        @security_group = @service.security_group
        create_prometheus_cloudwatch_alert(@service)

        @thanos = create_thanos(thanos_peers)
        create_thanos_cloudwatch_alert(@thanos)

        @service.used_by(@thanos)
        @thanos.used_by(@service)
      end

      def create_prom(thanos_peers)
        add! Terrafying::Components::Service.create_in(
          @vpc, 'prometheus',
          ports: [10900, 10901, 10902],
          loadbalancer: false,
          instance_type: 'm4.large',
          iam_policy_statements: thanos_store_access,
          instances: { max: 3, min: 1, desired: 2 },
          units: [prometheus_unit(thanos_peers), thanos_sidecar_unit],
          files: [prometheus_conf, thanos_bucket],
        )
      end

      def create_thanos(thanos_peers)
        add! Terrafying::Components::Service.create_in(
          @vpc, 'thanos',
          ports: [
            {
              number: 10902,
              health_check: {
                path: '/status',
                protocol: 'HTTP'
              }
            },
            {
              number: 10901
            },
            {
              number: 10900
            }
          ],
          instance_type: 't2.medium',
          units: [thanos_unit(thanos_peers)],
          instances: { max: 3, min: 1, desired: 2 }
        )
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
            ExecStartPre=/usr/bin/docker pull quay.io/prometheus/prometheus:#{@thanos_version}
            ExecStartPre=-/usr/bin/sed -i "s/{{HOST}}/%H/" /opt/prometheus/prometheus.yml
            ExecStartPre=/usr/bin/install -d -o nobody -g nobody -m 0755 /opt/prometheus/data
            ExecStart=/usr/bin/docker run --name prometheus \
              -p 9090:9090 \
              --network=prom \
              -v /opt/prometheus:/opt/prometheus \
              quay.io/prometheus/prometheus:#{@thanos_version} \
              --storage.tsdb.path=/opt/prometheus/data \
              --storage.tsdb.retention=1d \
              --storage.tsdb.min-block-duration=2h \
              --storage.tsdb.max-block-duration=2h \
              --config.file=/opt/prometheus/prometheus.yml \
              --web.enable-lifecycle \
              --log.level=warn
            Restart=always
            RestartSec=30
          PROM_UNIT
        }
      end

      def thanos_sidecar_unit(thanos_peers)
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
            EnvironmentFile=/run/metadata/coreos
            ExecStartPre=-/usr/bin/docker kill thanos
            ExecStartPre=-/usr/bin/docker rm thanos
            ExecStartPre=/usr/bin/docker pull improbable/thanos:#{@thanos_version}
            ExecStart=/usr/bin/docker run --name thanos \
              -p 10900-10902:10900-10902 \
              -v /opt/prometheus:/opt/prometheus \
              -v /opt/thanos:/opt/thanos \
              --network=prom \
              improbable/thanos:#{@thanos_version} \
              sidecar \
              --cluster.peers=#{thanos_peers}:10900 \
              --cluster.advertise-address=$${COREOS_EC2_IPV4_LOCAL}:10900 \
              --grpc-advertise-address=$${COREOS_EC2_IPV4_LOCAL}:10901 \
              --prometheus.url=http://prometheus:9090 \
              --tsdb.path=/opt/prometheus/data \
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
          contents: <<~PROM_CONF
            global:
              external_labels:
                monitor: prometheus
                cluster: data
                replica: {{HOST}}
              scrape_interval: 15s
            scrape_configs:
            - job_name: "ec2"
              params:
                format: ['prometheus']
              ec2_sd_configs:
              - region: eu-west-1
                filters:
                - name: vpc-id
                  values: ["#{@vpc.id}"]
                - name: tag-key
                  values: ["prometheus_port"]
               relabel_configs:
              - source_labels: [__meta_ec2_private_ip, __meta_ec2_tag_prometheus_port]
                replacement: $1:$2
                regex: ([^:]+)(?::\\\\d+)?;(\\\\d+)
                target_label: __address__
              - source_labels: [__meta_ec2_instance_id]
                target_label: instance_id
              - source_labels: [__meta_ec2_tag_prometheus_path]
                regex: (.+)
                replacement: $1
                target_label: __metrics_path__
          PROM_CONF
        }
      end

      def thanos_unit(thanos_peers)
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
            EnvironmentFile=/run/metadata/coreos
            ExecStartPre=-/usr/bin/docker kill thanos
            ExecStartPre=-/usr/bin/docker rm thanos
            ExecStartPre=/usr/bin/docker pull improbable/thanos:#{@thanos_version}
            ExecStart=/usr/bin/docker run --name thanos \
              -p 10900-10902:10900-10902 \
              improbable/thanos:#{@thanos_version} \
              query \
              --cluster.peers=#{thanos_peers}:10900 \
              --cluster.advertise-address=$${COREOS_EC2_IPV4_LOCAL}:10900 \
              --grpc-advertise-address=$${COREOS_EC2_IPV4_LOCAL}:10901 \
              --query.replica-label=replica \
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
        resource 'aws_cloudwatch_metric_alarm', name, {
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
          alarm_actions: ['${aws_sns_topic.prometheus_cloudwatch_topic.arn}']
        }
      end

      def create_prometheus_cloudwatch_alert(service)
        cloudwatch_alarm(service.name, 'AWS/ApplicationELB', {
          LoadBalancer: output_of('aws_lb', service.load_balancer.name, 'arn_suffix'),
          TargetGroup: service.load_balancer.target_groups[0].to_s.gsub(/id/, 'arn_suffix')
        })
      end

      def create_thanos_cloudwatch_alert(service)
        service.load_balancer.target_groups.each_with_index do |target_group, i|
          cloudwatch_alarm("#{service.name}_#{i}", 'AWS/NetworkELB', {
            LoadBalancer: output_of('aws_lb', service.load_balancer.name, 'arn_suffix'),
            TargetGroup: target_group.to_s.gsub(/id/, 'arn_suffix')
          })
        end
      end
    end
  end
end

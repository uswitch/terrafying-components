# frozen_string_literal: true

require 'digest'
require 'hash/merge_with_arrays'
require 'terrafying/generator'
require 'terrafying/util'
require 'terrafying/components/auditd'
require 'terrafying/components/dynamicset'
require 'terrafying/components/endpointservice'
require 'terrafying/components/ignition'
require 'terrafying/components/instance'
require 'terrafying/components/instanceprofile'
require 'terrafying/components/loadbalancer'
require 'terrafying/components/prometheus'
require 'terrafying/components/selfsignedca'
require 'terrafying/components/staticset'
require 'terrafying/components/usable'

module Terrafying
  module Components
    class Service < Terrafying::Context
      attr_reader :name, :zone, :domain_names, :ports, :instance_profile, :load_balancer, :instance_set

      include Usable

      def self.create_in(vpc, name, options = {})
        Service.new.create_in vpc, name, options
      end

      def self.find_in(vpc, name)
        Service.new.find_in vpc, name
      end

      def initialize
        super
      end

      def find_in(_vpc, _name)
        raise 'unimplemented'
      end

      def create_in(vpc, name, options = {})
        options = {
          ami: aws.ami('base-image-fc-3c48f829', owners = ['477284023816']),
          instance_type: 't3a.micro',
          ports: [],
          instances: [{}],
          zone: vpc.zone,
          cross_zone_load_balancing: false,
          iam_policy_statements: [],
          security_groups: [],
          keypairs: [],
          volumes: [],
          units: [],
          files: [],
          tags: {},
          users: [],
          ssh_group: vpc.ssh_group,
          subnets: vpc.subnets.fetch(:private, []),
          startup_grace_period: 300,
          depends_on: [],
          metadata_options: {},
          audit_role: "arn:aws:iam::#{aws.account_id}:role/auditd_logging",
          metrics_ports: [],
          vpc_endpoints_egress: []
        }.merge(options)

        unless options[:audit_role].nil?
          fluentd_conf = Auditd.fluentd_conf(options[:audit_role], options[:tags].keys)
          options = options.merge_with_arrays_merged(fluentd_conf)
        end

        unless options.key? :user_data
          options[:user_data] = Ignition.generate(options)
        end

        unless options.key?(:loadbalancer_subnets)
          options[:loadbalancer_subnets] = options[:subnets]
        end

        unless options[:instances].is_a?(Hash) || options[:instances].is_a?(Array)
          raise 'Unknown instances option, should be hash or array'
        end

        ident = "#{tf_safe(vpc.name)}-#{name}"

        @name = ident
        @zone = options[:zone]
        @ports = enrich_ports(options[:ports])
        @domain_names = [options[:zone].qualify(name)]

        depends_on = options[:depends_on] + options[:keypairs].map { |kp| kp[:resources] }.flatten.compact
        if options.key? :instance_profile
          @instance_profile = options[:instance_profile]
        else
          iam_statements = options[:iam_policy_statements] + options[:keypairs].map { |kp| kp[:iam_statement] }.compact
          @instance_profile = add! InstanceProfile.create(ident, statements: iam_statements)
        end

        metadata_options = options[:metadata_options]

        tags = options[:tags].merge(service_name: name)

        set = options[:instances].is_a?(Hash) ? DynamicSet : StaticSet

        if options.key?(:loadbalancer) # explicitly requested or rejected a loadbalancer
          wants_load_balancer = options[:loadbalancer]
        elsif options[:cross_zone_load_balancing] # indirect request for an LB
          wants_load_balancer = true
        else
          # by default we want one if we are an ASG with exposed ports
          wants_load_balancer = set == DynamicSet && @ports.count > 0
        end

        instance_set_options = {
          instance_profile: @instance_profile,
          depends_on: depends_on,
          metadata_options: metadata_options,
          tags: tags
        }

        if wants_load_balancer && @ports.any? { |p| p.key?(:health_check) }
          instance_set_options[:health_check] = { type: 'ELB', grace_period: options[:startup_grace_period] }
        end

        @instance_set = add! set.create_in(vpc, name, options.merge(instance_set_options))
        @security_group = @instance_set.security_group

        if options[:metrics_ports] && !options[:metrics_ports].empty?
          allow_scrape(vpc, options[:metrics_ports], @security_group)
        end

        if wants_load_balancer
          @load_balancer = add! LoadBalancer.create_in(
            vpc, name, options.merge(
                         subnets: options[:loadbalancer_subnets],
                         tags: tags,
                         cross_zone_load_balancing: options[:cross_zone_load_balancing]
                       )
          )

          @load_balancer.attach(@instance_set)

          if @load_balancer.type == 'application'
            @security_group = @load_balancer.security_group
            @egress_security_group = @instance_set.security_group
          end

          @zone.add_alias_in(self, name, @load_balancer.alias_config)
        elsif set == StaticSet
          @zone.add_record_in(self, name, @instance_set.instances.map(&:ip_address))
          @instance_set.instances.each do |i|
            @domain_names << vpc.zone.qualify(i.name)
            @zone.add_record_in(self, i.name, [i.ip_address])
          end
        end

        if set == DynamicSet && options[:rolling_update] == :signal
          @instance_profile.add_statement!(
            Effect: 'Allow',
            Action: ['cloudformation:SignalResource'],
            Resource: [@instance_set.stack]
          )
        end

        self
      end

      def allow_scrape(vpc, ports, security_group)
        prom = Prometheus.find_in(vpc: vpc)
        ports.each do |port|
          sg_rule_ident = Digest::SHA256.hexdigest("#{vpc.name}-#{port}-#{security_group}-#{prom.security_group}")
          resource :aws_security_group_rule, sg_rule_ident,
                   security_group_id: security_group,
                   type: 'ingress',
                   from_port: port,
                   to_port: port,
                   protocol: 'tcp',
                   source_security_group_id: prom.security_group
        end
      end

      def with_endpoint_service(options = {})
        add! EndpointService.create_for(@load_balancer, @name, {
          fqdn: @domain_names[0],
          zone: @zone
        }.merge(options))
      end
    end
  end
end

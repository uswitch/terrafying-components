# frozen_string_literal: true

require 'xxhash'

require 'terrafying/components/instance'
require 'terrafying/components/usable'

require_relative './ports'

module Terrafying
  module Components
    class StaticSet < Terrafying::Context
      attr_reader :name, :instances

      include Usable

      def self.create_in(vpc, name, options = {})
        StaticSet.new.create_in vpc, name, options
      end

      def self.find_in(vpc, name)
        StaticSet.new.find_in vpc, name
      end

      def initialize
        super
      end

      def find_in(_vpc, name)
        @name = name

        raise 'unimplemented'

        self
      end

      def create_in(vpc, name, options = {})
        options = {
          public: false,
          eip: false,
          ami: aws.ami('base-image-fc-75aa2aef', owners = ['477284023816']),
          instance_type: 't3a.micro',
          subnets: vpc.subnets.fetch(:private, []),
          ports: [],
          instances: [{}],
          instance_profile: nil,
          security_groups: [],
          user_data: '',
          tags: {},
          ssh_group: vpc.ssh_group,
          depends_on: [],
          volumes: [],
          vpc_endpoints_egress: []
        }.merge(options)

        ident = "#{tf_safe(vpc.name)}-#{name}"

        @name = ident
        @ports = enrich_ports(options[:ports])

        @security_group = resource :aws_security_group, ident,
                                   name: "staticset-#{ident}",
                                   description: "Describe the ingress and egress of the static set #{ident}",
                                   tags: options[:tags],
                                   vpc_id: vpc.id

        vpc_endpoints_egress = options[:vpc_endpoints_egress]
        if vpc_endpoints_egress.empty?
          default_egress_rule(ident, @security_group)
        else
          vpc_endpoint_egress_rules(ident, @security_group, vpc, vpc_endpoints_egress)
        end
        path_mtu_setup!

        @instances = options[:instances].map.with_index do |config, i|
          instance_ident = "#{name}-#{i}"

          instance = add! Instance.create_in(
            vpc, instance_ident, options.merge(
                                   {
                                     subnets: options[:subnets],
                                     security_groups: [@security_group] + options[:security_groups],
                                     depends_on: options[:depends_on],
                                     instance_profile: options[:instance_profile],
                                     tags: {
                                       staticset_name: ident
                                     }.merge(options[:tags])
                                   }.merge(config)
                                 )
          )

          options[:volumes].each.with_index do |volume, vol_i|
            volume_for("#{instance_ident}-#{vol_i}", instance, volume, options[:tags])
          end

          instance
        end

        @ports.each do |port|
          resource :aws_security_group_rule, "#{@name}-to-self-#{port[:name]}",
                   security_group_id: @security_group,
                   type: 'ingress',
                   from_port: from_port(port[:upstream_port]),
                   to_port: to_port(port[:upstream_port]),
                   protocol: port[:type] == 'udp' ? 'udp' : 'tcp',
                   self: true
        end

        self
      end

      def default_egress_rule(ident, security_group)
        resource :aws_security_group_rule, "#{ident}-default-egress",
                 security_group_id: security_group,
                 type: 'egress',
                 from_port: 0,
                 to_port: 0,
                 protocol: -1,
                 cidr_blocks: ['0.0.0.0/0']
      end


      def vpc_endpoint_egress_rules(ident, security_group, vpc, vpc_endpoints)
        prefix_ids = vpc_endpoints.map do | e |
          vpc_endpoint = data :aws_vpc_endpoint, "#{ident}-#{tf_safe(e)}", {
            vpc_id: vpc.id,
            service_name: e,
          }
          vpc_endpoint[:prefix_list_id]
        end

        resource :aws_security_group_rule, "#{ident}-vpc-endpoint-egress",
                 security_group_id: security_group,
                 type: 'egress',
                 from_port: 0,
                 to_port: 0,
                 protocol: -1,
                 prefix_list_ids: prefix_ids
      end

      def volume_for(name, instance, volume, tags)
        vol_opts = {
          availability_zone: instance.subnet.az,
          size: volume[:size],
          type: volume[:type] || 'gp2',
          encrypted: volume[:encrypted] || false,
          kms_key_id: volume[:kms_key_id],
          tags: {
            Name: name
          }.merge(tags)
        }.reject { |_, v| v.nil? }

        volume_id = resource :aws_ebs_volume, name, vol_opts

        resource :aws_volume_attachment, name,
                 device_name: volume[:device],
                 volume_id: volume_id,
                 instance_id: instance.id,
                 force_detach: true
      end

      def attach_load_balancer(load_balancer)
        @instances.product(load_balancer.targets).each.with_index do |(instance, target), i|
          resource :aws_lb_target_group_attachment, "#{load_balancer.name}-#{@name}-#{i}".gsub(%r{^(\d)}, '_\1'),
                   target_group_arn: target.target_group,
                   target_id: instance.id
        end

        used_by(load_balancer) if load_balancer.type == 'application'
      end
    end
  end
end

# frozen_string_literal: true

require 'xxhash'

require 'terrafying/components/usable'

module Terrafying
  module Components
    class Instance < Terrafying::Context
      attr_reader :id, :name, :ip_address, :subnet

      include Usable

      def self.create_in(vpc, name, options = {})
        Instance.new.create_in vpc, name, options
      end

      def self.find_in(vpc, name)
        Instance.new.find_in vpc, name
      end

      def initialize
        super
      end

      def find_in(_vpc, _name)
        raise 'unimplemented'
      end

      def create_in(vpc, name, options = {})
        options = {
          public: false,
          instance_type: 't2.micro',
          cpu_credits: 'unlimited',
          instance_profile: nil,
          ports: [],
          tags: {},
          security_groups: [],
          depends_on: []
        }.merge(options)

        ident = "#{tf_safe(vpc.name)}-#{name}"

        @name = name
        @ports = enrich_ports(options[:ports])

        @security_group = resource :aws_security_group, ident,
                                   name: "instance-#{ident}",
                                   description: "Describe the ingress and egress of the instance #{ident}",
                                   tags: options[:tags],
                                   vpc_id: vpc.id,
                                   egress: [
                                     {
                                       from_port: 0,
                                       to_port: 0,
                                       protocol: -1,
                                       cidr_blocks: ['0.0.0.0/0']
                                     }
                                   ]

        path_mtu_setup!

        lifecycle = if options.key? :ip_address
                      {
                        lifecycle: { create_before_destroy: false }
                      }
                    else
                      {
                        lifecycle: { create_before_destroy: true }
                      }
                    end

        if options.key? :subnet
          @subnet = options[:subnet]
        else
          subnets = options.fetch(:subnets, vpc.subnets[:private])
          # pick something consistent but not just the first subnet
          subnet_index = XXhash.xxh32(ident) % subnets.count
          @subnet = subnets[subnet_index]
        end

        @id = resource :aws_instance, ident, {
          ami: options[:ami],
          instance_type: options[:instance_type],
          credit_specification: {
            cpu_credits: options[:cpu_credits]
          },
          iam_instance_profile: profile_from(options[:instance_profile]),
          subnet_id: @subnet.id,
          associate_public_ip_address: options[:public],
          root_block_device: {
            volume_type: 'gp2',
            volume_size: 32
          },
          tags: {
            'Name' => ident
          }.merge(options[:tags]),
          vpc_security_group_ids: [
            vpc.internal_ssh_security_group
          ].push(*options[:security_groups]),
          user_data: options[:user_data],
          lifecycle: {
            create_before_destroy: true
          },
          depends_on: options[:depends_on]
        }.merge(options[:ip_address] ? { private_ip: options[:ip_address] } : {}).merge(lifecycle)

        @ip_address = output_of(:aws_instance, ident, options[:public] ? :public_ip : :private_ip)

        self
      end

      def profile_from(profile)
        profile.respond_to?(:id) ? profile.id : profile
      end
    end
  end
end

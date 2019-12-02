# frozen_string_literal: true

require 'terrafying/components/loadbalancer'
require 'terrafying/components/usable'
require 'terrafying/components/vpc'
require 'terrafying/generator'

module Terrafying
  module Components
    class Endpoint < Terrafying::Context
      attr_reader :fqdn, :security_group

      include Usable

      def self.create_in(vpc, name, options = {})
        Endpoint.new.create_in(vpc, name, options)
      end

      def initialize
        super
      end

      def create_in(vpc, name, options = {})
        options = {
          auto_accept: true,
          subnets: vpc.subnets.fetch(:private, []),
          private_dns: false,
          tags: {}
        }.merge(options)

        ident = "#{tf_safe(vpc.name)}-#{name}"
        @name = ident

        if options[:service]
          service_name = options[:service].service_name

          @ports = options[:service].load_balancer.ports
        elsif options[:service_name]
          service_name = options[:service_name]

          if options[:service_name].start_with?('com.amazonaws')
            @ports = enrich_ports([443])
          else
            endpoint_service = aws.endpoint_service_by_name(options[:service_name])

            target_groups = endpoint_service.network_load_balancer_arns.map do |arn|
              aws.target_groups_by_lb(arn)
            end.flatten

            @ports = enrich_ports(target_groups.map(&:port))
          end
        elsif options[:source]
          source = if options[:source].is_a?(VPC)
                     { vpc: options[:source], name: name }
                   else
                     options[:source]
                   end

          lb = LoadBalancer.find_in(source[:vpc], source[:name])

          @ports = lb.ports
          service_name = aws.endpoint_service_by_lb_arn(lb.id).service_name
        else
          raise 'You need to pass either a service_name or source option to create an endpoint'
        end

        @security_group = resource :aws_security_group, ident,
                                   name: "endpoint-#{ident}",
                                   description: "Describe the ingress and egress of the endpoint #{ident}",
                                   tags: options[:tags],
                                   vpc_id: vpc.id

        resource :aws_vpc_endpoint, ident,
                 vpc_id: vpc.id,
                 service_name: service_name,
                 vpc_endpoint_type: 'Interface',
                 security_group_ids: [@security_group],
                 auto_accept: options[:auto_accept],
                 subnet_ids: options[:subnets].map(&:id),
                 private_dns_enabled: options[:private_dns]

        @fqdn = output_of(:aws_vpc_endpoint, ident, 'dns_entry.0.dns_name')

        if options[:service]
          endpoint_service = options[:service]

          record_name = endpoint_service.fqdn.gsub(/.#{endpoint_service.zone.fqdn}$/, '')

          private_zone = add! Zone.create(endpoint_service.zone.fqdn, vpc: vpc)
          private_zone.add_record(
            record_name, [@fqdn], type: 'CNAME',
                                  resource_name: tf_safe("#{@name}-#{endpoint_service.fqdn}")
          )
        end

        self
      end
    end
  end
end

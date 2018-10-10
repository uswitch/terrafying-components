require 'digest'
require 'terrafying/components/usable'
require 'terrafying/generator'

require_relative './ports'

module Terrafying

  module Components

    class LoadBalancer < Terrafying::Context

      attr_reader :id, :name, :type, :security_group, :ports, :target_groups, :alias_config

      include Usable

      def self.create_in(vpc, name, options={})
        LoadBalancer.new.create_in vpc, name, options
      end

      def self.find_in(vpc, name)
        LoadBalancer.new.find_in vpc, name
      end

      def initialize()
        super
      end

      def find_in(vpc, name)
        @type = "network"
        ident = make_identifier(@type, vpc.name, name)

        begin
          lb = aws.lb_by_name(ident)
        rescue
          @type = "application"
          ident = make_identifier(@type, vpc.name, name)

          lb = aws.lb_by_name(ident)

          @security_group = aws.security_group_by_tags({ loadbalancer_name: ident })
        end

        @id = lb.load_balancer_arn
        @name = ident

        target_groups = aws.target_groups_by_lb(@id)

        @target_groups = target_groups.map(&:target_group_arn)
        @ports = enrich_ports(target_groups.map(&:port).sort.uniq)

        @alias_config = {
          name: lb.dns_name,
          zone_id: lb.canonical_hosted_zone_id,
          evaluate_target_health: true,
        }

        self
      end

      def create_in(vpc, name, options={})
        options = {
          ports: [],
          public: false,
          subnets: vpc.subnets.fetch(:private, []),
          tags: {
            Name: name
          },
          hex_ident: false
        }.merge(options)

        @hex_ident = options[:hex_ident]
        @ports = enrich_ports(options[:ports])

        l4_ports = @ports.select{ |p| is_l4_port(p) }

        if l4_ports.count > 0 && l4_ports.count < @ports.count
          raise 'Ports have to either be all layer 4 or 7'
        end

        @type = l4_ports.count == 0 ? "application" : "network"

        ident = make_identifier(@type, vpc.name, name)
        @name = ident

        if @type == "application"
          @security_group = resource :aws_security_group, ident, {
                                       name: "loadbalancer-#{ident}",
                                       description: "Describe the ingress and egress of the load balancer #{ident}",
                                       tags: options[:tags].merge(
                                         {
                                           loadbalancer_name: ident,
                                         }
                                       ),
                                       vpc_id: vpc.id,
                                     }

          path_mtu_setup!
        end

        @id = resource :aws_lb, ident, {
                         name: ident,
                         load_balancer_type: type,
                         internal: !options[:public],
                         subnet_mapping: options[:subnets].map{ |subnet|
                           {subnet_id: subnet.id}
                         },
                         tags: options[:tags],
                       }.merge(@type == "application" ? { security_groups: [@security_group] } : {})

        @target_groups = []

        @ports.each { |port|
          port_ident = "#{ident}-#{port[:downstream_port]}"

          target_group = resource :aws_lb_target_group, port_ident, {
                                    name: port_ident,
                                    port: port[:downstream_port],
                                    protocol: port[:type].upcase,
                                    vpc_id: vpc.id,
                                  }.merge(port.has_key?(:health_check) ? { health_check: port[:health_check] }: {})

          ssl_options = {}
          if port.has_key?(:ssl_certificate)
            ssl_options = {
              ssl_policy: "ELBSecurityPolicy-2015-05",
              certificate_arn: port[:ssl_certificate],
            }
          end

          resource :aws_lb_listener, port_ident, {
                     load_balancer_arn: @id,
                     port: port[:upstream_port],
                     protocol: port[:type].upcase,
                     default_action: {
                       target_group_arn: target_group,
                       type: "forward",
                     },
                   }.merge(ssl_options)

          @target_groups << target_group
        }

        @alias_config = {
          name: output_of(:aws_lb, ident, :dns_name),
          zone_id: output_of(:aws_lb, ident, :zone_id),
          evaluate_target_health: true,
        }

        self
      end

      def attach(set)
        if set.respond_to?(:attach_load_balancer)
          set.attach_load_balancer(self)

          if @type == "network"
            @security_group = set.ingress_security_group
          end
        else
          raise "Dont' know how to attach object to LB"
        end
      end

      def make_identifier(type, vpc_name, name)
        gen_id = "#{type}-#{tf_safe(vpc_name)}-#{name}"
        return Digest::SHA2.hexdigest(gen_id)[0..24] if @hex_ident || gen_id.size > 26
        gen_id[0..31]
      end

    end

  end

end

# frozen_string_literal: true

require 'terrafying/components/usable'
require 'terrafying/generator'
require 'digest'
require_relative './ports'

module Terrafying
  module Components
    class LoadBalancer < Terrafying::Context
      attr_reader :id, :name, :type, :security_group, :ports, :targets, :alias_config

      Struct.new('Target', :target_group, :listener, keyword_init: true)

      include Usable

      def self.create_in(vpc, name, options = {})
        LoadBalancer.new.create_in vpc, name, options
      end

      def self.find_in(vpc, name)
        LoadBalancer.new.find_in vpc, name
      end

      def initialize
        super
      end

      def find_in(vpc, name)
        @type = 'network'
        ident = make_identifier(@type, vpc.name, name)

        begin
          lb = aws.lb_by_name(ident)
        rescue StandardError
          @type = 'application'
          ident = make_identifier(@type, vpc.name, name)
          name = make_name(@type, vpc.name, name)

          lb = aws.lb_by_name(name)

          @security_group = aws.security_group_by_tags(loadbalancer_name: name)
        end

        @id = lb.load_balancer_arn
        @name = name

        target_groups = aws.target_groups_by_lb(@id)

        @targets = target_groups.map do |tg|
          Struct::Target.new(
            target_group: tg.target_group_arn,
            listener: nil
          )
        end

        @ports = enrich_ports(target_groups.map(&:port).sort.uniq)

        @alias_config = {
          name: lb.dns_name,
          zone_id: lb.canonical_hosted_zone_id,
          evaluate_target_health: true
        }

        self
      end

      def create_in(vpc, name, options = {})
        options = {
          ports: [],
          public: false,
          subnets: vpc.subnets.fetch(:private, []),
          cross_zone_load_balancing: false,
          hex_ident: false,
          idle_timeout: nil,
          tags: {},
          security_groups: []
        }.merge(options)

        @tags = {
          Name: name
        }.merge(options[:tags])

        @hex_ident = options[:hex_ident]
        @ports = enrich_ports(options[:ports])

        l4_ports = @ports.select { |p| is_l4_port(p) }

        if l4_ports.count > 0 && l4_ports.count < @ports.count
          raise 'Ports have to either be all layer 4 or 7'
        end

        @type = l4_ports.count == 0 ? 'application' : 'network'

        ident = make_identifier(@type, vpc.name, name)
        @name = make_name(@type, vpc.name, name)

        if application?
          @security_group = resource :aws_security_group, ident,
                                     name: "loadbalancer-#{@name}",
                                     description: "Describe the ingress and egress of the load balancer #{@name}",
                                     tags: @tags.merge(
                                       loadbalancer_name: @name
                                     ),
                                     vpc_id: vpc.id

          path_mtu_setup!
        end

        if network? && options[:security_groups].count > 0
          warn 'You cannot set security groups on a network loadbalancer, set them on the instances behind it.'
        end

        @id = resource :aws_lb, ident, {
          name: @name,
          load_balancer_type: type,
          internal: !options[:public],
          tags: @tags
        }.merge(subnets_for(options[:subnets]))
              .merge(application? ? { security_groups: [@security_group] + options[:security_groups], idle_timeout: options[:idle_timeout], access_logs: options[:access_logs] } : {})
              .merge(network? ? { enable_cross_zone_load_balancing: options[:cross_zone_load_balancing] } : {})
              .compact

        @targets = []

        @ports.each do |port|
          port_ident = "#{ident}-#{port[:downstream_port]}"
          port_name = "#{@name}-#{port[:downstream_port]}"

          actions = []

          default_action = port.key?(:action) ? port[:action] : forward_to_tg(port, port_ident, port_name, vpc)

          actions.append(authenticate_oidc(port[:oidc_config])) if !port[:oidc_config].nil?
          actions.append(default_action)

          ssl_options = alb_certs(port, port_ident)

          listener = resource :aws_lb_listener, port_ident, {
            load_balancer_arn: @id,
            port: port[:upstream_port],
            protocol: port[:type].upcase,
            default_action: actions
          }.merge(ssl_options)

          register_target(default_action[:target_group_arn], listener) if default_action[:type] == 'forward'
        end

        @alias_config = {
          name: output_of(:aws_lb, ident, :dns_name),
          zone_id: output_of(:aws_lb, ident, :zone_id),
          evaluate_target_health: true
        }
        self
      end

      def forward_to_tg(port, port_ident, port_name, vpc)
        target_group = resource :aws_lb_target_group, port_ident, {
          name: port_name,
          port: port[:downstream_port],
          protocol: port[:type].upcase,
          vpc_id: vpc.id
        }.merge(port.key?(:health_check) ? { health_check: port[:health_check] } : {})

        {
          type: 'forward',
          target_group_arn: target_group
        }
      end

      def authenticate_oidc(oidc_config)
        {
          type: "authenticate-oidc",
          authenticate_oidc: oidc_config
        }
      end

      def register_target(target_group, listener)
        @targets << Struct::Target.new(
          target_group: target_group,
          listener: listener
        )
      end

      def alb_certs(port, port_ident)
        return {} unless port.key? :ssl_certificate

        certs = Array(port[:ssl_certificate])
        default_cert = certs.shift
        certs.map { |cert| alb_cert(cert, port_ident) }

        {
          ssl_policy: 'ELBSecurityPolicy-TLS-1-2-2017-01',
          certificate_arn: default_cert
        }
      end

      def alb_cert(cert_arn, port_ident)
        cert_ident = "#{port_ident}-#{Digest::SHA2.hexdigest(cert_arn)[0..8]}"

        resource :aws_lb_listener_certificate, cert_ident,
                 listener_arn: "${aws_lb_listener.#{port_ident}.arn}",
                 certificate_arn: cert_arn
      end

      def application?
        @type == 'application'
      end

      def subnets_for(subnets)
        { subnets: subnets.map(&:id) }
      end

      def network?
        @type == 'network'
      end

      def attach(set)
        raise "Dont' know how to attach object to LB" unless set.respond_to?(:attach_load_balancer)

        set.attach_load_balancer(self)
        @security_group = set.ingress_security_group if network?
      end

      def autoscale(set, target_value:, disable_scale_in:)
        raise "Dont' know how to attach object to LB" unless set.respond_to?(:autoscale_on_load_balancer)

        set.autoscale_on_load_balancer(self, target_value: target_value, disable_scale_in: disable_scale_in)
      end

      def make_name(type, vpc_name, name)
        gen_id = "#{type}-#{tf_safe(vpc_name)}-#{name}"
        return Digest::SHA2.hexdigest(gen_id)[0..24] if @hex_ident || gen_id.size > 26

        gen_id[0..31]
      end

      def make_identifier(type, vpc_name, name)
        make_name(type, vpc_name, name).gsub(%r{^(\d)}, '_\1')
      end
    end
  end
end

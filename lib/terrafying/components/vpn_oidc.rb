
# frozen_string_literal: true

require 'digest'
require 'netaddr'

require 'terrafying/components/ignition'
require 'terrafying/generator'

IN4MASK = 0xffffffff

def cidr_to_split_address(raw_cidr)
  cidr = NetAddr::CIDR.create(raw_cidr)

  masklen = 32 - cidr.bits
  maskaddr = ((IN4MASK >> masklen) << masklen)

  maskip = (0..3).map do |i|
    (maskaddr >> (24 - 8 * i)) & 0xff
  end.join('.')

  "#{cidr.first} #{maskip}"
end

module Terrafying
  module Components
    class OIDCVPN < Terrafying::Context
      attr_reader :name, :cidr, :service, :ip_address

      def self.create_in(vpc, name, provider, options = {})
        new.create_in vpc, name, provider, options
      end

      def initialize
        super
      end

      def create_in(vpc, name, oidc_provider, options = {})
        options = {
          groups: [],
          cidr: '10.8.0.0/24',
          public: true,
          eip: true,
          subnets: vpc.subnets.fetch(:public, []),
          static: false,
          route_all_traffic: false,
          route_dns_entries: [],
          units: [],
          tags: {},
          service: {}
        }.merge(options)

        @name = name
        @vpc = vpc
        @cidr = options[:cidr]
        @fqdn = vpc.zone.qualify(name)

        unless oidc_provider.is_a?(Hash) && %i[client_id issuer_url].all? { |k| oidc_provider.key?(k) }
          raise 'you need to pass a oidc_provider with a client_id and issuer_url'
        end

        units = [
          openvpn_service,
          openvpn_authz_service(options[:route_all_traffic], options[:route_dns_entries], options[:groups], oidc_provider),
          caddy_service(options[:ca])
        ]
        files = [
          openvpn_conf,
          openvpn_env,
          openvpn_ip_delay,
          caddy_conf(options[:ca])
        ]
        keypairs = []

        if options.key?(:ca)
          keypairs.push(options[:ca].create_keypair_in(self, @fqdn))
        end

        if options[:static]
          subnet = options[:subnets].first
          instances = [{ subnet: subnet, ip_address: subnet.ip_addresses.first }]
        else
          instances = [{}]
        end

        @is_public = options[:public]
        @service = add! Service.create_in(
          vpc, name,
          {
            eip: @is_public,
            public: @is_public,
            ports: [22, 443, { number: 1194, type: 'udp' }],
            tags: options[:tags],
            units: units + options[:units],
            files: files,
            keypairs: keypairs,
            subnets: options[:subnets],
            instances: instances,
            iam_policy_statements: [
              {
                Effect: 'Allow',
                Action: [
                  'ec2:DescribeRouteTables'
                ],
                Resource: [
                  '*'
                ]
              }
            ]
          }.merge(options[:service])
        )

        @ip_address = @service.instance_set.instances[0].ip_address

        self
      end

      def allow_security_group_in(vpc, name: '')
        name = "allow-#{@vpc.name}-vpn".downcase if name.empty?

        ingress_rules = [
          {
            from_port: 0,
            to_port: 0,
            protocol: -1,
            security_groups: [@service.egress_security_group]
          }
        ]

        if @is_public
          ingress_rules << {
            from_port: 0,
            to_port: 0,
            protocol: -1,
            cidr_blocks: ["#{@ip_address}/32"]
          }
        end

        resource :aws_security_group, tf_safe("#{name}-#{vpc.name}"),
                 name: name,
                 vpc_id: vpc.id,
                 ingress: ingress_rules
      end

      def openvpn_service
        Ignition.container_unit(
          'openvpn', 'kylemanna/openvpn',
          host_networking: true,
          privileged: true,
          volumes: [
            '/etc/ssl/openvpn:/etc/ssl/openvpn:ro',
            '/etc/openvpn:/etc/openvpn'
          ],
          required_units: ['docker.service', 'network-online.target', 'openvpn-authz.service']
        )
      end

      def openvpn_authz_service(route_all_traffic, route_dns_entry, groups, oidc)
        optional_arguments = []

        optional_arguments << '--route-all' if route_all_traffic

        optional_arguments += groups.map { |group| "--oidc-allowed-groups \"#{group}\"" }
        optional_arguments += route_dns_entry.map { |entry| "--route-dns-entries #{entry}" }

        Ignition.container_unit(
          'openvpn-authz', 'quay.io/uswitch/openvpn-authz:2.0',
          host_networking: true,
          volumes: [
            '/etc/ssl/openvpn:/etc/ssl/openvpn',
            '/var/openvpn-authz:/var/openvpn-authz'
          ],
          environment_variables: [
            "AWS_REGION=#{aws.region}"
          ],
          arguments: optional_arguments + [
            "--http-address http://127.0.0.1:8080",
            "--fqdn #{@fqdn}",
            '--cache /var/openvpn-authz',
            "--oidc-client-id \"#{oidc[:client_id]}\"",
            "--oidc-issuer-url \"#{oidc[:issuer_url]}\"",
            '/etc/ssl/openvpn'
          ]
        )
      end

      def caddy_service(ca)
        optional_volumes = []

        optional_volumes << "/etc/ssl/#{ca.name}:/etc/ssl/#{ca.name}:ro" if ca

        Ignition.container_unit(
          'caddy', 'abiosoft/caddy:0.10.10',
          host_networking: true,
          volumes: [
            '/etc/ssl/certs:/etc/ssl/cert:ro',
            '/etc/caddy/Caddyfile:/etc/Caddyfile',
            '/etc/caddy/certs:/etc/caddy/certs'
          ] + optional_volumes,
          environment_variables: [
            'CADDYPATH=/etc/caddy/certs'
          ]
        )
      end

      def caddy_conf(ca)
        tls = ca ? "/etc/ssl/#{ca.name}/#{@fqdn}/cert /etc/ssl/#{ca.name}/#{@fqdn}/key" : 'cloud@uswitch.com'
        {
          path: '/etc/caddy/Caddyfile',
          mode: '0644',
          contents: <<~CADDYFILE
            #{@fqdn}:443
            tls #{tls}
            proxy / localhost:8080 {
              transparent
            }
          CADDYFILE
        }
      end

      def openvpn_conf
        {
          path: '/etc/openvpn/openvpn.conf',
          mode: '0644',
          contents: <<~EOF
            server #{cidr_to_split_address(@cidr)}
            verb 3

            iproute /etc/openvpn/ovpn_ip.sh

            key /etc/ssl/openvpn/server/key
            ca /etc/ssl/openvpn/ca/cert
            cert /etc/ssl/openvpn/server/cert
            dh /etc/ssl/openvpn/dh.pem
            tls-auth /etc/ssl/openvpn/ta.key

            cipher AES-256-CBC
            auth SHA512
            tls-version-min 1.2

            key-direction 0
            keepalive 10 60
            persist-key
            persist-tun

            proto udp
            # Rely on Docker to do port mapping, internally always 1194
            port 1194
            dev tun0
            status /tmp/openvpn-status.log

            user nobody
            group nogroup
          EOF
        }
      end

      def openvpn_env
        {
          path: '/etc/openvpn/ovpn_env.sh',
          mode: '0644',
          contents: <<~EOF
            declare -x OVPN_SERVER=#{@cidr}
          EOF
        }
      end

      # OpenVPN doesn't wait long enough for the tun0 device to init
      # https://github.com/kylemanna/docker-openvpn/issues/370
      def openvpn_ip_delay
        {
          path: '/etc/openvpn/ovpn_ip.sh',
          mode: '0755',
          contents: <<~IP_SCRIPT
            #!/usr/bin/env bash
            sleep 0.1
            /sbin/ip $*
          IP_SCRIPT
        }
      end

      def with_endpoint_service(*args)
        @service.with_endpoint_service(*args)
      end

      def security_group
        @service.security_group
      end

      def ingress_security_group
        @service.ingress_security_group
      end

      def egress_security_group
        @service.egress_security_group
      end

      def pingable_by(*services)
        @service.pingable_by(*services)
      end

      def used_by(*services)
        @service.used_by(*services)
      end

      def pingable_by_cidr(*cidrs)
        @service.pingable_by_cidr(*cidrs)
      end

      def used_by_cidr(*cidrs)
        @service.used_by_cidr(*cidrs)
      end
    end
  end
end

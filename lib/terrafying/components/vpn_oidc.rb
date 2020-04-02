
# frozen_string_literal: true

require 'digest'
require 'netaddr'

require 'terrafying/components/ignition'
require 'terrafying/components/service'
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

      def self.create_in(options)
        new(**options).tap(&:create_in)
      end

      def initialize(
        vpc:,
        name:,
        client_id:,
        issuer_url:,
        ca: nil,
        groups: [],
        cidr: '10.8.0.0/24',
        public: true,
        subnets: vpc.subnets.fetch(:public, []),
        static: false,
        route_all_traffic: false,
        route_dns_entries: [],
        units: [],
        tags: {},
        service_options: {}
      )
        super()
        @vpc = vpc
        @name = name
        @client_id = client_id
        @issuer_url = issuer_url
        @ca = ca
        @groups = groups
        @cidr = cidr
        @zone = vpc.zone
        @fqdn = @zone.qualify(name)
        @public = public
        @subnets = subnets
        @static = static
        @route_all_traffic = route_all_traffic
        @route_dns_entries = route_dns_entries
        @units = units
        @tags = tags
        @service_options = service_options
      end

      def create_in
        units = [
          openvpn_service,
          openvpn_authz_service(@ca, @fqdn, @route_all_traffic, @route_dns_entries, @groups, @client_id, @issuer_url),
        ]

        files = [
          openvpn_conf,
          openvpn_env,
          openvpn_ip_delay,
        ]

        if @ca
          units += [cert_checking_service, cert_checking_path, cert_checking_timer,restart_openvpn_authz_service]
          files << cert_checking_conf
        end

        keypairs = []
        keypairs.push(@ca.create_keypair_in(self, @fqdn, zone: @zone)) if @ca

        instances = [{}]
        if @static
          subnet = @subnets.first
          instances = [{ subnet: subnet, ip_address: subnet.ip_addresses.first }]
        end

        @service = add! Service.create_in(
          @vpc, @name,
          {
            eip: @public,
            public: @public,
            ports: [22, 443, { number: 1194, type: 'udp' }],
            tags:@tags,
            units: units + @units,
            files: files,
            keypairs: keypairs,
            subnets: @subnets,
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
          }.merge(@service_options)
        )

        @ip_address = @service.instance_set.instances.first.ip_address
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

        if @public
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

      def cert_checking_conf
        {
          path: '/opt/cert_checking.yml',
          mode: '0644',
          contents: <<~CERT_CHECKING_CONF
            casource: #{@ca.name}
            caname: #{@ca.source}
            fqdn: #{@fqdn}
          CERT_CHECKING_CONF
        }
      end

      def cert_checking_timer
        {

          name: 'cert_checking.timer',
          contents: <<~CERT_CHECKING_TIMER
            [Unit]
            Description=Certificate Checking Service Timer
            [Timer]
            OnCalendar=*-*-* 00:00:00
            Unit=cert_checking.service
            [Install]
            WantedBy=multi-user.target
          CERT_CHECKING_TIMER
        }
      end

      def cert_checking_service
        {
        name: 'cert_checking.service',
        enabled: false,
        contents: <<~CERT_CHECKING_SERVICE
            [Install]
            WantedBy=multi-user.target
            [Unit]
            Description=cert_checking
            [Service]
            Type=oneshot
            ExecStartPre=-/usr/bin/docker rm -f cert_checking
            ExecStart=/usr/bin/docker run --name cert_checking  \
            -e AWS_REGION=#{aws.region} \
            -v /etc/ssl/#{@ca.name}:/etc/ssl/#{@ca.name} \
            -v /opt/cert_checking.yml:/cert_checking.yml quay.io/uswitch/cert-downloader:v0.1
        CERT_CHECKING_SERVICE
        }
      end

      def cert_checking_path
        {

          name: 'cert_checking.path',
          contents: <<~CERT_CHECKING_PATH
            [Unit]
            Description=Monitor the file for changes
            [Path]
            PathChanged=/etc/ssl/#{@ca.name}
            Unit=restart-openvpn-authz.service
            [Install]
            WantedBy=multi-user.target
          CERT_CHECKING_PATH
        }
      end

      def restart_openvpn_authz_service
        {
          name: 'restart-openvpn-authz.service',
          enabled: false,
          contents: <<~RESTART_OPENVPN_AUTHZ
              [Install]
              WantedBy=multi-user.target
              [Unit]
              Description=restart openvpn-authz service
              [Service]
              Type=oneshot
              ExecStart=/usr/bin/systemctl restart openvpn-authz.service
          RESTART_OPENVPN_AUTHZ
          }
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

      def openvpn_authz_service(ca, fqdn, route_all_traffic, route_dns_entry, groups, client_id, issuer_url)
        optional_arguments = []
        optional_volumes = []

        optional_arguments << '--route-all' if route_all_traffic
        optional_arguments += groups.map { |group| "--oidc-allowed-groups \"#{group}\"" }
        optional_arguments += route_dns_entry.map { |entry| "--route-dns-entries #{entry}" }
        optional_arguments << "--tls-cert-file /etc/ssl/#{ca.name}/#{fqdn}/cert" if ca
        optional_arguments << "--tls-key-file /etc/ssl/#{ca.name}/#{fqdn}/key" if ca
        optional_volumes << "/etc/ssl/#{ca.name}:/etc/ssl/#{ca.name}" if ca

        Ignition.container_unit(
          'openvpn-authz', 'quay.io/uswitch/openvpn-authz:2.1',
          volumes: optional_volumes + [
            '/etc/ssl/openvpn:/etc/ssl/openvpn',
            '/var/openvpn-authz:/var/openvpn-authz'
          ],
          environment_variables: [
            "AWS_REGION=#{aws.region}"
          ],
          ports: ['443'],
          arguments: optional_arguments + [
            "--http-address https://0.0.0.0:443",
            "--fqdn #{fqdn}",
            '--cache /var/openvpn-authz',
            "--oidc-client-id \"#{client_id}\"",
            "--oidc-issuer-url \"#{issuer_url}\"",
            '/etc/ssl/openvpn'
          ]
        )
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

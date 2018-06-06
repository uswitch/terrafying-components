
module Terrafying

  module Components

    module Usable

      def security_group
        @security_group
      end

      def ingress_security_group
        @ingress_security_group || @security_group
      end

      def egress_security_group
        @egress_security_group || @security_group
      end

      def path_mtu_setup!
        resource :aws_security_group_rule, "#{@name}-path-mtu", {
                     security_group_id: self.egress_security_group,
                     type: "ingress",
                     protocol: 1, # icmp
                     from_port: 3, # icmp type
                     to_port: 4, # icmp code
                     cidr_blocks: ["0.0.0.0/0"],
                   }
      end

      def pingable_by_cidr(*cidrs)
        ident = Digest::SHA2.hexdigest cidrs.to_s

        resource :aws_security_group_rule, "#{@name}-to-#{ident}-ping", {
                     security_group_id: self.ingress_security_group,
                     type: "ingress",
                     protocol: 1, # icmp
                     from_port: 8, # icmp type
                     to_port: 0, # icmp code
                     cidr_blocks: cidrs,
                   }
      end

      def used_by_cidr(*cidrs, &block)
        cidrs.map do |cidr|
          cidr_ident = cidr.gsub('./', '-')

          @ports.select(&block).map do |port|
            resource :aws_security_group_rule, "#{@name}-to-#{cidr_ident}-#{port[:name]}", {
              security_group_id: ingress_security_group,
              type: 'ingress',
              from_port: from_port(port[:upstream_port]),
              to_port: to_port(port[:upstream_port]),
              protocol: port[:type] == 'udp' ? 'udp' : 'tcp',
              cidr_blocks: [cidr]
            }
          end
        end
      end

      def pingable_by(*other_resources)
        other_resources.map { |other_resource|
          resource :aws_security_group_rule, "#{@name}-to-#{other_resource.name}-ping", {
                     security_group_id: self.ingress_security_group,
                     type: "ingress",
                     protocol: 1, # icmp
                     from_port: 8, # icmp type
                     to_port: 0, # icmp code
                     source_security_group_id: other_resource.egress_security_group,
                   }

          resource :aws_security_group_rule, "#{@name}-to-#{other_resource.name}-pingv6", {
                     security_group_id: self.ingress_security_group,
                     type: "ingress",
                     protocol: 58, # icmpv6
                     from_port: 128, # icmp type
                     to_port: 0, # icmp code
                     source_security_group_id: other_resource.egress_security_group,
                   }

          resource :aws_security_group_rule, "#{other_resource.name}-to-#{@name}-ping", {
                     security_group_id: other_resource.egress_security_group,
                     type: "egress",
                     protocol: 1, # icmp
                     from_port: 8, # icmp type
                     to_port: 0, # icmp code
                     source_security_group_id: self.ingress_security_group,
                   }

          resource :aws_security_group_rule, "#{other_resource.name}-to-#{@name}-pingv6", {
                     security_group_id: other_resource.egress_security_group,
                     type: "egress",
                     protocol: 58, # icmpv6
                     from_port: 128, # icmp type
                     to_port: 0, # icmp code
                     source_security_group_id: self.ingress_security_group,
                   }
        }
      end

      def used_by(*other_resources)
        other_resources.map { |other_resource|
          @ports.map {|port|
            resource :aws_security_group_rule, "#{@name}-to-#{other_resource.name}-#{port[:name]}", {
                       security_group_id: self.ingress_security_group,
                       type: "ingress",
                       from_port: from_port(port[:upstream_port]),
                       to_port: to_port(port[:upstream_port]),
                       protocol: port[:type] == "udp" ? "udp" : "tcp",
                       source_security_group_id: other_resource.egress_security_group,
                     }

            resource :aws_security_group_rule, "#{other_resource.name}-to-#{@name}-#{port[:name]}", {
                       security_group_id: other_resource.egress_security_group,
                       type: "egress",
                       from_port: from_port(port[:downstream_port]),
                       to_port: to_port(port[:downstream_port]),
                       protocol: port[:type] == "udp" ? "udp" : "tcp",
                       source_security_group_id: self.ingress_security_group,
                     }
          }
        }
      end

    end

  end

end


PORT_NAMES = {
  22 => "ssh",
  80 => "http",
  443 => "https",
  1194 => "openvpn",
}

def enrich_ports(ports)
  ports.map { |port|
    if port.is_a?(Numeric)
      port = { upstream_port: port, downstream_port: port }
    end

    if port.has_key?(:number)
      port[:upstream_port] = port[:number]
      port[:downstream_port] = port[:number]
    end

    port = {
      type: "tcp",
      name: PORT_NAMES.fetch(port[:upstream_port], port[:upstream_port].to_s),
    }.merge(port)

    port
  }
end

def from_port(port)
  return port unless port_range?(port)
  port.split('-').first.to_i
end

def to_port(port)
  return port unless port_range?(port)
  port.split('-').last.to_i
end

def port_range?(port)
  port.is_a?(String) && port.match(/[0-9]+-[0-9]+/)
end

def is_l4_port(port)
  port[:type] == "tcp" || port[:type] == "udp"
end

def is_l7_port(port)
  port[:type] == "http" || port[:type] == "https"
end

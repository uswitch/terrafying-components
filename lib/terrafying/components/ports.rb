
PORT_NAMES = {
  22 => "ssh",
  80 => "http",
  443 => "https",
  1194 => "openvpn",
}

def enrich_ports(ports)
  ports = add_upstream_downstream(ports)
  ports = add_redirects(ports)
  add_names(ports)
end

def add_upstream_downstream(ports)
  ports.map do |port|
    if port.is_a?(Numeric)
      port = { upstream_port: port, downstream_port: port }
    end

    if port.key?(:number)
      port[:upstream_port] = port[:number]
      port[:downstream_port] = port[:number]
    end
    port
  end
end

def add_redirects(ports)
  ports.flat_map do |port|
    if port.key? :redirect_http_from_port
      redirect_port = redirect_http(port[:redirect_http_from_port], port[:upstream_port])
      port.delete(:redirect_http_from_port)
      return [port, redirect_port]
    end
    port
  end
end

def redirect_http(from_port, to_port)
  {
    upstream_port: from_port,
    downstream_port: from_port,
    type: 'http',
    action: {
      type: 'redirect',
      redirect: { port: to_port, protocol: 'HTTPS', status_code: 'HTTP_301' }
    }
  }
end

def add_names(ports)
  ports.map do |port|
    {
      type: 'tcp',
      name: PORT_NAMES.fetch(port[:upstream_port], port[:upstream_port].to_s),
    }.merge(port)
  end
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

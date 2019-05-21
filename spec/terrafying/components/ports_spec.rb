# frozen_string_literal: true

require 'terrafying/components/ports'

RSpec.describe Object, '#enrich_ports' do
  context 'when http redirect is specified' do
    it 'should create a new http port' do
      ports = [{
        type: 'https',
        number: 443,
        redirect_http_from_port: 80
      }]

      enriched_ports = enrich_ports(ports)

      expect(enriched_ports).to include(
        a_hash_including(
          name: 'http',
          type: 'http',
          upstream_port: 80,
          downstream_port: 80
        )
      )
    end

    it 'should create a http redirect action' do
      ports = [{
        number: 443,
        redirect_http_from_port: 80
      }]

      enriched_ports = enrich_ports(ports)

      expect(enriched_ports).to include(
        a_hash_including(
          name: 'http',
          action: {
            type: 'redirect',
            redirect: {
              port: 443,
              protocol: 'HTTPS',
              status_code: 'HTTP_301'
            }
          }
        )
      )
    end
  end

  context 'converting to port' do
    it 'should convert a number to a port' do
      ports = [123]

      enriched_ports = enrich_ports(ports)

      expect(enriched_ports).to include(
        a_hash_including(name: '123', upstream_port: 123, downstream_port: 123)
      )
    end

    it 'should convert a hash with a number to a port' do
      ports = [{ number: 123 }]

      enriched_ports = enrich_ports(ports)

      expect(enriched_ports).to include(
        a_hash_including(name: '123', upstream_port: 123, downstream_port: 123)
      )
    end
  end

  context 'port names' do
    it 'should name the port according to the IANA number' do
      ports = [22, 80, 443, 1194]

      enriched_ports = enrich_ports(ports)

      expect(enriched_ports).to include(
        a_hash_including(name: 'ssh', upstream_port: 22),
        a_hash_including(name: 'http', upstream_port: 80),
        a_hash_including(name: 'https', upstream_port: 443),
        a_hash_including(name: 'openvpn', upstream_port: 1194)
      )
    end
  end
end

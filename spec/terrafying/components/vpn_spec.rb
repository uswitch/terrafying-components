# frozen_string_literal: true

require 'terrafying'
require 'terrafying/components/vpn'

RSpec.describe Terrafying::Components::VPN do
  before do
    @vpc = stub_vpc('a-vpc', '10.0.0.0/16')
  end

  context 'validation of provider' do
    it 'requires a hash' do
      expect do
        Terrafying::Components::VPN.create_in(
          @vpc, 'foo', 'bhas'
        )
      end.to raise_error RuntimeError
    end

    it 'requires at least a type' do
      expect do
        Terrafying::Components::VPN.create_in(
          @vpc, 'foo', {}
        )
      end.to raise_error RuntimeError
    end

    it "it doesn't require client_id/client_secret if type is none" do
      expect do
        Terrafying::Components::VPN.create_in(
          @vpc, 'foo', type: 'none'
        )
      end.to_not raise_error
    end

    it "requires a client_id and client_secret if it's not none" do
      expect do
        Terrafying::Components::VPN.create_in(
          @vpc, 'foo', type: 'foo'
        )
      end.to raise_error RuntimeError
    end

    it 'if we provide a type, client_id and client_secret everything should be fine' do
      expect do
        Terrafying::Components::VPN.create_in(
          @vpc, 'foo', type: 'foo', client_id: 'foo', client_secret: 'foo'
        )
      end.to_not raise_error
    end
  end

  context 'oauth2 proxy' do
    it 'should have the id and secret in the user data' do
      vpn = Terrafying::Components::VPN.create_in(
        @vpc, 'foo', type: 'foo', client_id: 'some-id', client_secret: 'some-super-secret-string'
      )

      output = vpn.output_with_children

      vpn_instance = output['resource']['aws_instance'].values.first
      vpn_user_data = JSON.parse(vpn_instance[:user_data], symbolize_names: true)

      proxy_unit = vpn_user_data[:systemd][:units].select { |unit| unit[:name] == 'authnz.service' }.first

      expect(proxy_unit[:contents]).to include("--oauth-client-id='some-id'")
      expect(proxy_unit[:contents]).to include("--oauth-client-secret='some-super-secret-string'")
    end
  end

  context 'route_dns_entries' do
    it 'there shouldnt be any domains by default' do
      vpn = Terrafying::Components::VPN.create_in(
        @vpc, 'foo', type: 'none'
      )

      output = vpn.output_with_children

      vpn_instance = output['resource']['aws_instance'].values.first
      vpn_user_data = JSON.parse(vpn_instance[:user_data], symbolize_names: true)

      proxy_unit = vpn_user_data[:systemd][:units].select { |unit| unit[:name] == 'openvpn-authz.service' }.first

      expect(proxy_unit[:contents]).to_not include('--route-dns-entries')
    end

    it 'there shouldnt be any domains by default' do
      vpn = Terrafying::Components::VPN.create_in(
        @vpc, 'foo', { type: 'none' },
        route_dns_entries: [
          'wibble.com',
          'bibble.com'
        ]
      )

      output = vpn.output_with_children

      vpn_instance = output['resource']['aws_instance'].values.first
      vpn_user_data = JSON.parse(vpn_instance[:user_data], symbolize_names: true)

      proxy_unit = vpn_user_data[:systemd][:units].select { |unit| unit[:name] == 'openvpn-authz.service' }.first

      expect(proxy_unit[:contents]).to(
        include(
          '--route-dns-entries wibble.com',
          '--route-dns-entries bibble.com'
        )
      )
    end
  end
end

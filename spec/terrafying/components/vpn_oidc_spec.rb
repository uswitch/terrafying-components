# frozen_string_literal: true

require 'terrafying'
require 'terrafying/components/vpn_oidc'

RSpec.describe Terrafying::Components::OIDCVPN do
  before do
    @vpc = stub_vpc('a-vpc', '10.0.0.0/16')
  end

  context 'validation of provider' do
    it 'requires a hash' do
      expect do
        Terrafying::Components::OIDCVPN.create_in(
          @vpc, 'foo', 'bhas'
        )
      end.to raise_error RuntimeError
    end

    it 'requires at least a client_id and issuer_url' do
      expect do
        Terrafying::Components::OIDCVPN.create_in(
          @vpc, 'foo', {}
        )
      end.to raise_error RuntimeError
    end

    it 'if we provide a client_id and issuer_url everything should be fine' do
      expect do
        Terrafying::Components::OIDCVPN.create_in(
          @vpc, 'foo', client_id: 'foo', issuer_url: 'foo'
        )
      end.to_not raise_error
    end
  end

  context 'openvpn-authz' do
    it 'should have the id and secret in the user data' do
      vpn = Terrafying::Components::OIDCVPN.create_in(
        @vpc, 'foo', client_id: 'foo', issuer_url: 'foo.com/oidc'
      )

      output = vpn.output_with_children

      vpn_instance = output['resource']['aws_instance'].values.first
      vpn_user_data = JSON.parse(vpn_instance[:user_data], symbolize_names: true)

      authz_unit = vpn_user_data[:systemd][:units].select { |unit| unit[:name] == 'openvpn-authz.service' }.first

      expect(authz_unit[:contents]).to include('--oidc-client-id "foo"')
      expect(authz_unit[:contents]).to include('--oidc-issuer-url "foo.com/oidc"')
    end

    it 'should have groups if any are defined' do
      vpn = Terrafying::Components::OIDCVPN.create_in(
        @vpc, 'foo', { client_id: 'foo', issuer_url: 'foo.com/oidc' }, groups: ['test-group']
      )

      output = vpn.output_with_children

      vpn_instance = output['resource']['aws_instance'].values.first
      vpn_user_data = JSON.parse(vpn_instance[:user_data], symbolize_names: true)

      authz_unit = vpn_user_data[:systemd][:units].select { |unit| unit[:name] == 'openvpn-authz.service' }.first

      expect(authz_unit[:contents]).to include('--oidc-allowed-groups "test-group"')
    end

  end

  context 'route_dns_entries' do
    it 'there shouldnt be any domains by default' do
      vpn = Terrafying::Components::OIDCVPN.create_in(
        @vpc, 'foo', client_id: 'foo', issuer_url: 'foo.com/oidc'
      )

      output = vpn.output_with_children

      vpn_instance = output['resource']['aws_instance'].values.first
      vpn_user_data = JSON.parse(vpn_instance[:user_data], symbolize_names: true)

      proxy_unit = vpn_user_data[:systemd][:units].select { |unit| unit[:name] == 'openvpn-authz.service' }.first

      expect(proxy_unit[:contents]).to_not include('--route-dns-entries')
    end

    it 'there shouldnt be any domains by default' do
      vpn = Terrafying::Components::OIDCVPN.create_in(
        @vpc, 'foo', { client_id: 'foo', issuer_url: 'foo.com/oidc' },
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

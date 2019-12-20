# frozen_string_literal: true

require 'terrafying'
require 'terrafying/components/letsencrypt'

def providers_matching(ctx, type, name)
  ctx.output_with_children['provider']
     .select { |pr| pr.key?(type.to_s) && pr[type.to_s][:alias] == name }
end

def provider_matching(ctx, type, name)
  providers_matching(ctx, type, name).first
end

RSpec.describe Terrafying::Components::LetsEncrypt do
  it_behaves_like 'a CA'
end

RSpec.describe Terrafying::Components::LetsEncrypt, '#create' do
  context 'providers' do
    it 'creates the provider for staging' do
      ca = Terrafying::Components::LetsEncrypt.create('test-ca', 'test-bucket', renewing: true)

      prov = provider_matching(ca, :acme, :staging)

      expect(prov).to include(
        'acme' => {
          alias: :staging,
          server_url: 'https://acme-staging-v02.api.letsencrypt.org/directory'
        }
      )
    end

    it 'sets the provider for staging' do
      ca = Terrafying::Components::LetsEncrypt.create(
        'test-ca',
        'test-bucket',
        prefix: 'test-prefix',
        renewing: true,
        provider: :staging
      )

      reg = ca.output_with_children['resource']['acme_registration'].values.first

      expect(reg[:provider]).to eq('acme.staging')
    end

    it 'creates the provider for live' do
      ca = Terrafying::Components::LetsEncrypt.create('test-ca', 'test-bucket', renewing: true)

      prov = provider_matching(ca, :acme, :live)

      expect(prov).to include(
        'acme' => {
          alias: :live,
          server_url: 'https://acme-v02.api.letsencrypt.org/directory'
        }
      )
    end

    it 'sets the provider for live' do
      ca = Terrafying::Components::LetsEncrypt.create(
        'test-ca',
        'test-bucket',
        prefix: 'test-prefix',
        renewing: true,
        provider: :live
      )

      reg = ca.output_with_children['resource']['acme_registration'].values.first

      expect(reg[:provider]).to eq('acme.live')
    end
  end
end

RSpec.describe Terrafying::Components::LetsEncrypt, '#create_keypair' do
  context 'keypairs' do
    it 'sets the provider for staging' do
      ca = Terrafying::Components::LetsEncrypt.create(
        'test-ca',
        'test-bucket',
        prefix: 'test-prefix',
        renewing: true,
        provider: :staging
      )

      ca.create_keypair('test-cert', dns_names: ['test.example.com'])

      cert = ca.output_with_children['resource']['acme_certificate'].values.first

      expect(cert[:provider]).to eq('acme.staging')
    end

    it 'uses external nameservers when requested' do
      ca = Terrafying::Components::LetsEncrypt.create(
        'test-ca',
        'test-bucket',
        prefix: 'test-prefix',
        provider: :staging,
        renewing: true,
        use_external_dns: true
      )

      ca.create_keypair('test-cert', dns_names: ['test.example.com'])

      cert = ca.output_with_children['resource']['acme_certificate'].values.first

      expect(cert[:recursive_nameservers]).to include('1.1.1.1:53', '8.8.8.8:53', '8.8.4.4:53')
    end

    it 'uses system nameservers by default' do
      ca = Terrafying::Components::LetsEncrypt.create(
        'test-ca',
        'test-bucket',
        prefix: 'test-prefix',
        renewing: true,
        provider: :staging,
      )

      ca.create_keypair('test-cert', dns_names: ['test.example.com'])

      cert = ca.output_with_children['resource']['acme_certificate'].values.first

      expect(cert.key? :recursive_nameservers).to eq(false)
    end
  end
end

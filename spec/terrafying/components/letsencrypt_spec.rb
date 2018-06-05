# frozen_string_literal: true

require 'terrafying'
require 'terrafying/components/letsencrypt'

RSpec.describe Terrafying::Components::LetsEncrypt do
  it_behaves_like 'a CA'
end

RSpec.describe Terrafying::Components::LetsEncrypt, '#create' do
  context 'providers' do
    it 'sets the server_url based on the provider for staging' do
      expected_url = Terrafying::Components::LetsEncrypt::PROVIDERS[:staging][:server_url]
      ca = Terrafying::Components::LetsEncrypt.create(
        'test-ca',
        'test-bucket',
        prefix: 'test-prefix',
        provider: :staging
      )

      reg = ca.output_with_children['resource']['acme_registration'].values.first

      expect(reg[:server_url]).to eq(expected_url)
    end

    it 'sets the server_url based on the provider for live' do
      expected_url = Terrafying::Components::LetsEncrypt::PROVIDERS[:live][:server_url]
      ca = Terrafying::Components::LetsEncrypt.create(
        'test-ca',
        'test-bucket',
        prefix: 'test-prefix',
        provider: :live
      )

      reg = ca.output_with_children['resource']['acme_registration'].values.first

      expect(reg[:server_url]).to eq(expected_url)
    end
  end
end

RSpec.describe Terrafying::Components::LetsEncrypt, '#create_keypair' do
  context 'keypairs' do
    it 'sets the server_url based on the provider for staging' do
      expected_url = Terrafying::Components::LetsEncrypt::PROVIDERS[:staging][:server_url]
      ca = Terrafying::Components::LetsEncrypt.create(
        'test-ca',
        'test-bucket',
        prefix: 'test-prefix',
        provider: :staging
      )

      ca.create_keypair('test-cert', dns_names: ['test.example.com'])

      cert = ca.output_with_children['resource']['acme_certificate'].values.first

      expect(cert[:server_url]).to eq(expected_url)
    end
  end
end

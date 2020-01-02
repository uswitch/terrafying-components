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
      ca = Terrafying::Components::LetsEncrypt.create('test-ca', 'test-bucket')

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
        provider: :staging
      )

      reg = ca.output_with_children['resource']['acme_registration'].values.first

      expect(reg[:provider]).to eq('acme.staging')
    end

    it 'creates the provider for live' do
      ca = Terrafying::Components::LetsEncrypt.create('test-ca', 'test-bucket')

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
        provider: :staging,
      )

      ca.create_keypair('test-cert', dns_names: ['test.example.com'])

      cert = ca.output_with_children['resource']['acme_certificate'].values.first

      expect(cert.key? :recursive_nameservers).to eq(false)
    end
  end
end

RSpec.describe Terrafying::Components::LetsEncrypt, '#renewing' do
  context 'providers' do
    let(:id) {@id}

    def fake_hosted_zone(fqdn)
      @hosted_zones ||= {}
      @hosted_zones[fqdn] ||=
        begin
          warn "looking for a hosted zone with fqdn '#{fqdn}'"
          hosted_zones = @route53_client.stub_data(:list_hosted_zones_by_name, dns_name: fqdn, hosted_zones:[{id: 'IAMAZONESWEARS', name: fqdn + ".", config: {private_zone: false}}]).hosted_zones.select do |zone|
            zone.name == "#{fqdn}." && !zone.config.private_zone
          end
          if hosted_zones.count == 1
            hosted_zones.first
          elsif hosted_zones.count < 1
            raise "No hosted zone with fqdn '#{fqdn}' was found."
          elsif hosted_zones.count > 1
            raise "More than one hosted zone with name '#{fqdn}' was found: " + hosted_zones.join(', ')
          end
        end
      end

      def fake_find(fqdn)
        zone = fake_hosted_zone(fqdn)

        @id = zone.id
        @fqdn = fqdn

        self
      end

      it 'creates the certbot lambda' do
        @route53_client = Aws::Route53::Client.new(stub_responses: true)

        ca = Terrafying::Components::LetsEncrypt.create(
          'test-ca',
          'test-bucket',
          prefix: 'test-prefix',
          renewing: true
        )

        # in another world we could just set zone to nil because it get squish
        # ca.create_keypair('test-cert', dns_names: ['test.example.com'], zone: nil)

        zone = fake_find('test.example.com')
        ca.create_keypair('test-cert', dns_names: ['test.example.com'], zone: zone)

        certbot = ca.output_with_children['resource']['aws_lambda_function'].values.first

        expect(certbot[:function_name]).to eq('test-ca_lambda')
      end

  end
end

# frozen_string_literal: true

require 'terrafying/components/prometheus'

RSpec.describe Terrafying::Components::Prometheus, '#find_in' do
  let(:aws) { double('AWS') }
  let(:vpc) { stub_vpc('test-vpc', '10.10.0.0/16', aws: aws) }

  context 'finding prom for a vpc' do
    it 'should return a prom with a security group if one exists' do
      allow(aws).to receive(:security_group_in_vpc).and_return('sg-1234567890')

      prom = described_class.find_in(vpc: vpc)

      expect(prom.security_group).to be('sg-1234567890')
    end
  end
end

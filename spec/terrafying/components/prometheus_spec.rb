# frozen_string_literal: true

require 'terrafying/components/prometheus'

RSpec.describe Terrafying::Components::Prometheus, '#find_in' do
  let(:aws) { double('AWS') }
  let(:vpc) { stub_vpc('test-vpc', '10.10.0.0/16', aws: aws) }

  before do
    allow(aws).to receive(:instance_type_vcpu_count).and_return(2)
  end

  context 'finding prom for a vpc' do
    it 'should return a prom with a security group if one exists' do
      allow(aws).to receive(:security_group_in_vpc).and_return('sg-1234567890')

      prom = described_class.find_in(vpc: vpc)

      expect(prom.security_group).to be('sg-1234567890')
    end
  end

  context 'storing promtheus data' do
    it 'should add a volume to store the data with a default size of 20 GB' do
      prom = described_class.create_in(vpc: vpc)

      prom_vol = prom.output_with_children['resource']['aws_ebs_volume']['prometheus-0-0']
      puts prom_vol
      expect(prom_vol).to include(size: 20)
    end
  end
end

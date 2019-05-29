# frozen_string_literal: true

require 'terrafying'
require 'terrafying/components/instance'

RSpec.describe Terrafying::Components::Instance do
  it_behaves_like 'a usable resource'

  before do
    @vpc = stub_vpc('a-vpc', '10.0.0.0/16')
  end

  it 'should destroy then create when an ip is defined' do
    instance = Terrafying::Components::Instance.create_in(
      @vpc, 'an-instance', ip_address: '10.0.0.5'
    )

    expect(instance.output['resource']['aws_instance'].values.first[:lifecycle][:create_before_destroy]).to be false
  end

  it 'should pick a subnet for you if given a list' do
    instance = Terrafying::Components::Instance.create_in(
      @vpc, 'an-instance',
      subnets: @vpc.subnets[:private]
    )

    subnet_id = instance.output['resource']['aws_instance'].values.first[:subnet_id]

    expect(@vpc.subnets[:private].map(&:id)).to include(subnet_id)
  end

  context 'public and eips' do
    it 'should allocate a public ip when public is true' do
      instance = Terrafying::Components::Instance.create_in(
        @vpc, 'an-instance', public: true
      )

      inst = instance.output['resource']['aws_instance'].values.first

      expect(inst).to include(associate_public_ip_address: true)
      expect(instance.ip_address.to_s).to include('public_ip')
    end

    it 'should not allocate a public ip when public is false' do
        instance = Terrafying::Components::Instance.create_in(
          @vpc, 'an-instance', public: false
        )

        inst = instance.output['resource']['aws_instance'].values.first

        expect(inst).to include(associate_public_ip_address: false)
        expect(instance.ip_address.to_s).to match('private_ip')
    end

    it 'should allocate an eip ip when eip and public is true' do
      instance = Terrafying::Components::Instance.create_in(
        @vpc, 'an-instance', public: true, eip: true
      )

      inst = instance.output['resource']['aws_instance'].values.first
      eip  = instance.output['resource']['aws_eip'].values.first

      expect(inst).to include(associate_public_ip_address: false)
      expect(instance.ip_address.to_s).to match('aws_eip.a-vpc-an-instance.public_ip')
      expect(eip[:instance].to_s).to match('an-instance')
    end
  end
end

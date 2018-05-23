require 'terrafying'
require 'terrafying/components/staticset'

RSpec::Matchers.define_negated_matcher :not_have_key, :have_key

RSpec.describe Terrafying::Components::StaticSet do

  it_behaves_like "a usable resource"

  before do
    @vpc = stub_vpc("a-vpc", "10.0.0.0/16")
  end

  it "should create the correct number of instances" do
    instances = [{}, {}, {}]
    set = Terrafying::Components::StaticSet.create_in(
      @vpc, "foo", {
        instances: instances,
      }
    )

    output = set.output_with_children

    expect(output["resource"]["aws_instance"].count).to eq(instances.count)
  end

  it "should create volumes for each instance based on spec" do
    instances = [{}, {}]
    volumes = [
      {
        size: 100,
        device: "/dev/xvdl",
        mount: "/mnt/data",
      },
    ]

    set = Terrafying::Components::StaticSet.create_in(
      @vpc, "foo", { instances: instances, volumes: volumes },
    )

    output = set.output_with_children

    expect(output["resource"]["aws_ebs_volume"].count).to eq(instances.count * volumes.count)
    expect(output["resource"]["aws_volume_attachment"].count).to eq(instances.count * volumes.count)
  end

  it 'should have no kms_key_id key' do
    instances = [{}, {}]
    volumes = [
      {
        size: 100,
        device: '/dev/xvdl',
        mount:  '/mnt/data'
      }
    ]

    set = Terrafying::Components::StaticSet.create_in(
      @vpc, 'foo', { instances: instances, volumes: volumes }
    )

    volumes = set.output_with_children['resource']['aws_ebs_volume'].values

    expect(volumes).to include(
      not_have_key(:kms_key_id)
    )
  end

  it 'should create encrypted volumes for each instance based on spec' do
    instances = [{}, {}]
    volumes = [
      {
        size: 100,
        device: '/dev/xvdl',
        mount:  '/mnt/data',
        encrypted:  true,
        kms_key_id: 'my_key_id'
      }
    ]

    set = Terrafying::Components::StaticSet.create_in(
      @vpc, 'foo', { instances: instances, volumes: volumes }
    )

    volumes = set.output_with_children['resource']['aws_ebs_volume'].values

    expect(volumes).to include(
      a_hash_including({
        encrypted: true,
        kms_key_id: 'my_key_id'
      })
    )
  end

  it "should setup security group rules for instances to talk to each other on" do
    ports = [80, 443]
    set = Terrafying::Components::StaticSet.create_in(
      @vpc, "foo", { ports: ports }
    )

    rules = set.output_with_children["resource"]["aws_security_group_rule"].values

    port_rules = rules.select { |rule| ports.include?(rule[:from_port]) }

    expect(port_rules.count).to eq(ports.count)
    expect(port_rules.all? {|r| r[:self]}).to be true
  end

end

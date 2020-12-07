# frozen_string_literal: true

require 'terrafying'
require 'terrafying/components/staticset'
require 'terrafying/components/vpc'

RSpec.describe Terrafying::Components::VPC do
  before do
    @aws = double('AWS')

    @azs = ['eu-west-1a', 'eu-west-1b', 'eu-west-1c']

    allow(@aws).to receive(:availability_zones).and_return(@azs)
    allow(@aws).to receive(:hosted_zone).and_return(Aws::Route53::Types::HostedZone.new)
    allow(@aws).to receive(:ami).and_return('ami-foobar')

    allow_any_instance_of(Terrafying::Context).to receive(:aws).and_return(@aws)
  end

  context 'parent_zone' do
    it 'should default zone if not defined' do
      Terrafying::Components::VPC.create('foo', '10.0.0.0/16')

      expect(@aws).to have_received(:hosted_zone).with(Terrafying::Components::DEFAULT_ZONE)
    end

    it 'should use provided zone' do
      zone = Terrafying::Components::Zone.create('blah.usw.co')
      Terrafying::Components::VPC.create('foo', '10.0.0.0/16', parent_zone: zone)

      expect(@aws).to_not have_received(:hosted_zone)
    end
  end

  context 'subnets' do
    it 'should create public and private when internet accesible' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16', internet_access: true)

      expect(vpc.subnets[:private].count).to eq(@azs.count)
      expect(vpc.subnets[:public].count).to eq(@azs.count)
    end

    it 'should create only private when not internet accesible' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16', internet_access: false)

      expect(vpc.subnets[:private].count).to eq(@azs.count)
      expect(vpc.subnets.key?(:public)).to be false
    end

    it "should raise an error if there isn't enough room for the required subnets" do
      expect do
        Terrafying::Components::VPC.create('foo', '10.0.0.0/24')
      end.to raise_error(RuntimeError)
    end

    it 'should create nat gateway public networks when internet accessible' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16', internet_access: true)

      expect(vpc.subnets[:nat_gateway].count).to eq(@azs.count)
    end

    it 'should be able to be overriden by options' do
      vpc = Terrafying::Components::VPC.create(
        'foo', '10.0.0.0/16',
        subnets: {
          dmz: { public: true },
          secure: { public: false, internet: false }
        }
      )

      expect(vpc.subnets.key?(:public)).to be false
      expect(vpc.subnets.key?(:private)).to be false
      expect(vpc.subnets[:dmz].count).to eq(@azs.count)
      expect(vpc.subnets[:secure].count).to eq(@azs.count)
    end

    it 'should propergate tags down to the subnet resource' do
      vpc = Terrafying::Components::VPC.create(
        'foo', '10.0.0.0/16',
        internet_access: false,
        subnets: {
          offgrid: { internet: false, tags: { foo: 'bar' } }
        }
      )

      subnets = vpc.output_with_children['resource']['aws_subnet'].values

      expect(subnets.count).to eq(@azs.count)
      expect(subnets[0][:tags][:foo]).to eq('bar')
    end

    it 'should drop subnet' do
      vpc = Terrafying::Components::VPC.create(
        'foo', '10.75.0.0/16',
        internet_access: false,
        subnets: {
        }
      )
      cidrs = %w(10.75.0.0/24
        10.75.1.0/24
        10.75.2.0/24
        10.75.9.0/28
        10.75.9.16/28
        10.75.9.32/28
        10.75.16.0/20
        10.75.32.0/20
        10.75.48.0/20
      )

      cidrs.each {|c| vpc.drop_subnet!(c)}
      expect(vpc.extract_subnet!(20)).to eq("10.75.64.0/20")
      expect(vpc.extract_subnet!(28)).to eq("10.75.3.0/28")

    end

    it 'should put new subnet at start' do
      vpc = Terrafying::Components::VPC.create(
        'foo', '10.75.0.0/16',
        internet_access: false,
        subnets: {
        }
      )
      cidrs = %w(
        10.75.1.0/24
        10.75.2.0/24
      )

      cidrs.each {|c| vpc.drop_subnet!(c)}
      expect(vpc.extract_subnet!(24)).to eq("10.75.0.0/24")
    end

  it 'should not drop whole subnet' do
    vpc = Terrafying::Components::VPC.create(
      'foo', '10.75.0.0/16',
      internet_access: false,
      subnets: {
      }
    )
    cidrs = %w(
      10.75.1.0/24
      10.75.0.0/24
    )

    cidrs.each {|c| vpc.drop_subnet!(c)}
    expect(vpc.extract_subnet!(24)).to_not eq("10.75.0.0/24")
  end
end

  it 'should create a security group for SSH around the VPC' do
    cidr = '10.1.0.0/16'
    vpc = Terrafying::Components::VPC.create('foo', cidr)

    expect(vpc.output['resource']['aws_security_group'].count).to eq(1)

    ssh_security_group = vpc.output['resource']['aws_security_group'].values.first

    expect(ssh_security_group[:ingress].count).to eq(1)
    expect(ssh_security_group[:egress].count).to eq(1)

    rule = {
      from_port: 22,
      to_port: 22,
      protocol: 'tcp',
      cidr_blocks: [cidr],
      description: '',
      ipv6_cidr_blocks: [],
      prefix_list_ids: [],
      security_groups: [],
      self: nil
    }

    expect(ssh_security_group[:ingress][0]).to eq(rule)
    expect(ssh_security_group[:egress][0]).to eq(rule)
  end

  context 'peer_with_vpn' do
    it 'should blow up with more than two tunnels' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')

      expect do
        vpc.peer_with_vpn('1.2.3.4', ['10.1.0.0/16'], tunnels: [{}, {}, {}])
      end.to raise_error RuntimeError
    end

    it 'sets tunnel stuff properly' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')

      vpc.peer_with_vpn(
        '1.2.3.4', ['10.1.0.0/16'],
        tunnels: [
          {
            cidr: '1.2.3.4/30'
          },
          {
            cidr: '2.3.4.5/30',
            key: 'asdf'
          }
        ]
      )

      conn = vpc.output_with_children['resource']['aws_vpn_connection']['xinin-gavaf-1-2-3-4']

      expect(conn['tunnel1_inside_cidr']).to eq('1.2.3.4/30')
      expect(conn).to_not have_key('tunnel1_preshared_key')
      expect(conn['tunnel2_inside_cidr']).to eq('2.3.4.5/30')
      expect(conn['tunnel2_preshared_key']).to eq('asdf')
    end

    it 'create routes as expected' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')
      cidrs = ['10.1.0.0/16', '10.2.0.0/16']

      vpc.peer_with_vpn('1.2.3.4', cidrs)

      vpn_routes = vpc.output_with_children['resource']['aws_vpn_connection_route'].values
      subnet_routes = vpc.output_with_children['resource']['aws_route'].values

      vpn_routed_cidrs = vpn_routes.map { |r| r[:destination_cidr_block] }.sort.uniq
      subnet_routed_cidrs = subnet_routes.map { |r| r[:destination_cidr_block] }.sort.uniq

      expect(vpn_routed_cidrs).to include(*cidrs)
      expect(vpn_routed_cidrs.count).to eq(cidrs.count)
      expect(subnet_routed_cidrs).to include(*cidrs)
    end
  end

  context 'peer_with' do
    it 'should raise an error if the cidrs are overlapping' do
      vpc_a = Terrafying::Components::VPC.create('a', '10.0.0.0/16')
      vpc_b = Terrafying::Components::VPC.create('b', '10.0.0.0/20')

      expect do
        vpc_a.peer_with(vpc_b)
      end.to raise_error(RuntimeError)
    end

    it 'should create routes in both VPCs' do
      vpc_a = Terrafying::Components::VPC.create('a', '10.0.0.0/16')
      vpc_b = Terrafying::Components::VPC.create('b', '10.1.0.0/16')

      original_route_count = vpc_a.output_with_children['resource']['aws_route'].count

      vpc_a.peer_with(vpc_b)

      num_new_routes = vpc_a.output_with_children['resource']['aws_route'].count - original_route_count

      expect(num_new_routes).to eq(2 * vpc_a.subnets.count * vpc_a.azs.count * vpc_b.subnets.count * vpc_b.azs.count)
    end

    it 'should allow users to limit the subnets that are peered' do
      vpc_a = Terrafying::Components::VPC.create('a', '10.0.0.0/16')
      vpc_b = Terrafying::Components::VPC.create('b', '10.1.0.0/16')

      original_route_count = vpc_a.output_with_children['resource']['aws_route'].count

      our_subnets = vpc_a.subnets[:public]
      their_subnets = vpc_b.subnets[:public]

      vpc_a.peer_with(vpc_b, peering: [
                        { from: our_subnets, to: their_subnets },
                        { from: their_subnets, to: our_subnets }
                      ])

      num_new_routes = vpc_a.output_with_children['resource']['aws_route'].count - original_route_count

      expect(num_new_routes).to eq(2 * our_subnets.count * vpc_a.azs.count * their_subnets.count * vpc_b.azs.count)
    end

    it 'should allow us to completely peer vpcs' do
      vpc_a = Terrafying::Components::VPC.create('a', '10.0.0.0/16')
      vpc_b = Terrafying::Components::VPC.create('b', '10.1.0.0/16')

      original_route_count = vpc_a.output_with_children['resource']['aws_route'].count

      vpc_a.peer_with(vpc_b, complete: true)

      num_new_routes = vpc_a.output_with_children['resource']['aws_route'].count - original_route_count

      vpc_a_route_tables = vpc_a.subnets.values.flatten.map(&:route_table).sort.uniq
      vpc_b_route_tables = vpc_b.subnets.values.flatten.map(&:route_table).sort.uniq

      expect(num_new_routes).to eq(vpc_a_route_tables.count + vpc_b_route_tables.count)
    end
  end

  context 'extract_subnet!' do
    it 'should limit the size of a subnet to a /28' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')
      cidr = vpc.extract_subnet!(30)

      expect(cidr).to match(%r{[\.0-9]+/28})
    end

    it 'should raise when there are no subnets left' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')

      249.times do
        vpc.extract_subnet!(24)
      end

      expect do
        vpc.extract_subnet!(24)
      end.to raise_error(RuntimeError)
    end
  end

  context 'allocate_subnet!' do
    it 'should create subnets for each availability zone' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')
      subnets = vpc.allocate_subnets!('asdf')

      expect(subnets.count).to eq(vpc.azs.count)
    end

    it 'should attach an internet gateway if subnet is public' do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')
      subnets = vpc.allocate_subnets!('asdf', public: true)

      output = vpc.output_with_children

      route = output['resource']['aws_route'].values.select do |route|
        route[:route_table_id] = subnets[0].route_table
      end.first

      expect(route.key?(:gateway_id)).to be true
      expect(route.key?(:nat_gateway_id)).to be false
    end

    it "should attach a NAT gateway if it's connected to the internet but not public" do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')
      subnets = vpc.allocate_subnets!('asdf', public: false, internet: true)

      output = vpc.output_with_children

      route = output['resource']['aws_route'].values.select do |route|
        route[:route_table_id] == subnets[0].route_table
      end.first

      expect(route.key?(:gateway_id)).to be false
      expect(route.key?(:nat_gateway_id)).to be true
    end

    it "should not have any routes if it isn't public and no internet" do
      vpc = Terrafying::Components::VPC.create('foo', '10.0.0.0/16')
      subnets = vpc.allocate_subnets!('asdf', public: false, internet: false)

      output = vpc.output_with_children

      routes = output['resource']['aws_route'].values.select do |route|
        route[:route_table_id] == subnets[0].route_table
      end

      expect(routes.count).to eq(0)
    end
  end
end

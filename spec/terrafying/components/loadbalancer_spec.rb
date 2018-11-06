# frozen_string_literal: true

require 'digest'
require 'terrafying'
require 'terrafying/components/instance'
require 'terrafying/components/loadbalancer'
require 'terrafying/components/staticset'

RSpec.describe Terrafying::Components::LoadBalancer do

  it_behaves_like "a usable resource"

  before do
    @vpc = stub_vpc("a-vpc", "10.0.0.0/16")
  end

  it "should error on a mix of layer 4 and 7 ports" do
    expect {
      Terrafying::Components::LoadBalancer.create_in(
        @vpc, "foo", {
          ports: [
            { type: "tcp", number: 1234 },
            { type: "https", number: 443 },
          ],
        }
      )
    }.to raise_error RuntimeError
  end

  it "should create an ALB when only layer 7" do
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, "foo", {
        ports: [
          { type: "https", number: 443 },
        ],
      }
    )

    expect(lb.type).to eq("application")
  end

  it "should create an NLB when only layer 4" do
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, "foo", {
        ports: [
          { type: "tcp", number: 1234 },
        ],
      }
    )

    expect(lb.type).to eq("network")
  end

  it "if a port defines a ssl cert it should be added to the listener" do
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, "foo", {
        ports: [
          { type: "https", number: 443, ssl_certificate: "some-arn" },
        ],
      }
    )

    expect(lb.output["resource"]["aws_lb_listener"].count).to eq(1)

    listener = lb.output["resource"]["aws_lb_listener"].values.first

    expect(listener[:ssl_policy]).to_not be nil
    expect(listener[:certificate_arn]).to eq("some-arn")
  end

  it "should map usable to attached set when NLB" do
    set = Terrafying::Components::StaticSet.create_in(@vpc, "wibble")
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, "foo", {
        ports: [
          { type: "tcp", number: 1234 },
        ],
      }
    )

    lb.attach(set)
    lb.used_by_cidr("1.2.3.4/32")

    sg_rules = lb.output_with_children["resource"].fetch("aws_security_group_rule", {}).values

    expect(sg_rules.count).to eq(1)
    expect(sg_rules[0][:security_group_id]).to eq(set.ingress_security_group)
    expect(sg_rules[0][:cidr_blocks]).to eq(["1.2.3.4/32"])
  end

  it "should have a name with at most 32 characters" do
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, "abcdefghijklmnopqrstuvwxyz123456789", {}
    )
    expect(lb.name.length).to be <= 32
  end

  it 'should use hex identifiers when requested' do
    name = 'abcdefghijklmnopqrstuvwxyz123456789'
    expected_hex = Digest::SHA2.hexdigest("application-#{@vpc.name}-#{name}")[0..24]

    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, name, hex_ident: true
    )

    expect(lb.name).to eq(expected_hex)
  end

  context('application load balancer') do
    it('should use subnets to specify the list of subnets') do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [{ type: 'https', number: 443, ssl_certificate: 'some-arn' }]
      )

      lb_resource = lb.output_with_children['resource']['aws_lb'].values.first

      expect(lb_resource).to include(
        subnets: a_collection_including(
          '${aws_subnet.a-vpc-private-eu-west-1a.id}',
          '${aws_subnet.a-vpc-private-eu-west-1b.id}',
          '${aws_subnet.a-vpc-private-eu-west-1c.id}'
        )
      )
    end

    context('ssl certificates') do
      it('should use the first cert passed as a string') do
        lb = Terrafying::Components::LoadBalancer.create_in(
          @vpc, 'test-alb', ports: [{ type: 'https', number: 443, ssl_certificate: 'some-arn' }]
        )

        listener = lb.output_with_children['resource']['aws_lb_listener'].values.first

        expect(listener).to include(
          certificate_arn: 'some-arn'
        )
      end

      it('should use the first cert passed as an array') do
        lb = Terrafying::Components::LoadBalancer.create_in(
          @vpc, 'test-alb', ports: [{ type: 'https', number: 443, ssl_certificate: ['some-arn'] }]
        )

        listener = lb.output_with_children['resource']['aws_lb_listener'].values.first

        expect(listener).to include(
          certificate_arn: 'some-arn'
        )
      end

      it('should create certificate listener resources for additional certs') do
        lb = Terrafying::Components::LoadBalancer.create_in(
          @vpc, 'test-alb', ports: [{ type: 'https', number: 443, ssl_certificate: ['test-1', 'test-2', 'test-3'] }]
        )

        listener_certificates = lb.output_with_children['resource']['aws_lb_listener_certificate'].values

        expect(listener_certificates).to include(
          a_hash_including(certificate_arn: 'test-2'),
          a_hash_including(certificate_arn: 'test-3')
        )
      end
    end

  end

  context('network load balancer') do
    it('should use subnet_mapping to specify the list of subnets') do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [{ type: 'tcp', number: 22 }]
      )

      lb_resource = lb.output_with_children['resource']['aws_lb'].values.first

      expect(lb_resource).to include(
        subnet_mapping: a_collection_including(
          { subnet_id: '${aws_subnet.a-vpc-private-eu-west-1a.id}' },
          { subnet_id: '${aws_subnet.a-vpc-private-eu-west-1b.id}' },
          { subnet_id: '${aws_subnet.a-vpc-private-eu-west-1c.id}' }
        )
      )
    end
  end
end

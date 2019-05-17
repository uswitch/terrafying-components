# frozen_string_literal: true

require 'digest'
require 'terrafying'
require 'terrafying/components/instance'
require 'terrafying/components/loadbalancer'
require 'terrafying/components/staticset'

RSpec::Matchers.define_negated_matcher :not_include, :include

RSpec.describe Terrafying::Components::LoadBalancer do
  it_behaves_like 'a usable resource'

  before do
    @vpc = stub_vpc('a-vpc', '10.0.0.0/16')
  end

  it 'should error on a mix of layer 4 and 7 ports' do
    expect do
      Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'foo',
        ports: [
          { type: 'tcp', number: 1234 },
          { type: 'https', number: 443 }
        ]
      )
    end.to raise_error RuntimeError
  end

  it 'should create an ALB when only layer 7' do
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, 'foo',
      ports: [
        { type: 'https', number: 443 }
      ]
    )

    expect(lb.type).to eq('application')
  end

  it 'should create an NLB when only layer 4' do
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, 'foo',
      ports: [
        { type: 'tcp', number: 1234 }
      ]
    )

    expect(lb.type).to eq('network')
  end

  it 'if a port defines a ssl cert it should be added to the listener' do
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, 'foo',
      ports: [
        { type: 'https', number: 443, ssl_certificate: 'some-arn' }
      ]
    )

    expect(lb.output['resource']['aws_lb_listener'].count).to eq(1)

    listener = lb.output['resource']['aws_lb_listener'].values.first

    expect(listener[:ssl_policy]).to_not be nil
    expect(listener[:certificate_arn]).to eq('some-arn')
  end

  it 'should map usable to attached set when NLB' do
    set = Terrafying::Components::StaticSet.create_in(@vpc, 'wibble')
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, 'foo',
      ports: [
        { type: 'tcp', number: 1234 }
      ]
    )

    lb.attach(set)
    lb.used_by_cidr('1.2.3.4/32')

    sg_rules = lb.output_with_children['resource'].fetch('aws_security_group_rule', {}).values

    expect(sg_rules.count).to eq(1)
    expect(sg_rules[0][:security_group_id]).to eq(set.ingress_security_group)
    expect(sg_rules[0][:cidr_blocks]).to eq(['1.2.3.4/32'])
  end

  it 'should have a name with at most 32 characters' do
    lb = Terrafying::Components::LoadBalancer.create_in(
      @vpc, 'abcdefghijklmnopqrstuvwxyz123456789', {}
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

    it 'should apply security_groups' do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb',
        ports: [{ type: 'https', number: 443, ssl_certificate: 'some-arn' }],
        security_groups: ['sg-000']
      )

      lb_resource = lb.output_with_children['resource']['aws_lb'].values.first

      expect(lb_resource).to include(
        security_groups: a_collection_including(
          'sg-000'
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

    context 'idle timeouts' do
      it 'should set the idle timeout if specified' do
        lb = Terrafying::Components::LoadBalancer.create_in(
          @vpc, 'test-alb',
          ports: [{ type: 'https', number: 443, ssl_certificate: ['test-1', 'test-2', 'test-3'] }],
          idle_timeout: 1
        )

        lb_resource = lb.output_with_children['resource']['aws_lb'].values.first

        expect(lb_resource).to include(idle_timeout: 1)
      end

      it 'should not set the idle timeout if not specified' do
        lb = Terrafying::Components::LoadBalancer.create_in(
          @vpc, 'test-alb', ports: [{ type: 'https', number: 443, ssl_certificate: ['test-1', 'test-2', 'test-3'] }]
        )

        lb_resource = lb.output_with_children['resource']['aws_lb'].values.first

        expect(lb_resource.keys).to not_include(:idle_timeout)
      end
    end
  end

  context('adding targets to the loadbalancer') do
    it('should create a listener for each port') do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [
          { type: 'http',  number: 80 },
          { type: 'https', number: 443 }
        ]
      )

      listeners = lb.output_with_children['resource']['aws_lb_listener'].values

      expect(listeners).to include(
        a_hash_including(port: 80,  protocol: 'HTTP'),
        a_hash_including(port: 443, protocol: 'HTTPS')
      )
    end

    it('should create a target group a port with no action') do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [{ type: 'http', number: 80 }]
      )

      target_group = lb.output_with_children['resource']['aws_lb_target_group'].values.first

      expect(target_group).to include(port: 80, protocol: 'HTTP')
    end

    it('should create a listener with a forward action for a port by default') do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [{ type: 'http', number: 80 }]
      )

      listener = lb.output_with_children['resource']['aws_lb_listener'].values.first

      expect(listener).to include(
        port: 80,
        default_action: a_hash_including(
          type: 'forward',
          target_group_arn: '${aws_lb_target_group.application-a-vpc-test-alb-80.id}'
        )
      )
    end

    it('should create a listener with with an action for a port an action specified') do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [{
          type: 'http', number: 80, action: { type: 'redirect', redirect: {} }
        }]
      )

      listener = lb.output_with_children['resource']['aws_lb_listener'].values.first

      expect(listener).to include(
        port: 80,
        default_action: { type: 'redirect', redirect: {} }
      )
    end

    it('should only register a target for each port with no actions specified') do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [
          { type: 'http',  number: 80 },
          { type: 'https', number: 443 },
          { type: 'https', number: 4433, action: { type: 'redirect', redirect: {} } }
        ]
      )

      expect(lb.targets.size).to eq(2)
      expect(lb.targets).to contain_exactly(
        have_attributes(
          listener: '${aws_lb_listener.application-a-vpc-test-alb-80.id}',
          target_group: '${aws_lb_target_group.application-a-vpc-test-alb-80.id}'
        ),
        have_attributes(
          listener: '${aws_lb_listener.application-a-vpc-test-alb-443.id}',
          target_group: '${aws_lb_target_group.application-a-vpc-test-alb-443.id}'
        )
      )
    end
  end

  context('network load balancer') do
    it('should use subnets to specify the list of subnets') do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [{ type: 'tcp', number: 22 }]
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

    it 'should never set idle timeout even if specified' do
      lb = Terrafying::Components::LoadBalancer.create_in(
        @vpc, 'test-alb', ports: [{ type: 'tcp', number: 22 }], idle_timeout: 1
      )

      lb_resource = lb.output_with_children['resource']['aws_lb'].values.first

      expect(lb_resource.keys).to not_include(:idle_timeout)
    end
    it 'should warn if you try and set security groups' do
      expect_any_instance_of(Terrafying::Components::LoadBalancer).to receive(:warn).with(
        matching('You cannot set security groups on a network loadbalancer, set them on the instances behind it.')
      ).at_least(:once)

      described_class.create_in(
        @vpc, 'foo',
        ports: [
          { type: 'tcp', number: 1234 }
        ],
        security_groups: ['sg-000']
      )
    end
  end
end

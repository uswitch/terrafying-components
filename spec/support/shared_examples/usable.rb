RSpec::Matchers.define_negated_matcher :not_include, :include
RSpec::Matchers.define_negated_matcher :not_match, :match

shared_examples "a usable resource" do

  it { is_expected.to respond_to(:used_by) }
  it { is_expected.to respond_to(:used_by_cidr) }
  it { is_expected.to respond_to(:pingable_by) }
  it { is_expected.to respond_to(:pingable_by_cidr) }

  let :ports do
    [
      { type: "http", number: 80 },
      { type: "https", number: 443 },
    ]
  end

  before do
    @vpc = stub_vpc("a-vpc", "10.0.0.0/15")
    @main_resource = described_class.create_in(
      @vpc, "some-thing", {
        ports: ports,
      },
    )
  end

  it "should allow path MTU ICMP messages back on egress" do
    security_group_rules = @main_resource.output_with_children["resource"].fetch("aws_security_group_rule", {}).values

    expect(
      security_group_rules.any? { |rule|
        rule[:type] == "ingress" &&
          rule[:security_group_id] == @main_resource.egress_security_group &&
          rule[:protocol] == 1 &&
          rule[:from_port] == 3 &&
          rule[:to_port] == 4 &&
          rule[:cidr_blocks].include?("0.0.0.0/0")
      }
    ).to be true
  end

  it "should add ingress that maps the right cidrs" do
    cidrs = ["10.1.0.0/16", "10.2.0.0/16"]
    @main_resource.used_by_cidr(*cidrs)

    output = @main_resource.output_with_children

    expect(output["resource"]["aws_security_group_rule"].count).to be >= (ports.count * cidrs.count)

    expect(
      cidrs.product(ports).all? { |cidr, port|
        output["resource"]["aws_security_group_rule"].any? { |_, rule|
          rule[:type] == "ingress" && \
          rule.has_key?(:cidr_blocks) && \
          rule[:cidr_blocks][0] == cidr && \
          rule[:from_port] == port[:number] && \
          rule[:to_port] == port[:number] && \
          rule[:protocol] == "tcp"
        }
      }
    ).to be true

  end

  it "should add icmp that maps the right cidrs" do
    cidrs = ["10.1.0.0/16", "10.2.0.0/16"]
    @main_resource.pingable_by_cidr(*cidrs)

    output = @main_resource.output_with_children

    expect(output["resource"]["aws_security_group_rule"].count).to be >= 2

    expect(
      output["resource"]["aws_security_group_rule"].any? { |_, rule|
        rule[:type] == "ingress" && \
        rule.has_key?(:cidr_blocks) && \
        rule[:cidr_blocks] == cidrs && \
        rule[:from_port] == 8 && \
        rule[:to_port] == 0 && \
        rule[:protocol] == 1
      }
    ).to be true
  end

  it "should add ingress that maps the right resources" do
    other_resource = Terrafying::Components::Instance.create_in(@vpc, "some-thing-else")
    another_resource = Terrafying::Components::Instance.create_in(@vpc, "another-thing")

    resources = [other_resource, another_resource]

    @main_resource.used_by(*resources)

    output = @main_resource.output_with_children

    expect(output["resource"]["aws_security_group_rule"].count).to be >= (ports.count * resources.count)

    expect(
      resources.product(ports).all? { |resource, port|
        output["resource"]["aws_security_group_rule"].any? { |_, rule|
          rule[:type] == "ingress" && \
          rule.has_key?(:source_security_group_id) && \
          rule[:source_security_group_id] == resource.security_group && \
          rule[:from_port] == port[:number] && \
          rule[:to_port] == port[:number] && \
          rule[:protocol] == "tcp"
        }
      }
    ).to be true
  end

  it "should add icmp that maps the right resources" do
    other_resource = Terrafying::Components::Instance.create_in(@vpc, "some-thing-else")

    @main_resource.pingable_by(other_resource)

    output = @main_resource.output_with_children

    expect(output["resource"]["aws_security_group_rule"].count).to be >= 4

    expect(
      output["resource"]["aws_security_group_rule"].any? { |_, rule|
        rule[:type] == "ingress" && \
        rule.has_key?(:source_security_group_id) && \
        rule[:source_security_group_id] == other_resource.egress_security_group && \
        rule[:from_port] == 8 && \
        rule[:to_port] == 0 && \
        rule[:protocol] == 1
      }
    ).to be true

    expect(
      output["resource"]["aws_security_group_rule"].any? { |_, rule|
        rule[:type] == "ingress" && \
        rule.has_key?(:source_security_group_id) && \
        rule[:source_security_group_id] == other_resource.egress_security_group && \
        rule[:from_port] == 128 && \
        rule[:to_port] == 0 && \
        rule[:protocol] == 58
      }
    ).to be true

    expect(
      output["resource"]["aws_security_group_rule"].any? { |_, rule|
        rule[:type] == "egress" && \
        rule.has_key?(:source_security_group_id) && \
        rule[:source_security_group_id] == @main_resource.ingress_security_group && \
        rule[:from_port] == 8 && \
        rule[:to_port] == 0 && \
        rule[:protocol] == 1
      }
    ).to be true

    expect(
      output["resource"]["aws_security_group_rule"].any? { |_, rule|
        rule[:type] == "egress" && \
        rule.has_key?(:source_security_group_id) && \
        rule[:source_security_group_id] == @main_resource.ingress_security_group && \
        rule[:from_port] == 128 && \
        rule[:to_port] == 0 && \
        rule[:protocol] == 58
      }
    ).to be true
  end

  it 'should map from and to port when a range is passed in' do
    test_resource = described_class.create_in(
      @vpc, 'some-thing', {
        ports: [
          number: '1000-1200'
        ]
      }
    )

    test_resource.used_by_cidr('10.1.0.0/16')

    rules = test_resource.output_with_children['resource']['aws_security_group_rule'].values

    expect(rules).to include(
      a_hash_including(
        from_port: 1000,
        to_port:   1200
      )
    )
  end

  it 'should map port when a number is passed in' do
    test_resource = described_class.create_in(
      @vpc, 'some-thing', {
        ports: [
          number: 1200
        ]
      }
    )

    test_resource.used_by_cidr('10.1.0.0/16')

    rules = test_resource.output_with_children['resource']['aws_security_group_rule'].values

    expect(rules).to include(
      a_hash_including(
        from_port: 1200,
        to_port:   1200
      )
    )
  end

  it 'should filter out ports using the block when used by cidrs' do
    @main_resource.used_by_cidr('0.0.0.0/0') { |port| port[:upstream_port] != 443 }

    rules = @main_resource.output_with_children['resource']['aws_security_group_rule'].values

    expect(rules).to include(
      a_hash_including(
        from_port: 80, to_port: 80, cidr_blocks: ['0.0.0.0/0']
      )
    )
    expect(rules).to not_include(
      a_hash_including(
        from_port: 443, to_port: 443, cidr_blocks: ['0.0.0.0/0']
      )
    )
  end

  it 'should filter out ports using the block when used by other resources' do
    other_resource = Terrafying::Components::Instance.create_in(@vpc, 'some-thing-else')
    another_resource = Terrafying::Components::Instance.create_in(@vpc, 'another-thing')

    resources = [other_resource, another_resource]

    @main_resource.used_by(*resources) { |port| port[:upstream_port] != 443 }

    rules = @main_resource.output_with_children['resource']['aws_security_group_rule'].values

    expect(rules).to include(
      *resources.map { |res| a_hash_including(from_port: 80, to_port: 80, source_security_group_id: res.egress_security_group) }
    )
    expect(rules).to not_include(
      *resources.map { |res| a_hash_including(from_port: 443, to_port: 443, source_security_group_id: res.egress_security_group) }
    )
  end

  it 'should replace [./] with [-] in the cidr when naming the resource' do
    @main_resource.used_by_cidr('0.0.0.0/0') { |port| port[:upstream_port] != 443 }

    keys = @main_resource.output_with_children['resource']['aws_security_group_rule'].keys

    expect(keys).to all(not_match('0.0.0.0/0'))
    expect(keys).to include(a_string_matching('0-0-0-0-0'))
  end
end

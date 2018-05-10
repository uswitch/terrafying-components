require 'base64'
require 'terrafying'
require 'terrafying/components/service'

RSpec.describe Terrafying::Components::Service do

  it_behaves_like "a usable resource"

  before do
    @vpc = stub_vpc("a-vpc", "10.0.0.0/16")
  end

  it "should use user_data if passed in" do
    user_data = "something"
    service = Terrafying::Components::Service.create_in(
      @vpc, "foo", {
        user_data: user_data,
      }
    )

    output = service.output_with_children

    expect(output["resource"]["aws_instance"].values.first[:user_data]).to eq(user_data)
  end

  it "should generate user_data if not explicitly given" do
    unit = Terrafying::Components::Ignition.container_unit("app", "app:latest")
    service = Terrafying::Components::Service.create_in(
      @vpc, "foo", {
        units: [unit],
      }
    )

    output = service.output_with_children

    unit_contents = unit[:contents].dump[1..-2]

    expect(output["resource"]["aws_instance"].values.first[:user_data]).to include(unit_contents)
  end

  it 'should add fluentd config for auditd logs to user data if user data not explicitly given' do
    unit = Terrafying::Components::Ignition.container_unit('app', 'app:latest')
    service = Terrafying::Components::Service.create_in(
      @vpc, 'foo', {
        units: [unit]
      }
    )

    output = service.output_with_children

    expect(output['resource']['aws_instance'].values.first[:user_data]).to include('/etc/fluentd/conf.d')
  end

  it 'should add fluentd config for auditd logs to user data with the default audit role' do
    unit = Terrafying::Components::Ignition.container_unit('app', 'app:latest')
    service = Terrafying::Components::Service.create_in(
      @vpc, 'foo', {
        units: [unit]
      }
    )

    user_data = service.output_with_children['resource']['aws_instance'].values.first[:user_data]
    files = JSON.parse(user_data, { symbolize_names: true })[:storage][:files]

    conf_file = files.find { |f| f[:path] == '/etc/fluentd/conf.d/30_auditd_output_s3.conf' }
    conf_content = Base64.decode64(conf_file[:contents][:source].sub(/^[^,]*,/, ''))

    expect(conf_content).to include('role_arn arn:aws:iam::1234:role/auditd_logging')
  end

  it 'should add fluentd config for auditd logs to user data with the audit role specified' do
    unit = Terrafying::Components::Ignition.container_unit('app', 'app:latest')
    service = Terrafying::Components::Service.create_in(
      @vpc, 'foo', {
        units: [unit],
        audit_role: 'an-audit-role'
      }
    )

    user_data = service.output_with_children['resource']['aws_instance'].values.first[:user_data]
    files = JSON.parse(user_data, { symbolize_names: true })[:storage][:files]

    conf_file = files.find { |f| f[:path] == '/etc/fluentd/conf.d/30_auditd_output_s3.conf' }
    conf_content = Base64.decode64(conf_file[:contents][:source].sub(/^[^,]*,/, ''))

    expect(conf_content).to include('role_arn an-audit-role')
  end

  it 'should add iam policy to assume audit role specified' do
    unit = Terrafying::Components::Ignition.container_unit('app', 'app:latest')
    service = Terrafying::Components::Service.create_in(
      @vpc, 'foo', {
        units: [unit],
        audit_role: 'an-audit-role'
      }
    )

    policy_json = service.output_with_children['resource']['aws_iam_role_policy']['a-vpc-foo'][:policy]
    policy = JSON.parse(policy_json, symbolize_names: true)

    expect(policy[:Statement]).to include(
      a_hash_including(
        {
          Effect: 'Allow',
          Action: ['sts:AssumeRole'],
          Resource: ['an-audit-role']
        }
      )
    )
  end

  context('iam policy') do
    it 'should add specified iam policy statements to the instance' do
      specified_policy = {
        Effect: 'Allow',
        Action: ['s3:*'],
        Resource: ['all-the-buckets']
      }

      unit = Terrafying::Components::Ignition.container_unit('app', 'app:latest')
      service = Terrafying::Components::Service.create_in(
        @vpc, 'foo', {
          units: [unit],
          iam_policy_statements: [specified_policy]
        }
      )

      policy_json = service.output_with_children['resource']['aws_iam_role_policy']['a-vpc-foo'][:policy]
      policy = JSON.parse(policy_json, symbolize_names: true)

      expect(policy[:Statement]).to include(a_hash_including(specified_policy))
    end
  end


  it "should depend on any key pairs passed in" do
    ca = Terrafying::Components::SelfSignedCA.create("ca", "some-bucket")
    keypair = ca.create_keypair("keys")

    service = Terrafying::Components::Service.create_in(
      @vpc, "foo", {
        keypairs: [keypair],
      }
    )

    output = service.output_with_children

    expect(output["resource"]["aws_instance"].values.first[:depends_on]).to include(*keypair[:resources])
  end

  it "should create a dynamic set when instances is a hash" do
    service = Terrafying::Components::Service.create_in(
      @vpc, "foo", {
        instances: { min: 1, max: 1, desired: 1, tags: {} },
      }
    )

    output = service.output_with_children

    expect(output["resource"]["aws_cloudformation_stack"].count).to eq(1)
  end

  it "should pass down instance tags to asg" do
    service = Terrafying::Components::Service.create_in(
      @vpc, "foo", {
        instances: { min: 1, max: 1, desired: 1, tags: { foo: "bar" } },
      }
    )

    output = service.output_with_children["resource"]["aws_cloudformation_stack"].values.first

    expect(output).not_to be_nil

    asg_config = JSON.parse(output[:template_body])
    tags = asg_config["Resources"]["AutoScalingGroup"]["Properties"]["Tags"]

    foo_tag = tags.select { |tag| tag["Key"] == "foo" }.first

    expect(foo_tag["Value"]).to eq("bar")
  end

  context "asg health check" do
    it "it should default to EC2 checks" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [443],
        }
      )

      output = service.output_with_children

      expect(output["resource"]["aws_cloudformation_stack"].count).to eq(1)
      template_body = JSON.parse(output["resource"]["aws_cloudformation_stack"].values.first[:template_body])
      expect(template_body["Resources"]["AutoScalingGroup"]["Properties"]["HealthCheckType"]).to eq("EC2")
    end

    it "should set an elb health check on dynamic set if it has a load balancer and some health checks" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [{ number: 443, health_check: { path: "/foo", protocol: "HTTPS" }}],
        }
      )

      output = service.output_with_children

      expect(output["resource"]["aws_cloudformation_stack"].count).to eq(1)
      template_body = JSON.parse(output["resource"]["aws_cloudformation_stack"].values.first[:template_body])
      expect(template_body["Resources"]["AutoScalingGroup"]["Properties"]["HealthCheckType"]).to eq("ELB")
    end
  end

  it "should create a static set when instances is an array" do
    service = Terrafying::Components::Service.create_in(
      @vpc, "foo", {
        instances: [{}, {}],
      }
    )

    output = service.output_with_children

    expect(output["resource"]["aws_instance"].count).to eq(2)
  end

  it "should error when instances is something unknown" do
    expect {
      Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: 3,
        }
      )
    }.to raise_error RuntimeError
  end

  context "private link" do

    it "shouldn't work if there isn't a load balancer" do
      service = Terrafying::Components::Service.create_in(@vpc, "foo")

      expect {
        service.with_endpoint_service
      }.to raise_error(RuntimeError)
    end

    it "shouldn't work if it's an ALB" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          ports: [{ number: 443, type: "https" }],
        }
      )

      expect {
        service.with_endpoint_service
      }.to raise_error(RuntimeError)
    end

    it "should generate a service resource" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [443],
        }
      )

      service.with_endpoint_service

      output = service.output_with_children

      expect(output["resource"]["aws_vpc_endpoint_service"].count).to eq(1)
    end

  end

  context "load balancer" do

    it "should create the security groups for ALB to talk to ASG" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [{ type: "https", number: 443 }],
        }
      )

      output = service.output_with_children

      instance_to_lb_rules = output["resource"]["aws_security_group_rule"].values.select { |r|
        r[:security_group_id] == service.instance_set.security_group && \
        r[:source_security_group_id] == service.load_balancer.security_group
      }
      lb_to_instance_rules = output["resource"]["aws_security_group_rule"].values.select { |r|
        r[:security_group_id] == service.load_balancer.security_group && \
        r[:source_security_group_id] == service.instance_set.security_group
      }

      expect(instance_to_lb_rules.count).to eq(service.ports.count)
      expect(instance_to_lb_rules[0][:type]).to eq("ingress")
      expect(instance_to_lb_rules[0][:protocol]).to eq("tcp")
      expect(instance_to_lb_rules[0][:from_port]).to eq(443)
      expect(instance_to_lb_rules[0][:to_port]).to eq(443)

      expect(lb_to_instance_rules.count).to eq(service.ports.count)
      expect(lb_to_instance_rules[0][:type]).to eq("egress")
      expect(lb_to_instance_rules[0][:protocol]).to eq("tcp")
      expect(lb_to_instance_rules[0][:from_port]).to eq(443)
      expect(lb_to_instance_rules[0][:to_port]).to eq(443)
    end

    it "should create the security groups for ALB to talk to instances" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          ports: [{ type: "https", number: 443 }],
          loadbalancer: true,
        }
      )

      output = service.output_with_children

      instance_rules = output["resource"]["aws_security_group_rule"].values.select { |r| r[:security_group_id] == service.instance_set.security_group }
      instance_to_lb_rules = instance_rules.select { |r| r[:source_security_group_id] == service.load_balancer.security_group }

      expect(instance_to_lb_rules.count).to eq(service.ports.count)
      expect(instance_to_lb_rules[0][:type]).to eq("ingress")
      expect(instance_to_lb_rules[0][:protocol]).to eq("tcp")
      expect(instance_to_lb_rules[0][:from_port]).to eq(443)
      expect(instance_to_lb_rules[0][:to_port]).to eq(443)
    end

    it "should create no security groups, beyond path mtu, for NLBs" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [443],
        }
      )

      output = service.output_with_children

      instance_rules = output["resource"].fetch("aws_security_group_rule", {}).values.select { |r|
        r[:security_group_id] == service.instance_set.security_group
      }
      instance_to_lb_rules = instance_rules.select { |r| r[:source_security_group_id] == service.load_balancer.security_group }

      expect(instance_to_lb_rules.count).to eq(1)
    end

    it "shouldn't use ALB as egress security group when binding services" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [{ type: "https", number: 443 }],
        }
      )

      service_b = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [{ type: "https", number: 443 }],
        }
      )

      service.used_by(service_b)

      output = service.output_with_children

      binding_rules = output["resource"].fetch("aws_security_group_rule", {}).values.select { |r|
        r[:security_group_id] == service_b.load_balancer.ingress_security_group && \
        r[:source_security_group_id] == service.instance_set.egress_security_group
      }

      expect(binding_rules.count).to eq(service.ports.count)
    end

  end

end

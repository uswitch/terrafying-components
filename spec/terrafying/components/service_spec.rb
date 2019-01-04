require 'base64'
require 'terrafying'
require 'terrafying/components/service'

RSpec::Matchers.define_negated_matcher :not_include, :include

RSpec.describe Terrafying::Components::Service do

  it_behaves_like "a usable resource"

  before do
    @vpc = stub_vpc("a-vpc", "10.0.0.0/16")
  end

  context "cfn signal" do

    it "should add an iam permission to cfn signal" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1 },
          rolling_update: :signal,
        }
      )

      output = service.output_with_children

      _, service_iam_policy = output["resource"]["aws_iam_role_policy"].select { |k, _| k == "a-vpc-foo" }.first
      service_iam_statements = JSON.parse(service_iam_policy[:policy], symbolize_names: true)[:Statement]

      expect(service_iam_statements).to include(
                                          a_hash_including(
                                            {
                                              Effect: 'Allow',
                                              Action: ['cloudformation:SignalResource'],
                                              Resource: [service.instance_set.stack_arn.to_s],
                                            }
                                          )
                                        )
    end

    it "should not add an iam permission by default" do
      service = Terrafying::Components::Service.create_in(
        @vpc, "foo", {
          instances: { min: 1, max: 1, desired: 1 },
        }
      )

      output = service.output_with_children

      _, service_iam_policy = output["resource"]["aws_iam_role_policy"].select { |k, _| k == "a-vpc-foo" }.first
      service_iam_statements = JSON.parse(service_iam_policy[:policy], symbolize_names: true)[:Statement]

      expect(service_iam_statements).to_not include(
                                              a_hash_including(
                                                {
                                                  Effect: 'Allow',
                                                  Action: ['cloudformation:SignalResource'],
                                                  Resource: [service.instance_set.stack_arn.to_s],
                                                }
                                              )
                                            )
    end

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

    it "should create no security groups for NLBs" do
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

      expect(instance_to_lb_rules.count).to eq(0)
    end

    it "shouldn't use ALB as egress security group when binding services" do
      service_a = Terrafying::Components::Service.create_in(
        @vpc, "foo-a", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [{ type: "https", number: 443 }],
        }
      )

      service_b = Terrafying::Components::Service.create_in(
        @vpc, "foo-b", {
          instances: { min: 1, max: 1, desired: 1, tags: {} },
          ports: [{ type: "https", number: 443 }],
        }
      )

      service_a.used_by(service_b)

      rules = service_a.output_with_children['resource']['aws_security_group_rule'].values

      expect(rules).to include(
        a_hash_including(
          from_port: 443,
          type: 'ingress',
          security_group_id: service_a.load_balancer.ingress_security_group,
          source_security_group_id: service_b.instance_set.egress_security_group
        )
      )

      expect(rules).to not_include(
        a_hash_including(
          from_port: 443,
          type: 'ingress',
          security_group_id: service_a.load_balancer.ingress_security_group,
          source_security_group_id: service_b.load_balancer.egress_security_group
        )
      )
    end

    context('instance profiles') do
      it 'should use the specified instance profile' do
        service = Terrafying::Components::Service.create_in(@vpc, 'foo', instance_profile: 'magical-instance-profile')

        ec2_instance = service.output_with_children['resource']['aws_instance'].values.first
        expect(ec2_instance).to include(
          iam_instance_profile: 'magical-instance-profile'
        )
      end

      it 'should use the specified instance profile for ASGs' do
        service = Terrafying::Components::Service.create_in(@vpc, 'foo', instances: { min: 1, max: 1, desired: 1, tags: {} }, instance_profile: 'magical-instance-profile')

        launch_config = service.output_with_children['resource']['aws_launch_configuration'].values.first
        expect(launch_config).to include(
          iam_instance_profile: 'magical-instance-profile'
        )
      end
    end

    context('metrics ports') do
      it 'should allow the prom security group to connect to the metric ports' do
        port = 1234
        prom_sec_group = 'sg-1234567890'
        allow(@vpc.aws).to receive(:security_group_in_vpc).and_return(prom_sec_group)

        service = Terrafying::Components::Service.create_in(@vpc, 'foo', metrics_ports: [port])

        rules = service.output_with_children['resource']['aws_security_group_rule'].values

        expect(rules).to include(
          a_hash_including(
            security_group_id: service.egress_security_group,
            type: 'ingress',
            from_port: port,
            to_port: port,
            protocol: 'tcp',
            source_security_group_id: prom_sec_group
          )
        )
      end
    end
  end
end

require 'base64'
require 'terrafying'
require 'terrafying/components/ignition'
require 'terrafying/components/selfsignedca'
require 'terrafying/util'


RSpec.describe Terrafying::Components::Ignition, '#container_unit' do
  before do
    @aws = double('AWS')
    allow(@aws).to receive(:region).and_return('eu-west-1')
    allow_any_instance_of(Terrafying::Context).to receive(:aws).and_return(@aws)
  end


  it 'creates a unit file' do
    container_unit = Terrafying::Components::Ignition.container_unit("app", "app:latest")

    expect(container_unit[:name]).to eq("app.service")
    expect(container_unit[:contents]).to match(/app:latest/)
  end

  it 'sets up host networking' do
    container_unit = Terrafying::Components::Ignition.container_unit("app", "app:latest", { host_networking: true })

    expect(container_unit[:contents]).to match(/--net=host/)
  end

  it 'sets up privileged mode' do
    container_unit = Terrafying::Components::Ignition.container_unit("app", "app:latest", { privileged: true })

    expect(container_unit[:contents]).to match(/--privileged/)
  end

  it 'adds environment variables' do
    container_unit = Terrafying::Components::Ignition.container_unit(
      "app", "app:latest", {
        environment_variables: [ "FOO=bar" ],
      }
    )

    expect(container_unit[:contents]).to match(/-e FOO=bar/)
  end

  it 'adds volumes' do
    container_unit = Terrafying::Components::Ignition.container_unit(
      "app", "app:latest", {
        volumes: [ "/tmp:/tmp:ro" ],
      }
    )

    expect(container_unit[:contents]).to match(/-v \/tmp:\/tmp:ro/)
  end

  it 'adds arguments' do
    container_unit = Terrafying::Components::Ignition.container_unit(
      "app", "app:latest", {
        arguments: [ "/bin/bash", "-c 'echo hi'" ],
      }
    )

    expect(container_unit[:contents]).to match(/\/bin\/bash\s+\\\n-c 'echo hi'/)
  end

  it 'adds required units' do
    container_unit = Terrafying::Components::Ignition.container_unit(
      "app", "app:latest", {
        require_units: [ "disk.mount", "database.service" ],
      }
    )

    expect(container_unit[:contents]).to match(/Requires=disk.mount database.service/)
    expect(container_unit[:contents]).to match(/After=disk.mount database.service/)
  end

end

RSpec.describe Terrafying::Components::Ignition, '#generate' do
  before do
    @aws = double('AWS')
    allow(@aws).to receive(:region).and_return('eu-west-1')
    allow_any_instance_of(Terrafying::Context).to receive(:aws).and_return(@aws)
  end

  context 'with volumes' do
    it 'creates userdata with correct mountpoints' do
      options = {
        volumes: [{ name: 'test_vol', mount: '/var/test', device: '/dev/test' }]
      }

      user_data_ign = Terrafying::Components::Ignition.generate(options)

      units = JSON.parse(user_data_ign, { symbolize_names: true })[:systemd][:units]

      expect(units.any? do |unit|
        unit == {
          name: 'var-test.mount',
          enabled: true,
          contents: "[Install]\nWantedBy=local-fs.target\n\n[Unit]\nBefore=docker.service\n\n[Mount]\nWhat=/dev/test\nWhere=/var/test\nType=ext4\n"
        }
      end).to be true
    end
  end

  it "adds in unit files" do
    user_data = Terrafying::Components::Ignition.generate(
      {
        units: [{ name: "foo.service", contents: "LOOL" }],
      }
    )

    units = JSON.parse(user_data, { symbolize_names: true })[:systemd][:units]

    expect(units.any? do |unit|
             unit == {
               name: 'foo.service',
               enabled: true,
               contents: "LOOL"
             }
           end).to be true
  end

  it "adds in drops not just contents into units" do
    user_data = Terrafying::Components::Ignition.generate(
      {
        units: [{ name: "docker.service", dropins: [{contents: "LOL", name: "10-lol.conf"}] }],
      }
    )

    units = JSON.parse(user_data, { symbolize_names: true })[:systemd][:units]

    expect(units.any? do |unit|
             unit == {
               name: 'docker.service',
               enabled: true,
               dropins: [{contents: "LOL", name: "10-lol.conf"}],
             }
           end).to be true
  end

  context 'files' do

    it 'adds in files with string contents' do
      user_data = Terrafying::Components::Ignition.generate(
        {
          files: [{ path: "/etc/app/app.conf", mode: "0999", contents: "LOOL" }],
        }
      )

      files = JSON.parse(user_data, { symbolize_names: true })[:storage][:files]

      expect(files.any? do |file|
               file == {
                 filesystem: "root",
                 mode: "0999",
                 path: "/etc/app/app.conf",
                 user: { id: 0 },
                 group: { id: 0 },
                 contents: { source: "data:;base64,TE9PTA==" },
               }
             end).to be true
    end

    it 'adds in files with sources' do
      user_data = Terrafying::Components::Ignition.generate(
        {
          files: [{ path: '/etc/app/app.conf', mode: '0999', contents: { source: 's3://bucket/file' } }],
        }
      )

      files = JSON.parse(user_data, { symbolize_names: true })[:storage][:files]

      expect(files).to include(
       {
         filesystem: 'root',
         mode: '0999',
         path: '/etc/app/app.conf',
         user: { id: 0 },
         group: { id: 0 },
         contents: { source: 's3://bucket/file' }
       }
     )
    end
  end
  it 'passes through the ssh_group' do
    user_data = Terrafying::Components::Ignition.generate(
      {
        ssh_group: 'smurfs'
      }
    )

    files = JSON.parse(user_data, { symbolize_names: true })[:storage][:files]

    conf_file = files.find { |f| f[:path] == '/etc/usersync.env' }
    conf_content = Base64.decode64(conf_file[:contents][:source].sub(/^[^,]*,/, ''))

    expect(conf_content).to match(/USERSYNC_SSH_GROUP="smurfs"/)
  end

  context "keypairs" do

    it 'setups keypairs/cas properly' do
      ca = Terrafying::Components::SelfSignedCA.create('great-ca', 'some-bucket')
      keypair = ca.create_keypair('foo')

      user_data = Terrafying::Components::Ignition.generate(
        {
          keypairs: [keypair]
        }
      )

      files = JSON.parse(user_data, { symbolize_names: true })[:storage][:files]

      ca_crt = files.find { |f| f[:path] == '/etc/ssl/great-ca/ca.cert' }
      pair_key = files.find { |f| f[:path] == '/etc/ssl/great-ca/foo/key' }
      pair_crt = files.find { |f| f[:path] == '/etc/ssl/great-ca/foo/cert' }

      expect(ca_crt[:contents][:source]).to eq('s3://some-bucket/great-ca/ca.cert')
      expect(pair_key[:contents][:source]).to eq('s3://some-bucket/great-ca/foo/key')
      expect(pair_crt[:contents][:source]).to eq('s3://some-bucket/great-ca/foo/cert')

    end

    it 'handles ca keypairs' do
      ca = Terrafying::Components::SelfSignedCA.create('great-ca', 'some-bucket')

      user_data = Terrafying::Components::Ignition.generate(
        {
          keypairs: [ca.keypair]
        }
      )

      files = JSON.parse(user_data, { symbolize_names: true })[:storage][:files]

      key = files.find { |f| f[:path] == '/etc/ssl/great-ca/ca.key' }
      crt = files.find { |f| f[:path] == '/etc/ssl/great-ca/ca.cert' }

      expect(key[:contents][:source]).to eq('s3://some-bucket/great-ca/ca.key')
      expect(crt[:contents][:source]).to eq('s3://some-bucket/great-ca/ca.cert')
    end

    it 'shouldnt duplicate the ca.cert' do
      ca = Terrafying::Components::SelfSignedCA.create('great-ca', 'some-bucket')

      user_data = Terrafying::Components::Ignition.generate(
        {
          keypairs: [ca.keypair]
        }
      )

      files = JSON.parse(user_data, { symbolize_names: true })[:storage][:files]

      expect(files.select { |file| file[:path].end_with? 'ca.cert' }.count).to eq(1)
    end
  end

  context "validation" do

    it "should ensure every file has a path" do
      expect {
        Terrafying::Components::Ignition.generate(
          {
            files: [ { } ],
          }
        )
      }.to raise_error(RuntimeError)
    end

    it "should pass a valid file" do
      expect {
        Terrafying::Components::Ignition.generate(
          {
            files: [ { path: "/", mode: "0644", contents: "" } ],
          }
        )
      }.to_not raise_error
    end

    it "should ensure every unit has a name" do
      expect {
        Terrafying::Components::Ignition.generate(
          {
            units: [ { } ],
          }
        )
      }.to raise_error(RuntimeError)
    end

    it "should ensure every unit has contents and/or dropins" do
      expect {
        Terrafying::Components::Ignition.generate(
          {
            units: [ { name: "foo" } ],
          }
        )
      }.to raise_error(RuntimeError)
      expect {
        Terrafying::Components::Ignition.generate(
          {
            units: [ { name: "foo", contents: "bar" } ],
          }
        )
      }.to_not raise_error
      expect {
        Terrafying::Components::Ignition.generate(
          {
            units: [ { name: "foo", dropins: [] } ],
          }
        )
      }.to_not raise_error
      expect {
        Terrafying::Components::Ignition.generate(
          {
            units: [ { name: "foo", contents: "bar", dropins: [] } ],
          }
        )
      }.to_not raise_error
    end

    it "should pass a valid unit" do
      expect {
        Terrafying::Components::Ignition.generate(
          {
            units: [ { name: "foo.service", contents: "blarf" } ],
          }
        )
      }.to_not raise_error
    end

  end
end

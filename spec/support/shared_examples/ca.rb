# frozen_string_literal: true

shared_examples 'a CA' do
  it { is_expected.to respond_to(:create) }
  it { is_expected.to respond_to(:create_keypair) }
  it { is_expected.to respond_to(:create_keypair_in) }
  it { is_expected.to respond_to(:reference_keypair) }
  it { is_expected.to respond_to(:<=>) }

  let :ca_name do
    'some-ca'
  end

  let :bucket_name do
    'a-bucket'
  end

  before do
    @ca = described_class.create(ca_name, bucket_name)
  end

  describe '.create' do
    it 'should put the cert in s3' do
      expect(@ca.output['resource']['aws_s3_bucket_object'].values).to(
        include(a_hash_including(bucket: bucket_name, key: @ca.object_key(@ca.name, :cert)))
      )
    end

    it 'should populate name' do
      expect(@ca.name).to eq(ca_name)
    end

    describe 'certificate acl' do
      it 'should be private by default' do
        ca_cert = @ca.output['resource']['aws_s3_bucket_object'].values.select do |object|
          object[:key].end_with?('ca.cert')
        end

        expect(ca_cert.count).to eq(1)
        expect(ca_cert[0][:acl]).to eq('private')
      end

      it 'should be public when wanted' do
        ca = described_class.create(ca_name, bucket_name, public_certificate: true)

        ca_cert = ca.output['resource']['aws_s3_bucket_object'].values.select do |object|
          object[:key].end_with?('ca.cert')
        end

        expect(ca_cert.count).to eq(1)
        expect(ca_cert[0][:acl]).to eq('public-read')
      end
    end

    it 'should have keys/certs that start with "/" when it has no prefix' do
      ca = described_class.create(ca_name, bucket_name)
      s3_objects = ca.output['resource']['aws_s3_bucket_object'].values

      expect(s3_objects).to all(include(key: start_with('/')))
    end

    it 'should have keys/certs that start with "/" when it has a prefix' do
      ca = described_class.create(ca_name, bucket_name, prefix: 'a_prefix')
      s3_objects = ca.output['resource']['aws_s3_bucket_object'].values

      expect(s3_objects).to all(include(key: start_with('/')))
    end
  end

  describe '.create_keypair_in' do
    it 'should put stuff in the right context' do
      ctx = Terrafying::Context.new

      keypair = @ca.create_keypair_in(ctx, 'foo')

      resource_names = keypair[:resources].map { |r| r.split('.')[1] }

      expect(ctx.output['resource']['aws_s3_bucket_object'].keys).to include(*resource_names)
      expect(@ca.output['resource']['aws_s3_bucket_object'].keys).to_not include(*resource_names)
    end
  end

  describe '.create_keypair' do
    it 'should reference the right bucket objects in output' do
      keypair = @ca.create_keypair('foo')

      expect(@ca.output['resource']['aws_s3_bucket_object'].values).to(
        include(
          a_hash_including(bucket: bucket_name, key: match(@ca.object_key(keypair[:name], :key, '.*'))),
          a_hash_including(bucket: bucket_name, key: match(@ca.object_key(keypair[:name], :cert, '.*'))),
        )
      )
    end

    it 'should create a pointer to the latest version of the key and cert' do
      keypair = @ca.create_keypair('foo')


      # we want to check that it references the version in the path of the real key/cert
      key_re = Regexp.new(@ca.object_key(keypair[:name], :key, '([^l].*)'))
      cert_re = Regexp.new(@ca.object_key(keypair[:name], :cert, '([^l].*)'))

      objects = @ca.output['resource']['aws_s3_bucket_object'].values

      key_version = objects.map { |obj| key_re.match(obj[:key]) }.compact[0][1]
      cert_version = objects.map { |obj| cert_re.match(obj[:key]) }.compact[0][1]

      expect(objects).to(
        include(
          a_hash_including(bucket: bucket_name, key: match(@ca.object_key(keypair[:name], :key, 'latest')), content: key_version),
          a_hash_including(bucket: bucket_name, key: match(@ca.object_key(keypair[:name], :cert, 'latest')), content: cert_version)
        )
      )
    end

    it 'should reference the correct resources in the IAM statement' do
      keypair = @ca.create_keypair('foo')

      arns = keypair[:iam_statement][:Resource]

      expect(arns).to include(
        @ca.object_arn(@ca.name, :cert),
        @ca.object_arn(keypair[:name], :cert),
        @ca.object_arn(keypair[:name], :key)
      )
    end

    it 'arn function outputs a correct arn' do
      expect(@ca.object_arn('asd', :cert)).to match("arn:aws:s3:::#{bucket_name}/#{@ca.name}/asd/*/cert")
    end

    it 'arn function outputs a correct arn for a CA' do
      expect(@ca.object_arn(@ca.name, :cert)).to match("arn:aws:s3:::#{bucket_name}/#{@ca.name}/ca.cert")
    end

    it 'should reference resources that exist' do
      keypair = @ca.create_keypair('foo')

      expect(keypair[:resources].all? do |r|
        type, name = r.split('.')
        @ca.output['resource'][type].key? name
      end).to be true
    end

    it 'should have keys/certs that start with "/" when it has no prefix' do
      ca = described_class.create(ca_name, bucket_name)
      ca.create_keypair('bar')

      s3_objects = ca.output['resource']['aws_s3_bucket_object'].values

      expect(s3_objects).to all(include(key: start_with('/')))
    end

    it 'should have keys/certs that start with "/" when it has a prefix' do
      ca = described_class.create(ca_name, bucket_name, prefix: 'a_prefix')
      ca.create_keypair('bar')

      s3_objects = ca.output['resource']['aws_s3_bucket_object'].values

      expect(s3_objects).to all(include(key: start_with('/')))
    end
  end

  it 'should be sortable' do
    a = described_class.create('a', 'a-bucket')
    b = described_class.create('b', 'b-bucket')
    c = described_class.create('c', 'c-bucket')

    unsorted = [b, c, a]
    expect(unsorted.sort).to eq([a, b, c])
  end
end

require 'digest'
require 'ostruct'
require 'terrafying/components/security/trail'

RSpec.describe Terrafying::Components::Security::Trail, '#create' do
  let(:store) { OpenStruct.new(name: 'test', arn: 'test-arn', key_arn: 'test-key-arn') }
  let(:name) { 'test-trail'}
  let(:bucket_name) { 'test-bucket-a' }
  let(:bucket_sha) { Digest::SHA256.hexdigest("#{name}-#{bucket_name}")[0..16] }
  let(:bucket_res) { "ct-ignore-#{bucket_sha}"}
  let(:bucket_arn) { "${data.aws_s3_bucket.#{bucket_res}.arn}/"}

  context('s3 data selectors') do

    context('with no buckets to ignore') do

      it('should return a basic selector for all buckets') do
        ctx = described_class.create(name, store: store, topic: 'test-topic')

        event_selectors = trail(name, ctx)[:event_selector]

        expect(event_selectors).to include(
            a_hash_including(
                read_write_type: "All",
                data_resource: {
                    type: "AWS::S3::Object",
                    values: ["arn:aws:s3:::"],
                }
            )
        )
      end

      it('should not return an advanced selector for s3 oject data events') do
        ctx = described_class.create(name, store: store, topic: 'test-topic')

        advanced_selectors = trail(name, ctx)[:advanced_event_selector]

        expect(Array(advanced_selectors)).not_to include(
            a_hash_including(
                field_selector: array_including(
                    {field: 'eventCategory',  equals: ['Data']},
                    {field: 'resources.type', equals: ['AWS::S3::Object']},
                )
            )
        )
      end
    end

    context('with buckets to ignore') do
      it('should return an advanced selector for all buckets except ignored') do
        ctx = described_class.create(name, store: store, topic: 'test-topic', ignore_buckets: [bucket_name])

        advanced_selectors = trail(name, ctx)[:advanced_event_selector]

        expect(advanced_selectors).to include(
            a_hash_including(
                name: 'Log all S3 buckets objects events except these',
                field_selector: array_including(
                    {field: 'eventCategory',  equals: ['Data']},
                    {field: 'resources.type', equals: ['AWS::S3::Object']},
                    {field: 'resources.ARN',  not_equals: array_including(bucket_arn)},
                )
            )
        )
      end

      it('should return an advanced selector for management events') do
        ctx = described_class.create(name, store: store, topic: 'test-topic', ignore_buckets: [bucket_name])

        advanced_selectors = trail(name, ctx)[:advanced_event_selector]

        expect(advanced_selectors).to include(
            a_hash_including(
                name: 'Log readOnly and writeOnly management events',
                field_selector: array_including(
                    {field: 'eventCategory',  equals: ['Management']},
                )
            )
        )
      end

      it('should not return a basic selector for all buckets') do
        ctx = described_class.create(name, store: store, topic: 'test-topic', ignore_buckets: ['bucket-a', 'bucket-b'])

        event_selectors = trail(name, ctx)[:event_selector]

        expect(event_selectors).not_to include(
            a_hash_including(
                read_write_type: "All",
                data_resource: {
                    type: "AWS::S3::Object",
                    values: ["arn:aws:s3:::"],
                }
            )
        )
      end

      it('should create data sources to read the bucket arn') do
        ctx = described_class.create(name, store: store, topic: 'test-topic', ignore_buckets: [bucket_name])

        s3_bucket = ctx.output_with_children['data']['aws_s3_bucket'][bucket_res]

        expect(s3_bucket).not_to be_nil
        expect(s3_bucket).to include(bucket: bucket_name)
      end

    end

  end
end

def trail(name, ctx)
  ctx.output_with_children['resource']['aws_cloudtrail'][name]
end

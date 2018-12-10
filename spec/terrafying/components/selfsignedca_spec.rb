require 'terrafying'
require 'terrafying/components/selfsignedca'

RSpec::Matchers.define_negated_matcher :not_include, :include

RSpec.describe Terrafying::Components::SelfSignedCA do

  it_behaves_like "a CA"

  it "should stick the ca key in s3 if it is referenced" do
    ca = Terrafying::Components::SelfSignedCA.create("foo", "some-bucket")

    expect(ca.output["resource"]["aws_s3_bucket_object"].values).to not_include(
      a_hash_including(
        key: a_string_matching(/ca.key$/)
      )
    )

    kp = ca.keypair

    expect(ca.output["resource"]["aws_s3_bucket_object"].values).to include(
      a_hash_including(
        key: a_string_matching(/ca.key$/)
      )
    )

    expect(kp.has_key?(:name)).to be false
  end

  it "should stick the ca key in s3 if when given a ca/key" do
    ca = Terrafying::Components::SelfSignedCA.create("foo", "some-bucket", ca_cert: "foo.cert", ca_key: "foo.key")
    kp = ca.keypair

    expect(ca.output["resource"]["aws_s3_bucket_object"].values).to include(
      a_hash_including(
        content: a_string_matching(/foo.cert$/)
      )
    )

  end

end

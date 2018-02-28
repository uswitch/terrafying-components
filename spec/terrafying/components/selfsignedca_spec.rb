require 'terrafying'
require 'terrafying/components/selfsignedca'


RSpec.describe Terrafying::Components::SelfSignedCA do

  it_behaves_like "a CA"

  it "should stick the ca key in s3 if it is referenced" do
    ca = Terrafying::Components::SelfSignedCA.create("foo", "some-bucket")

    expect(ca.output["resource"]["aws_s3_bucket_object"].select { |_, obj|
             obj[:key].end_with?("ca.key")
           }.count).to eq(0)

    kp = ca.keypair

    expect(ca.output["resource"]["aws_s3_bucket_object"].select { |_, obj|
             obj[:key].end_with?("ca.key")
           }.count).to eq(1)

    expect(kp.has_key?(:name)).to be false
  end

end

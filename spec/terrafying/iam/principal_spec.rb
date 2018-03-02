# frozen_string_literal: true

require 'terrafying/iam/principal'

RSpec.describe Terrafying::IAM::Grant do
  context 'creating a principal' do
    it 'for a type' do
      pr = Terrafying::IAM::Principal.for('some-type', 'some-user')

      expect(pr.type).to eq('some-type')
      expect(pr.principals).to include('some-user')
    end

    it 'for aws' do
      pr = Terrafying::IAM::Principal.for_aws('some-user')

      expect(pr.type).to eq('AWS')
      expect(pr.principals).to include('some-user')
    end

    it 'for aws with multiple principals' do
      pr = Terrafying::IAM::Principal.for_aws('some-user', 'another-arn')

      expect(pr.principals).to include('some-user', 'another-arn')
    end
  end

  context 'converting to hash' do
    it 'has the type as a key and principal set' do
      pr = Terrafying::IAM::Principal.for('some-type', 'some-user')
      pr_h = pr.to_h

      expect(pr_h).to have_key(:'some-type')
      expect(pr_h[:'some-type']).to include('some-user')
    end

    it 'has the aws as a key and principal set' do
      pr = Terrafying::IAM::Principal.for_aws('some-user')
      pr_h = pr.to_h

      expect(pr_h).to have_key(:AWS)
      expect(pr_h[:AWS]).to include('some-user')
    end
  end
end

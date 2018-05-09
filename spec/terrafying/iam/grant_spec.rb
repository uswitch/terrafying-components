# frozen_string_literal: true

require 'terrafying/iam/grant'

RSpec.describe Terrafying::IAM::Grant do
  context 'creating a grant' do
    it 'for a bucket' do
      grant = Terrafying::IAM::Grant.for('a-bucket')

      expect(grant.resources).to include('a-bucket')
    end

    it 'for more than one bucket' do
      grant = Terrafying::IAM::Grant.for('a-bucket', '2nd-bucket')

      expect(grant.resources).to include('a-bucket', '2nd-bucket')
    end

    it 'for a bucket with one action' do
      grant = Terrafying::IAM::Grant
              .for('a-bucket')
              .actions('an-action')

      expect(grant.action).to include('an-action')
    end

    it 'for a bucket with more than one action' do
      grant = Terrafying::IAM::Grant
              .for('a-bucket')
              .actions('an-action', '2nd-action')

      expect(grant.action).to include('an-action', '2nd-action')
    end
  end

  context 'converting to hash' do
    it 'has resources' do
      grant = Terrafying::IAM::Grant
              .for('a-bucket')
              .actions('an-action')

      resources = grant.to_h[:Resource]

      expect(resources).to include('a-bucket')
    end

    it 'has actions' do
      grant = Terrafying::IAM::Grant
              .for('a-bucket')
              .actions('an-action')

      actions = grant.to_h[:Action]

      expect(actions).to include('an-action')
    end
  end
end

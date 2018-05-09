# frozen_string_literal: true

require 'terrafying/iam/statement'

RSpec.describe Terrafying::IAM::Statement do
  context 'creating a statement' do
    it 'allows' do
      st = Terrafying::IAM::Statement.for('a-principal').allow

      expect(st.effect).to eq(:Allow)
    end

    it 'denies' do
      st = Terrafying::IAM::Statement.for('a-principal').deny

      expect(st.effect).to eq(:Deny)
    end

    it 'allows a principal' do
      st = Terrafying::IAM::Statement.for('a-principal').allow

      expect(st.principal).to include('a-principal')
    end

    it 'allows more than one principal' do
      st = Terrafying::IAM::Statement.for('a-principal', '2nd-principal').allow

      expect(st.principal).to include('a-principal', '2nd-principal')
    end
  end

  context 'converting to array' do
    it 'has an empty list as no grants were set' do
      st = Terrafying::IAM::Statement.for('a-principal').allow

      expect(st.to_a.empty?).to be(true)
    end
  end
end

# frozen_string_literal: true

require 'terrafying/iam/dsl'

RSpec.describe Terrafying::IAM do
  before(:each) do
    @test_obj = Object.new
    @test_obj.extend(Terrafying::IAM)
  end

  it 'starts a new statement with effect allow' do
    sb = @test_obj.allow('boo')

    expect(sb.effect).to eq(:Allow)
  end

  it 'starts a new statement with effect deny' do
    sb = @test_obj.deny('boo')

    expect(sb.effect).to eq(:Deny)
  end
end

RSpec.describe Terrafying::IAM, 'principals' do
  before(:each) do
    @test_obj = Object.new
    @test_obj.extend(Terrafying::IAM)
  end

  it 'anyone returns a principal for public access' do
    pr = @test_obj.anyone

    expect(pr.type).to eq('AWS')
    expect(pr.principals).to eq(['*'])
  end

  it 'account returns a principal for account-wide access' do
    pr = @test_obj.account

    expect(pr.type).to eq('AWS')
    expect(pr.principals).to eq(['arn:aws:iam::136393635417:root'])
  end
end

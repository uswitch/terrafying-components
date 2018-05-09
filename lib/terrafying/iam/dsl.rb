# frozen_string_literal: true

require 'terrafying/iam/grant'
require 'terrafying/iam/statement'

module Terrafying
  module IAM
    def allow(*principals)
      Statement.for(principals).allow
    end

    def deny(*principals)
      Statement.for(principals).deny
    end

    def read_buckets(*buckets)
      Grant.for(buckets)
           .actions(
             's3:GetBucketAcl',
             's3:GetBucketPolicy',
             's3:ListBucket',
             's3:ListBucketVersions'
           )
    end

    def read_objects(*paths)
      Grant.for(paths)
           .actions(
             's3:GetObject'
           )
    end

    def anyone
      Principal.for_aws('*')
    end

    def account
      Principal.for_aws('arn:aws:iam::136393635417:root')
    end
  end
end

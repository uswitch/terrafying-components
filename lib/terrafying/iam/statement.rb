# frozen_string_literal: true

require 'json'

module Terrafying
  module IAM
    class Statement
      attr_reader :principal, :effect, :grants

      def self.for(*principals)
        new principals
      end

      def initialize(principals)
        @grants = []
        @principal = principals
      end

      def allow
        @effect = :Allow
        self
      end

      def deny
        @effect = :Deny
        self
      end

      def to(*grants)
        @grants = grants
        self
      end

      def to_a
        h = {
          Effect: @effect,
          Principal: @principal
        }

        @grants.map { |g| h.merge(g.to_h) }
      end
    end
  end
end

# frozen_string_literal: true

require 'json'

module Terrafying
  module IAM
    class Grant
      attr_reader :resources, :action

      def self.for(*resources)
        new resources
      end

      def initialize(resources)
        @resources = resources
      end

      def actions(*actions)
        @action = actions
        self
      end

      def to_h
        {
          Action: @action,
          Resource: @resources
        }
      end
    end
  end
end

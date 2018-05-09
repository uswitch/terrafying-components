# frozen_string_literal: true

require 'json'

module Terrafying
  module IAM
    class Principal
      attr_reader :type, :principals

      def self.for(type, *principals)
        new type, principals
      end

      def self.for_aws(*principals)
        Principal.for('AWS', *principals)
      end

      def initialize(type, principals)
        @type = type
        @principals = principals
      end

      def to_h
        {
          "#{@type}": @principals
        }
      end

      def to_s
        JSON.pretty_generate to_h
      end
    end
  end
end

# frozen_string_literal: true

# this file is copied from ignition.rb: https://github.com/uswitch/terrafying-components/blob/master/lib/terrafying/components/ignition.rb

require 'erb'
require 'ostruct'
require 'yaml'

module Terrafying
  module Components
    class Cloudconfig
      UNIT_REQUIRED_KEYS = [:name].freeze
      FILE_REQUIRED_KEYS = %i[path mode contents].freeze
      
      def self.generate(options = {})
        options = {
          keypairs: [],
          volumes: [],
          files: [],
          units: [],
          users: [],
          networkd_units: [],
          ssh_group: 'cloud',
          disable_update_engine: false,
          region: Terrafying::Generator.aws.region
        }.merge(options)

        unless options[:units].all? { |u| UNIT_REQUIRED_KEYS.all? { |key| u.key?(key) } }
          raise "All units require the following keys: #{UNIT_REQUIRED_KEYS}"
        end

        unless options[:units].all? { |u| u.key?(:contents) || u.key?(:dropins) || u.fetch(:enabled, true) == false || u.fetch(:mask, false) == true }
          raise 'All enabled unmasked units have to have contents and/or dropins'
        end

        unless options[:files].all? { |f| FILE_REQUIRED_KEYS.all? { |key| f.key?(key) } }
          raise "All files require the following keys: #{FILE_REQUIRED_KEYS}"
        end

        options[:cas] = options[:keypairs].map { |kp| kp[:ca] }.compact.sort.uniq

        # changes apart from ignition.rb
        # changed template file to cloudconfig.yaml
        erb_path = File.join(File.dirname(__FILE__), 'templates/cloudconfig.yaml')
        erb = ERB.new(IO.read(erb_path), nil, '-')
        # instead of ignition json, we'll output the yaml file
        erb.result(OpenStruct.new(options).instance_eval { binding })

      end
    end
  end
end

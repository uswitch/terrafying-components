# frozen_string_literal: true

require 'erb'
require 'ostruct'

module Terrafying
  module Components
    class Ignition
      UNIT_REQUIRED_KEYS = [:name].freeze
      FILE_REQUIRED_KEYS = %i[path mode contents].freeze

      def self.container_unit(name, image, options = {})
        options = {
          volumes: [],
          environment_variables: [],
          arguments: [],
          require_units: [],
          host_networking: false,
          privileged: false
        }.merge(options)

        if options[:require_units].count > 0
          require_units = options[:require_units].join(' ')
          require = <<~EOF
            After=#{require_units}
            Requires=#{require_units}
          EOF
        end

        docker_options = []

        if options[:environment_variables].count > 0
          docker_options += options[:environment_variables].map do |var|
            "-e #{var}"
          end
        end

        if options[:volumes].count > 0
          docker_options += options[:volumes].map do |volume|
            "-v #{volume}"
          end
        end

        docker_options << '--net=host' if options[:host_networking]

        docker_options << '--privileged' if options[:privileged]

        docker_options_str = " \\\n" + docker_options.join(" \\\n")

        if options[:arguments].count > 0
          arguments = " \\\n" + options[:arguments].join(" \\\n")
        end

        {
          name: "#{name}.service",
          contents: <<~EOF
            [Install]
            WantedBy=multi-user.target

            [Unit]
            Description=#{name}
            #{require}

            [Service]
            ExecStartPre=-/usr/bin/docker rm -f #{name}
            ExecStart=/usr/bin/docker run --name #{name} #{docker_options_str} \
            #{image} #{arguments}
            Restart=always
            RestartSec=30

          EOF
        }
      end

      def self.generate(options = {})
        options = {
          keypairs: [],
          volumes: [],
          files: [],
          units: [],
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

        erb_path = File.join(File.dirname(__FILE__), 'templates/ignition.yaml')
        erb = ERB.new(IO.read(erb_path))

        yaml = erb.result(OpenStruct.new(options).instance_eval { binding })

        Terrafying::Util.to_ignition(yaml)
      end
    end
  end
end

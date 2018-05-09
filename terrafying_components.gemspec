# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'terrafying/components/version'

Gem::Specification.new do |spec|
  spec.name          = "terrafying_components"
  spec.version       = Terrafying::Components::VERSION
  spec.authors       = ["uSwitch Limited"]
  spec.email         = ["developers@uswitch.com"]
  spec.license       = "Apache-2.0"

  spec.summary       = %q{No.}
  spec.description   = %q{No.}
  spec.homepage      = "https://github.com/uswitch/terrafying-components"

  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency 'rspec', '~> 3.7'
  spec.add_development_dependency 'rspec-mocks', '~> 3.7'

  spec.add_runtime_dependency 'netaddr', '~> 1.5'
  spec.add_runtime_dependency 'terrafying', '~> 1'
  spec.add_runtime_dependency 'xxhash', '~> 0.4.0'
end

# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'terrafying/components/version'

Gem::Specification.new do |spec|
  spec.name          = 'terrafying-components'
  spec.version       = Terrafying::Components::VERSION
  spec.authors       = ['uSwitch Limited']
  spec.email         = ['developers@uswitch.com']
  spec.license       = 'Apache-2.0'

  spec.summary       = 'No.'
  spec.description   = 'No.'
  spec.homepage      = 'https://github.com/uswitch/terrafying-components'

  spec.files         = `git ls-files lib/`.split($RS)
  spec.require_paths = ['lib']

  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.7'
  spec.add_development_dependency 'rspec-mocks', '~> 3.7'

  spec.add_runtime_dependency 'terrafying', '>= 1.8.0'
  spec.add_runtime_dependency 'xxhash', '~> 0.4.0'
end

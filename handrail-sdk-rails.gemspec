require_relative "lib/handrail/sdk/rails/version"

Gem::Specification.new do |spec|
  spec.name = "handrail-sdk-rails"
  spec.version = Handrail::SDK::Rails::VERSION
  spec.authors = ["Handrail"]
  spec.email = ["support@handrail.dev"]

  spec.summary = "Rails helpers for Handrail project operation endpoints."
  spec.description = "Verifies Handrail operation invocation signatures and builds typed operation response envelopes."
  spec.homepage = "https://github.com/c0x65o/handrail-sdk-rails"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.files = Dir.chdir(__dir__) do
    Dir["lib/**/*.rb", "README.md", "LICENSE*"]
  end
  spec.require_paths = ["lib"]
end

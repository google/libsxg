require_relative 'lib/sxg/version'

Gem::Specification.new do |spec|
  spec.name          = "sxg"
  spec.version       = Sxg::VERSION
  spec.authors       = ["Hiroki Kumazaki"]
  spec.email         = ["kumagi@google.com"]

  spec.summary       = %q{library for Signed HTTP Exchange}
  spec.description   = %q{You can generate SXG and certificate chain.}
  spec.homepage      = "https://github.com/google/libsxg"
  spec.license       = "MIT"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.3.0")

  spec.metadata["allowed_push_host"] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/google/libsxg"
  spec.metadata["changelog_uri"] = "https://github.com/google/libsxg/releases"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.extensions << "ext/sxg/extconf.rb"
  spec.add_development_dependency "rake-compiler"
end

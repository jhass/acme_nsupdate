# coding: utf-8
lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

require "acme_nsupdate/version"

Gem::Specification.new do |spec|
  spec.name          = "acme_nsupdate"
  spec.version       = AcmeNsupdate::VERSION
  spec.authors       = ["Jonne Haß"]
  spec.email         = ["me@jhass.eu"]

  spec.summary       = "ACME (Let's Encrypt) client with nsupdate (DDNS) integration."
  spec.description   = "CLI tool to obtain certificates via ACME and update the matching TLSA records.
    The primary authentication method is http-01 via webroot for now, but dns-01 is supported too."
  spec.homepage      = "https://github.com/jhass/acme_nsupdate"
  spec.license       = "MIT"

  spec.files         = Dir["lib/**/*.rb", "bin/*", "LICENSE.txt", "README.md"]
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(/^bin\//) {|f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "slop", "~> 4.0"
  spec.add_dependency "acme-client", "~> 2.0.0"
  spec.add_dependency "faraday-detailed_logger"
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake"
end

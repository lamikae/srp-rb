# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "srp-rb/version"

Gem::Specification.new do |s|
  s.name        = "srp-rb"
  s.version     = Srp::Rb::VERSION
  s.authors     = ["lamikae"]
  s.email       = [""]
  s.homepage    = ""
  s.summary     = %q{Secure Remote Password protocol SRP-6a.}
  s.description = %q{
    Ruby implementation of the Secure Remote Password protocol (SRP-6a).
    SRP is a cryptographically strong authentication protocol for
    password-based, mutual authentication over an insecure network connection.}

  s.rubyforge_project = "srp-rb"

  s.files         = Dir.glob("lib/**/*")
  s.test_files    = Dir.glob("spec/*")
  s.require_paths = ["lib"]

  s.add_dependency "digest-sha3"

  s.add_development_dependency "rspec"
end

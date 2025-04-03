# -*- encoding: utf-8 -*-
require File.expand_path('../lib/saml/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["benoist"]
  gem.email         = ["benoist.claassen@gmail.com"]
  gem.description   = %q{This gem is a (partial) implementation of the XMLDsig specification}
  gem.summary       = %q{This gem is a (partial) implementation of the XMLDsig specification (http://www.w3.org/TR/xmldsig-core)}
  gem.homepage      = "https://github.com/benoist/xmldsig"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "saml"
  gem.license       = 'MIT'
  gem.require_paths = ["lib"]
  gem.version       = SAML::VERSION
  
  gem.required_ruby_version = '>= 1.9.2'

  gem.add_dependency("nokogiri", '>= 1.6.8', '< 2.0.0')
  gem.add_dependency("securerandom", '>= 0.3.1', '< 1.0.0')
  gem.add_dependency("scientist", '>= 1.6.4', '< 2.0.0')
  gem.add_dependency("time", ">= 0.3.0", "< 1.0.0")
end

Gem::Specification.new do |s|
  s.name        = "swiftauth"
  s.version     = "1.0.0"
  s.summary     = "Official SwiftAuth SDK for Ruby"
  s.description = "Ruby client for SwiftAuth authentication, licensing, and real-time features."
  s.authors     = ["SwiftAuth"]
  s.homepage    = "https://swiftauth.net"
  s.license     = "MIT"
  s.required_ruby_version = ">= 3.0"

  s.files = Dir["lib/**/*.rb"]

  s.add_dependency "json"
end

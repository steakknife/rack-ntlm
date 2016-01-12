require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "rack-ntlm"
    gem.summary = %Q{Rack middleware for transparent authentication with NTLM}
    gem.description = %Q{Rack middleware for transparent authentication with NTLM. This is a fork from lukefx/rack-ntlm on Github. This makes the Rack middleware a gem and uses net/ldap to search the user against an ActiveDirectory server. This is work in progress, so contributions are welcome.}
    gem.email = "dtsato@gmail.com"
    gem.homepage = "http://github.com/dtsato/rack-ntlm"
    gem.authors = ["Danilo Sato", "Steve Lawson", "Matt Conover"]
    
    gem.has_rdoc = true
    gem.rdoc_options = ["--main", "README.rdoc", "--inline-source", "--line-numbers"]
    gem.extra_rdoc_files = ["README.rdoc"]

    gem.test_files = Dir['test/**/*'] + Dir['test/*']
    
    gem.add_dependency('rubyntlm', '0.1.2.cv')
  end
  
  Jeweler::GemcutterTasks.new
  
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: sudo gem install jeweler"
end

desc 'Default: run unit tests.'
task :default => :test

desc 'Test the rack_ntlm plugin.'
Rake::TestTask.new(:test) do |t|
  t.libs << 'lib'
  t.libs << 'test'
  t.pattern = 'test/**/*_test.rb'
  t.verbose = true
end

desc 'Generate documentation for the rack_ntlm plugin.'
Rake::RDocTask.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = 'rdoc'
  rdoc.title    = 'Rack-ntlm'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.rdoc_files.include('README.rdoc')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

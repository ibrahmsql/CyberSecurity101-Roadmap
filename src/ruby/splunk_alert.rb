#!/usr/bin/env ruby
# splunk_alert.rb – Run a Splunk search and export results to CSV
# Gems: gem install splunk-client csv
# Usage: ruby splunk_alert.rb https://splunk:8089 user pass "search index=main error | head 20" output.csv
require 'splunk-client'
require 'csv'

unless ARGV.length == 5
  puts "Usage: ruby splunk_alert.rb <url> <user> <pass> <search> <out.csv>"
  exit 1
end
url, user, pass, query, outfile = ARGV
service = Splunk::connect(:username => user, :password => pass, :scheme => 'https', :host => URI(url).host, :port => URI(url).port)
job = service.jobs.create query
while !job.is_done?
  sleep 1
end
puts "[+] Query finished, writing #{outfile}…"
CSV.open(outfile, 'w') do |csv|
  csv << job.results.field_names
  job.results.each do |row|
    csv << row.values
  end
end
puts '[+] Done.'

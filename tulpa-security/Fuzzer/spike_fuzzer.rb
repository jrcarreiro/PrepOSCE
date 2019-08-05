#!/usr/bin/env ruby
# Simple wrapper to run multiple .spk files using generic_send_tcp

spikese = '/usr/bin/generic_send_tcp'

if ARGV[4] = " "
    puts "Usage: $0 IP_ADDRESS PORT SKIPFILE SKIPVAR SKIPSTR\n\n"
end

skipfiles = ARGV[2]
files = Dir.glob("*.spk")

for i in files do
    system("#{spikese} #{ARGV[0]} #{ARGV[1]}  #{i} #{ARGV[3]} #{ARGV[4]}")
end
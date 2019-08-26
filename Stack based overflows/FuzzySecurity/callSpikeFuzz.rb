#!/usr/bin/env ruby

require 'socket'

host = "192.168.0.15"
port = "21"
spikese = '/usr/bin/generic_send_tcp'
file = "fuzzerFTP.spk"

s = TCPSocket.open(host, port)
s.recv(1024)

s.send("USER anonymous\r\n", 0)
s.recv(1024)
s.send("PASS anonymous\r\n", 0)
s.recv(1024)

system("#{spikese} #{host} #{port} #{file} 0 0")

# for i in files do
#     system("#{spikese} #{ARGV[0]} #{ARGV[1]}  #{i} #{ARGV[3]} #{ARGV[4]}")
# end
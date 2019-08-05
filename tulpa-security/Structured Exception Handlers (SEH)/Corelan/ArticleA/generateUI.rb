#!/usr/bin/env ruby

uitxt = "ui.txt"

junk = "A" * 5000


File.open(uitxt, 'w') {|s| s.write(junk)}
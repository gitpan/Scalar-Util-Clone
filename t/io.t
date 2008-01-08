use strict;
use warnings;
use blib;

use Test::More tests => 3;
use IO::Handle;
use Scalar::Util::Clone qw(clone);
use Data::Dumper;

my $io = IO::Handle->new();
my $clone = clone($io);

isnt (\$clone, \$io);
is ($clone, $io);
is (Dumper($clone), Dumper($io));

use strict;
use warnings;
use blib;

use Scalar::Util::Clone qw(clone);
use Test::More tests => 8;

$| = 1;

sub coderef1 { ok(1) }

my $coderef2 = sub { ok(1) };

my $clone1 = clone(\&coderef1);
my $clone2 = clone($coderef2);

isnt (\$clone1, \\&coderef1);
is ($clone1, \&coderef1);

isnt (\$clone2, \\&coderef2);
is ($clone2, $coderef2);

coderef1();
$coderef2->();
$clone1->();
$clone2->();

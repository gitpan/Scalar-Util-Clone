#!perl

use strict;
use warnings;

use Data::Dumper;
use Test::More tests => 8;

$| = 1;

use_ok ('Scalar::Util::Clone', qw(clone));
use_ok ('Scalar::Util', qw(weaken isweak));

my $test1 = [ undef ];
my $test2 = { self => undef };

weaken($test1->[0] = $test1);
weaken($test2->{self} = $test2);

ok (isweak($test1->[0]));
ok (isweak($test2->{self}));

my $clone1 = clone($test1);
my $clone2 = clone($test2);

ok(isweak($clone1->[0]));
ok(isweak($clone2->{self}));

is (Dumper($test1), Dumper($clone1));
is (Dumper($test2), Dumper($clone2));

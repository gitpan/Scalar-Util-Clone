use strict;
use warnings;
use blib;

use Data::Dumper; $Data::Dumper::Terse = $Data::Dumper::Indent = 1;
use Test::More tests => 11;
use Scalar::Util::Clone qw(clone);

$| = 1;

use_ok ('Scalar::Util', qw(weaken isweak));

my $test1 = [ undef ];
my $test2 = { self => undef };

weaken($test1->[0] = $test1);
weaken($test2->{self} = $test2);

ok (isweak($test1->[0]));
ok (isweak($test2->{self}));

ok(not(isweak($test1)));
ok(not(isweak($test2)));

my $clone1 = clone($test1);
my $clone2 = clone($test2);

ok(isweak($clone1->[0]));
ok(isweak($clone2->{self}));

ok(not(isweak($clone1)));
ok(not(isweak($clone2)));

is (Dumper($clone1), Dumper($test1));
is (Dumper($clone2), Dumper($test2));

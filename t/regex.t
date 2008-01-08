use strict;
use warnings;
use blib;

use Test::More tests => 6;
use Scalar::Util::Clone qw(clone);

my $re = qr{Hello, World!};
my $clone = clone($re);

isnt (\$clone, \$re);
is ($clone, $re);

my $succeed = 'Hello, World!';
my $fail = 'hello, world!';

ok($succeed =~ /$re/);
ok($succeed =~ /$clone/);
ok($fail !~ /$re/);
ok($fail !~ /$clone/);

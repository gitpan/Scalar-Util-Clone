use strict;
use warnings;
use blib;

use Data::Dumper;
use Scalar::Util::Clone qw(clone);
use Test::More tests => 6;

$| = 1;

is (Dumper({}), Dumper(clone({})));
is (Dumper({ foo => undef }), Dumper(clone({ foo => undef })));
is (Dumper({ foo => 1 }), Dumper(clone({ foo => 1 })));
is (Dumper(bless { foo => undef }, 'bar'), Dumper(clone(bless { foo => undef }, 'bar')));
is (Dumper(bless { foo => 1 }, 'bar'), Dumper(clone(bless { foo => 1 }, 'bar')));
is (Dumper({ chr(256), 1 }), Dumper(clone({ chr(256), 1 })));

#!perl

use strict;
use warnings;

use Test::More tests => 13;

$| = 1;

use_ok ('Scalar::Util::Clone', qw(clone));

is (undef, clone (undef));
is (0, clone (0));
is (-42, clone (-42));
is (42, clone (42));
is (+42, clone (+42));
is (3.1415927, clone (3.1415927));
is (-3.1415927, clone (-3.1415927));
is ('', clone (''));
is ('a', clone ('a'));
is (chr(256), clone(chr(256)));
is ('foo', clone ('foo'));
is ("foo\0bar", clone ("foo\0bar"));

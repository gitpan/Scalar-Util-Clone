#!perl

use strict;
use warnings;

use Tie::Hash;
use base qw(Tie::ExtraHash);
use Data::Dumper;
use Scalar::Util::Clone qw(clone);
use Test::More tests => 5;

$| = 1;

sub FETCH { uc $_[0]->[0]->{$_[1]} }

my %test = ();
tie %test, __PACKAGE__;

my $test = \%test;

$test->{alpha} = 'beta';
$test->{gamma} = 'vlissides';

is ($test->{alpha}, 'BETA');
is ($test->{gamma}, 'VLISSIDES');

my $clone = clone $test;

is ($clone->{alpha}, 'BETA');
is ($clone->{gamma}, 'VLISSIDES');

is (Dumper($test), Dumper($clone));

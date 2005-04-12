#!perl

package Scalar::Util::Clone::Test::TiedHash;

use strict;
use warnings;

require Tie::Hash;
require Exporter;
use Carp qw(confess);

our @ISA = qw(Tie::StdHash);

sub TIEHASH {
    my $class = shift;
    my $self = [ {}, [] ];
    bless $self, $class;
}

sub FETCH {
    my ($self, $key) = @_;
    my ($hash, $array) = @$self;
    return $hash->{$key}->[0];
}

sub STORE {
    my ($self, $key, $value) = @_;
    my ($hash, $array) = @$self;
    if (exists $hash->{$key}) {
	$hash->{$key}->[0] = $value;
    } else {
	push @$array, $key; 
	$hash->{$key} = [ $value, $#$array ];
    }
}

sub FIRSTKEY {
    my $self = shift;
    my ($hash, $array) = @$self;
    return $#$array == -1 ? undef : $array->[0];
}

sub NEXTKEY {
    my ($self, $lastkey) = @_;
    my ($hash, $array) = @$self;
    my $value = $hash->{$lastkey};
    my $index = $value->[1] + 1;
    return ($index <= $#$array) ? $array->[$index] : undef;
}

sub EXISTS {
    my ($self, $key) = @_;
    my ($hash, $array) = @$self;
    return exists $hash->{$key};
}

sub DELETE {
    my ($self, $key) = @_;
    my ($hash, $array) = @$self;
    my $value = delete $hash->{$key};
    splice @$array, $value->[1], 1;
}

sub CLEAR {
    my ($self, $key) = @_;
    my ($hash, $array) = @$self;
    %$hash = @$array = ();
}

sub TIEHANDLE {
    my ($self, $key) = @_;
    my ($hash, $array) = @$self;
    return $hash;
}

1;

package Scalar::Util::Clone::Test::Node;

# simple Node class to test Scalar::Util::Clone's weakref cloning

use strict;
use warnings;
use Scalar::Util qw(weaken);

sub new {
    my ($class, $id) = @_;
    my $self = {
		CHILDREN    => [ ],
		ID	    => $id,
		INDEX	    => { },
		PARENT	    => undef
    };
    bless $self, $class;
}

sub add {
    my ($self, $child) = @_;
    my $child_id = $child->{ID};

    push @{$self->{CHILDREN}}, $child;
    $self->{INDEX}->{$child_id} = $child;
    weaken ($child->{PARENT} = $self);
    return $self;
}

1;

package main;

use strict;
use warnings;

use Data::Dumper;
use Test::More tests => 34;

BEGIN { $| = 1; use_ok('Scalar::Util::Clone', qw(clone)); } # 1 

# Test::Deep's cache transforms the values it compares - in particular
# it winds up leaving null pointers in the magical backref AV of weak referents,
# which in turn causes clone_array() - which shouldn't have to check for such
# anomalies - to segfault.

sub is_deep ($$;$) {
	my ($got, $want, $msg) = @_;
	no warnings 'once';
	local ($Data::Dumper::Terse = $Data::Dumper::Indent) = (1, 1);
	return is(Dumper($got), Dumper($want), $msg);
}

SKIP: {
    skip ('Weakrefs are not supported in this version of perl', 13) unless (&Scalar::Util::Clone::supports_weakrefs);

    # don't use Scalar::Util until we're sure this perl supports weakrefs
    use_ok('Scalar::Util', qw(weaken isweak));

    my $v1 = {};

    $v1->{a} = $v1;

    weaken ($v1->{a});
    my $v2 = clone($v1);

    ok (isweak ($v1->{a}), 'original weakref');
    ok (isweak ($v2->{a}), 'cloned weakref');
    is_deep($v1, $v2, 'cloned weakref - same contents');

    my $multi_weak = [ $v1, $v1, $v2, $v2 ];
    my $multi_weak_clone = clone($multi_weak);
	# print Dumper($multi_weak_clone), $/;
	# print Dumper($multi_weak), $/;
    is_deep($multi_weak, $multi_weak_clone, 'cloned weakrefs - same contents');

    my $node1 = Scalar::Util::Clone::Test::Node->new(1);
    my $node2 = Scalar::Util::Clone::Test::Node->new(2);
    my $node3 = Scalar::Util::Clone::Test::Node->new(3);

    $node2->add($node3);
    $node1->add($node2);

    my $node4 = clone($node1);

    isnt ($node4, $node1, 'cloned node: different refs');
    is_deep($node4, $node1, 'cloned node: same data');

    isnt ($node4->{CHILDREN}, $node1->{CHILDREN}, 'cloned node children: different refs');
    # the by-name index of child nodes is tested because that's the
    # kind of node used by Xelig 
    isnt ($node4->{INDEX}, $node1->{INDEX}, 'cloned node index: different refs');

    is ($node1->{CHILDREN}->[0]->{PARENT}, $node1,
	'original node: self->child->parent = self');
    is ($node4->{CHILDREN}->[0]->{PARENT}, $node4,
	'cloned node: self->child->parent = self');

    is ($node1->{INDEX}->{2}->{PARENT}, $node1,
	'original node: self->idx->child->parent = self');
    is ($node4->{INDEX}->{2}->{PARENT}, $node4,
	'cloned node: self->idx->child->parent = self');
}

my %tied = ();

# an indexed hash (like Tie::IxHash)
tie %tied, 'Scalar::Util::Clone::Test::TiedHash';

my $undef = undef;
my $integer = 42;
my $float = 3.1415927;
my $string = 'Hello, world';
my $hash = {};
my $uhash = { key1 => undef, key2 => undef };
my $array = [];
my $tied = \%tied;
my $regex = qr{Hello, World!};
my $all = {
    HASH    => $hash,
    ARRAY   => $array,
    STRING  => $string,
    INTEGER => $integer,
    FLOAT   => $float,
    TIED    => $tied,
    REGEX	=> $regex
};

srand(time);

for (0 .. 9) {
    my $key = sprintf 'key_%d_%.3d', $_, substr (rand(), 2, 3); 
    $tied{$key} = $_;
    $hash->{$key} = $_;
    push @$array, $key;
}

my $hash_clone = clone($hash);
my $uhash_clone = clone ($uhash);
my $array_clone = clone($array);
my $tied_clone = clone($tied);
my $all_clone1 = clone($all);

is ($undef, clone($undef), 'undef');
is ($integer, clone($integer), 'integer');
is ($float, clone($float), 'float');
is ($string, clone($string), 'string');

isnt ($hash, $hash_clone, 'HASH ref: different refs');
is_deeply ($hash, $hash_clone, 'HASH ref: same values');

isnt ($uhash, $uhash_clone, 'cloned hash with undef values: different refs');
is_deeply ($uhash, $uhash_clone, 'cloned hash with undef values: same values');

isnt ($array, $array_clone, 'ARRAY ref: different refs');
is_deeply ($array, $array_clone, 'ARRAY ref: same values');

# the clone's keys should have the same ordering as the original's
isnt ($tied, $tied_clone, 'tied hash: different refs');
# make sure the tied hashes are the same
is_deeply($tied_clone, $tied, 'clone tied hash: same values');
# make sure the tying (and therefore the ordering) worked
is_deeply ([ keys %$tied_clone ], $array, 'cloned tied hash: same order');

isnt ($all, $all_clone1, 'compound data structure: different refs');
is_deeply ($all, $all_clone1, 'compound data structure: same values');

$all->{SELF} = $all;
my $all_clone2 = clone($all);

isnt ($all, $all_clone2, 'compound self-referential data structure: different refs');

is_deep($all_clone2, $all,
    'compound self-referential data structure: same values');
delete $all->{SELF};
	    
bless $all, 'Scalar::Util::Clone::Test::Object';
my $all_clone3 = clone($all);

isnt ($all, $all_clone3, 'object: different refs');
is_deeply ($all, $all_clone3, 'object: same values');
is (ref $all, ref $all_clone3, 'object: same class');

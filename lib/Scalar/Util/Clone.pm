package Scalar::Util::Clone;

use 5.008;

use strict;
use warnings;

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);

our @EXPORT_OK = qw(clone);

our $VERSION = '0.04';

bootstrap Scalar::Util::Clone $VERSION;

1;

__END__

=head1 NAME

Scalar::Util::Clone - recursively copy datatypes using perl's builtin functions

=head1 SYNOPSIS

    use Scalar::Util::Clone qw(clone);

    $a = Foo->new();
    $b = { alpha => 'beta', gamma => 'vlissides' };

    tie %c, 'Foo::Bar';

    $d = clone($a);
    $e = clone($b);
    $f = clone(\%c);

    # or

    my $node2 = {
        name	    => 'node2',
        children    => [ $node3, $node4 ],
        parent	    => weaken ($node1)	    # weaken() to avoid memory leak
    };

    my $clone = clone($node2);

=head1 DESCRIPTION

This module exports a clone() function which unlocks the builtin functionality perl uses to clone a new interpreter
and its values. As such, it is capable of cloning all perl datatypes, including weak references, hashes with shared keys,
hashes with UTF8 keys, restricted hashes, tied variables, regex objects, and other curios lurking in Perl's intestines. Because
the clone operation is performed at the lowest level, copying the datatype's internals rather than reconstructing it
via the public API, the operation is fast and comprehensive, and produces values that exactly match their original
(for instance, L<Data::Dumper> dumps of hashes are always guaranteed to be the same as those of the original).

For performance reasons, the following types are passed through transparently rather than being deep cloned:
formats, code refs, typeglobs, IO handles, and stashes.

C<clone> returns a recursive copy of its argument, which can be an arbitrary (scalar) type including nested HASH, ARRAY
and reference types, tied variables and objects.

To duplicate non-scalar types (e.g. lists, ARRAYs and HASHes), pass them to C<clone> by reference. e.g.
    
    my $copy = clone (\@array);

    # or

    my %copy = %{ clone (\%hash) };

For a slower, but more flexible solution see Storable's C<dclone>.

=cut

=head1 VERSION

0.04

=head1 SEE ALSO

L<Clone>, L<Storable>

=head1 AUTHOR

chocolateboy: <chocolate.boy@email.com>

=head1 COPYRIGHT

Copyright (c) 2005, chocolateboy.

This module is free software. It may be used, redistributed
and/or modified under the same terms as Perl itself.

=cut

package Net::IRR::Cache;

use strict;
use warnings;

use Carp;
use YAML::Tiny;

BEGIN {
	our ($VERSION);
	$VERSION = 0.11;
}

# where to save cache files and also to load exception files form
our $Data_Dir = '/tmp';
our $Cache_Prefix = 'irr-cache';
our $Exceptions_Prefix = 'irr-exceptions';


# Create a Net::IRR:Cache object
sub load {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self = {};
	my %conf = @_;

	$self->{afi}       = $conf{afi}       || undef; # Address family to fetch data for. ipv4 or ipv6.
	$self->{asn}       = $conf{asn}       || undef; # AS number of entity we are fetching data for.
	$self->{rpsl}      = $conf{rpsl}      || undef; # RPSL expression to resolve.
	$self->{irrconfig} = $conf{irrconfig} || undef; # IRR host data (keys host, source, protocol).
	$self->{peval_bin} = $conf{peval_bin} || undef; # Path to peval.
	$self->{flat}      = $conf{flat}      || undef; # Flat or tree mode when loading route data (default flat).
	$self->{data_dir}  = $conf{data_dir}  || undef; # Path to irr-cache and exception files.
	$self->{refresh}   = $conf{refresh}   || 0;     # Load data from IRR or use cached values in irr-cache.
	$self->{debug}     = $conf{debug}     || 0;

	# verify passed parameters
	$self->{peval_bin} = '/usr/bin/peval' if (!defined $self->{peval_bin});
	$self->{flat} = 1 if (!defined $self->{flat});
	$self->{data_dir} = $Data_Dir if (!defined $self->{data_dir});
	if ($self->{refresh} == 0 && $self->{flat} == 0) {
		carp "Withouth refresh only flat mode is possible. Flat mode automatically enabled.";
		$self->{flat} = 1;
	}
	# default to RIPE IRR
	if (! defined $self->{irrconfig}) {
		$self->{irrconfig}->{host}     = 'whois.ripe.net';
		$self->{irrconfig}->{protocol} = 'ripe';
		$self->{irrconfig}->{source}   = 'RIPE';
	}

	# peval and its IRR arguments.
	$self->{arg_base} = sprintf("-h %s -protocol %s -s %s", 
		$self->{irrconfig}->{host},
		$self->{irrconfig}->{protocol},
		$self->{irrconfig}->{source},
	);
	# Indicates if data has been populated already.
	$self->{resolved} = 0;
	# data holds current AS and route lists.
	$self->{data} = {};

	bless ($self, $class);

	$self->_load_data_file();
	$self->_load_exceptions();
	$self->resolve();
	return $self;
}


# write data for this as to irr-cache file
sub write {
	my $self = shift;
	my $file = shift || undef;

	if ($self->{resolved} == 0) {
		$self->resolve();
	}

	$file = $self->{data_dir}.'/'.$Cache_Prefix.'.'.$self->{afi}.'.yaml' if (!defined $file);
	my $yaml = YAML::Tiny->read( $file );
	if (!defined $yaml) {
		$yaml = new YAML::Tiny();
	}
	$yaml->[0]->{ $self->{asn} } = {};
	$yaml->[0]->{ $self->{asn} }->{'asn_list'} = $self->get_asn_list();
	$yaml->[0]->{ $self->{asn} }->{'route_list'} = $self->get_route_list();
	$yaml->write( $file );
}


# returns a list ref with all ases behind given rpsl expression
# taking into account exceptions
sub get_asn_list {
	my $self = shift;
	if ($self->{resolved} == 0) {
		$self->resolve();
	}
	my @as_list = keys %{ $self->{data} };
	@as_list = sort {$a <=> $b} map { s/AS//; $_ } grep { /^\d+$/ } @as_list;
	return \@as_list;
}


# returns a list ref with all routes behind given rpsl expression
# taking into account exceptions
sub get_route_list {
	my $self = shift;
	my $asn = shift || undef;
	if ($self->{resolved} == 0) {
		$self->resolve();
	}
	my $list = {};
	if (!defined $asn) {
		# return a flat list
		foreach ( keys %{ $self->{data} } ) {
			foreach ( keys %{ $self->{data}->{$_} } ) {
				$list->{$_} = 1;
			}
		}
	}
	my @routes;
	if ($self->{afi} eq 'ipv4') {
		@routes = map  { $_->[0] }
				sort { $a->[1] cmp $b->[1] }
				map  { [$_, sprintf("%03.f%03.f%03.f%03.f", split(/[\.\/]/, $_))] }
				keys %{ $list };
	}
	elsif ($self->{afi} eq 'ipv6') {
		@routes = map  { $_->[0] }
				sort { $a->[1] cmp $b->[1] }
				map  { [$_, sprintf("%04s%04s%04s%04s", split(/[:\/]/, $_))] }
				keys %{ $list };
	}
	else {
		@routes = sort keys %{ $list };
	}
	return \@routes;
}


# Loads as data (as and route list).
# Fetches data from IRR if refresh = 1
# In tree mode each as has its routes looked up and stored in a tree structure.
# In flat mode routes are looked up for entire rpsl expression and stored in a
# flat list.
# Takes into account exceptions.
sub resolve {
	my $self = shift;
	# get data from IRR only if requested
	if ($self->{refresh} == 1) {
		$self->{data} = {};
		$self->as_set_to_as();
		if ($self->{flat} == 0) {
			foreach ( keys %{ $self->{data} } ) {
				$self->as_to_routes($_);
			}
		}
		else {
			$self->as_to_routes();
		}
	}
	# do exceptions
	$self->exceptions();
	$self->{resolved} = 1;
}


# Resolves given rpsl expression at IRR to a list of ases.
sub as_set_to_as {
	my $self = shift;
	my $as_set = shift || $self->{rpsl};
	my $arg = sprintf("-no-as 'afi %s.unicast %s'", $self->{afi}, $as_set);

	my $output = '';
	$self->_do_cmd($arg, \$output);

	my @list = ();
	if ($output !~ /NOT ANY/) {
		$output =~ s/[\(\)\{\}]//g;
		$output =~ s/[,\n]/ /g;
		$output =~ s/[\s]*AS([0-9]+)[\s]*/$1 /g;
		@list = split(/\s+/, $output);
	}
	@{ $self->{data} }{ @list } = (undef) x @list;
}


# Resolves given rpsl expression at IRR to a list of routes.
sub as_to_routes {
	my $self =shift;
	my $asn = shift || $self->{rpsl};
	my $arg = sprintf("'afi %s.unicast %s'", $self->{afi}, $asn);

	my $output = '';
	$self->_do_cmd($arg, \$output);

	my @list = ();
	if ($output !~ /NOT ANY/) {
		$output =~ s/[\(\)\{\}]//g;
		$output =~ s/[,\n]/ /g;
		@list = split(/\s+/, $output);
	}
	@{ $self->{data}->{$asn} }{@list} = (1) x @list;
}


# Calls an apropriate exception function based on flat mode value.
sub exceptions {
	my $self = shift;

	if ($self->{flat}) {
		$self->_exceptions_flat();
	}
	else {
		$self->_exceptions_tree();
	}
}


# Adds or removes ases and routes based on data in exception file.
# Routes to delete will not be deleted in flat mode unles the originating
# AS value is "ANY".
sub _exceptions_flat {
	my $self = shift;
	my $me = $self->{asn};

	my $to_add = $self->{exceptions}->{$me}->{add};
	my $to_delete = $self->{exceptions}->{$me}->{delete};

	# add entries
	foreach ( keys %{ $to_add } ) {
		my $asn = $_;
		$asn =~ s/AS//;
		foreach ( @{ $to_add->{$_} } ) {
			$self->{data}->{ $self->{rpsl} }->{$_} = 1;
			$self->{data}->{$asn} = {};
		}
	}

	# delete entries
	# in flat list we cannot determine an origin of prefix
	# so leave them in but warn user
	foreach ( keys %{ $to_delete } ) {
		my $asn = $_;
		$asn =~ s/AS//;
		if ($_ eq "ANY") {
			foreach ( @{ $to_delete->{$_} } ) {
				my $route = $_;
				foreach ( keys %{ $self->{data} } ) {
					delete $self->{data}->{$_}->{$route};
				}
			}
		}
		next if ( !exists $self->{data}->{$asn} );
		if ( $to_delete->{$_} eq "ALL" ) {
			delete $self->{data}->{$asn};
			next;
		}
		foreach ( @{ $to_delete->{$_} } ) {
			carp "Will not delete route exception [$_] from [AS$asn] in flat mode.";
		}
	}
}


# Adds or removes ASes and routes based on data in exception file.
sub _exceptions_tree {
	my $self = shift;
	my $me = $self->{asn};

	my $to_add = $self->{exceptions}->{$me}->{add};
	my $to_delete = $self->{exceptions}->{$me}->{delete};

	# add entries
	foreach ( keys %{ $to_add } ) {
		my $asn = $_;
		$asn =~ s/AS//;
		foreach ( @{ $to_add->{$_} } ) {
			$self->{data}->{$asn}->{$_} = 1;
		}
	}

	# delete entries
	foreach ( keys %{ $to_delete } ) {
		my $asn = $_;
		$asn =~ s/AS//;
		if ($_ eq "ANY") {
			foreach ( @{ $to_delete->{$_} } ) {
				my $route = $_;
				foreach ( keys %{ $self->{data} } ) {
					delete $self->{data}->{$_}->{$route};
				}
			}
		}
		next if ( !exists $self->{data}->{$asn} );
		if ( $to_delete->{$_} eq "ALL" ) {
			delete $self->{data}->{$asn};
			next;
		}
		foreach ( @{ $to_delete->{$_} } ) {
			delete $self->{data}->{$asn}->{$_};
		}
	}
}


# Loads current AS data from irr-cache YAML file.
sub _load_data_file {
	my $self = shift;
	my $data_path = $self->{data_dir}.'/'.$Cache_Prefix.'.'.$self->{afi}.'.yaml';
	my $yaml = YAML::Tiny->read( $data_path );
	if (!defined $yaml || !defined $yaml->[0]->{ $self->{asn} }) {
		return;
	}
	my $asn_list = $yaml->[0]->{ $self->{asn} }->{asn_list};
	my $route_list = $yaml->[0]->{ $self->{asn} }->{route_list};
	$self->{data} = {};
	@{ $self->{data} }{ @{ $asn_list } } = (undef) x @{ $asn_list };
	$self->{data}->{ $self->{rpsl} } = {};
	@{ $self->{data}->{ $self->{rpsl} } }{ @{ $route_list } } = (1) x @{ $route_list };
}


# Loads data from exceptions file.
sub _load_exceptions {
	my $self = shift;
	my $exception_path = $self->{data_dir}.'/'.$Exceptions_Prefix.'.'.$self->{afi}.'.yaml';
	my $yaml = YAML::Tiny->read( $exception_path );
	$self->{exceptions} = $yaml->[0];
}


# Runs an external command. Its output is saved in $output string ref.
# Dies if command exit code > 0.
sub _do_cmd {
	my $self = shift;
	my $arg = shift;
	my $output = shift;
	my ($stdin, $stdout, $stderr);
	my $cmd = sprintf("%s %s %s", $self->{peval_bin}, $self->{arg_base}, $arg);

	print "$cmd\n" if $self->{debug};

	open(CMDOUTPUT, "$cmd |");
	$$output = <CMDOUTPUT>;
	close(CMDOUTPUT);

	my $exit_code = $? >> 8;
	print "child exit code: $exit_code\n" if $self->{debug};

	if ($exit_code > 0) {
		die "ERROR running [$cmd]. Exit code: $exit_code\n";
	}

	if ($self->{debug}) {
		print "-----\nRaw stdout:\n";
		print $$output;
		print "-----\n";
	}
}

1;

__END__

=pod

=head1 NAME

Net::IRR::Cache - Cache results from Internet Routing Registy for later use

=head1 PREAMBLE

This library fetches data from an Internet Routing Registry (IRR) such as RIPE
or RADB. Data can be cached in a YAML file for later use by other tools like
building BGP peering filters.

=head1 SYNOPSIS

    use Net::IRR::Cache;

    # Get fresh data for AS set AS-ARNES
    my $irr_fetcher = Net::IRR::Cache->load(
        afi       => 'ipv6',
        asn       => 'AS2107',
        rpsl      => 'AS-ARNES',
        data_dir  => '/tmp',
        refresh   => 1,
    );

    # Get a list of IPv6 routes contained in configured AS-SET
    $routes = $irr_fetcher->get_route_list();

    # Save fetched AS and route info to cache file
    $irr_fetcher->write();

=head1 DESCRIPTION

Net::IRR::Cache provides a way to cache data from IRR databases and allows for
small local modifications like adding or removing single prefixes from IRR data.

Data is looked up for a given RPSL expression. The result is a list of AS
numbers and route (or route6) objects contained in a given RPSL expression. The
data can be further filtered by suplying ASes and routes to add or delete from
IRR data in a YAML exception file. Finally data can be stored in a YAML data
file for later use.

To simplify reading cached IRR data as much as possible a L<Net::IRR::Read>
module is also provided.

Fetching data from IRR is implemented via peval from IRRtoolset mantained by ISC
and can be obtained at:
L<http://www.isc.org/software/irrtoolset>

=head1 METHODS

=head2 load

The C<load> constructor loads data eather from an IRR database or from an
existing cache. It also reads the exception file and removes or adds entries to
the IRR data.

The given RPSL expression is evaluated for a list of AS numbers and routes
contained within.

C<load> methods accepts the following named arguments:

=over

=item * afi => Address family to operate on. ipv4 or ipv6.

=item * asn => AS number of entity we are fetching data for.

=item * rpsl => RPSL expression to resolve.

=item * irrconfig => Hashref wirg IRR host data (must have keys: host, source,
protocol). Defaults to RIPE IRR database.

=item * refresh => Load data from IRR or use cached values in irr-cache.

=item * peval_bin => Path to peval binary. Defaults to C</usr/bin/peval>.

=item * flat => All retrieved routes in a single list, discarding originating AS
information (default). If set to false routes will be stored in a hash where the
key is the AS the route belongs to. Setting this to false is experimental and
will probably not work correctly.

=item * data_dir => Directory path to read and write files from.

=item * debug => Print debugging output to STDOUT.

=back

=head2 write $file

Writes data in the current object to a cache file.

Data is written to a YAML file with the current ASN as key. This key contains
two more keys: asn_list with all AS numbers loaded and route_list with all IPv4
or IPv6 prefixes.

Any existing data in the cache file current ASN is removed before writing new
data. All other data in the file is preserved. (Limitations of L<YAML::Tiny>
module apply.)

If you do not specify a file to wite to, the destination is generated based on
C<$Data_Dir>, C<$Cache_Prefix> and current address family. For example:
C</tmp/irr-cache.ipv6.yaml>.

=head2 get_asn_list

Return a listref with loaded AS numbers for current ASN and AFI.

=head2 get_route_list

Return a listref with loaded routes for current ASN and AFI.

=head1 AUTHOR

Matej Vadnjal E<lt>matej@vadnjal.netE<gt>

=head1 COPYRIGHT

Copyright 2012 Matej Vadnjal.

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.

=cut

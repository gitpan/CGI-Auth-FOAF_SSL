package CGI::Auth::FOAF_SSL::CertifiedThing;

use RDF::Query;
use RDF::Query::Client;
use RDF::Trine;

our $VERSION = '0.52';

sub new
{
	my $class = shift;
	my $this  = {};

	$this->{'identity'}    = shift;
	$this->{'model'}       = shift;
	$this->{'endpoint'}    = shift;

	bless $this, $class;
}

sub identity
{
	my $this = shift;
	return $this->{'identity'};
}

sub model
{
	my $this = shift;
	return $this->{'model'};
}

sub endpoint
{
	my $this = shift;
	return $this->{'endpoint'};
}

sub getter
{
	my $this  = shift;
	my $key   = shift;
	my @preds = @_;
	
	PREDICATE: foreach my $p (@preds)
	{
		last PREDICATE
			if defined $this->{ $key };
		
		my $query_string = sprintf("SELECT ?x WHERE { <%s> <%s> ?x . } ORDER BY ?x", $this->identity, $p);
		my $results;
		
		if (defined $this->model)
		{
			my $query = RDF::Query->new($query_string);
			$results  = $query->execute($this->model);
		}
		elsif (defined $this->endpoint)
		{
			my $query = RDF::Query::Client->new($query_string);
			$results  = $query->execute($this->endpoint, {QueryMethod=>'POST'});
		}
		
		RESULT: while (my $row = $results->next)
		{
			last RESULT
				if defined $this->{ $key };
			
			my $node = $row->{'x'};
		
			if (defined $node and $node->is_resource)
				{ $this->{ $key } = $node->uri; }
			elsif (defined $node and $node->is_literal)
				{ $this->{ $key } = $node->literal_value; }
		}
	}
	
	return $this->{ $key };
}

1;

__END__

=head1 NAME

CGI::Auth::FOAF_SSL::CertifiedThing - a resource (in the RDFS sense)

=head1 SYNOPSIS

  my $auth = CGI::Auth::FOAF_SSL->new_from_cgi;
  if ($auth->is_secure)
  {
    my $thing = $auth->certified_thing;
    if ($thing)
    {
      my $webid = $thing->identity;
    }
  }

=head1 DESCRIPTION

=head2 Constructor

=over 4

=item C<< $thing = CGI::Auth::FOAF_SSL::CertifiedThing->new($id, $model, $ep) >>

Create a new object representing something. $id is an identfying URI, and is
required. $model is an RDF::Trine::Model containing data about the thing, or
may be undef. $ep is a SPARQL endpoint URL, or may be undef.

=back

=head2 Public Methods

=over 4

=item C<< $thing->identity >>

Returns the URI identifying the thing.

=item C<< $thing->model >>

Returns an RDF::Trine::Model which may contain data about the thing.

=item C<< $thing->endpoint >>

Returns a URL for a SPARQL Protocol endpoint that may be able to provide data
about the thing.

=back

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 SEE ALSO

L<CGI::Auth::FOAF_SSL>.

=head2 Subclasses

=over 4

=item * L<CGI::Auth::FOAF_SSL::Agent>

=item * L<CGI::Auth::FOAF_SSL::OnlineAccount>

=back

=head1 AUTHOR

Toby Inkster, E<lt>tobyink@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009-2010 by Toby Inkster

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8 or,
at your option, any later version of Perl 5 you may have available.

=cut


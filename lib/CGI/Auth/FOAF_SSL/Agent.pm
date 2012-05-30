package CGI::Auth::FOAF_SSL::Agent;

use RDF::Query;
use RDF::Query::Client;
use RDF::Trine;

our $VERSION = '1.003';

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

sub _getter
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

sub name
{
	my $this = shift;
	return $this->_getter('name',
		'http://xmlns.com/foaf/0.1/name',
		'http://www.w3.org/2000/01/rdf-schema#label',
		'http://xmlns.com/foaf/0.1/nick');
}

sub homepage
{
	my $this = shift;
	return $this->_getter('homepage',
		'http://xmlns.com/foaf/0.1/homepage',
		'http://xmlns.com/foaf/0.1/weblog',
		'http://xmlns.com/foaf/0.1/page');
}

sub img
{
	my $this = shift;
	return $this->_getter('img',
		'http://xmlns.com/foaf/0.1/img',
		'http://xmlns.com/foaf/0.1/depiction');
}

sub mbox
{
	my $this = shift;
	return $this->_getter('mbox',
		'http://xmlns.com/foaf/0.1/mbox');
}

1;

__END__

=head1 NAME

CGI::Auth::FOAF_SSL::Agent - an agent (in the FOAF sense)

=head1 SYNOPSIS

  my $auth = CGI::Auth::FOAF_SSL->new_from_cgi;
  if ($auth->is_secure)
  {
    my $person = $auth->agent;
    if ($person)
    {
      my $name = $person->name;
      my $link = $person->homepage;
    }
  }

=head1 DESCRIPTION

=head2 Constructor

=over 4

=item C<< new($webid, $model, $endpoint) >>

Create a new object representing an agent. $webid is an identfying URI, and is
required. $model is an RDF::Trine::Model containing data about the agent, or
may be undef. $endpoint is a SPARQL endpoint URL, or may be undef.

=back

=head2 Public Methods

=over 4

=item C<< identity >>

Returns the URI identifying the agent.

=item C<< model >>

Returns an RDF::Trine::Model which may contain data about the agent.

=item C<< endpoint >>

Returns a URL for a SPARQL Protocol endpoint that may be able to provide data
about the agent.

=item C<< name >>

The name of an agent (e.g. a person's name).

=item C<< homepage >>

Gets the URL of the agent's homepage.

=item C<< img >>

Gets the URL of an image or depiction of the agent.

=item C<< mbox >>

Gets an e-mail address (including "mailto:") to communicate with
the agent.

=back

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 SEE ALSO

L<CGI::Auth::FOAF_SSL>.

=head1 AUTHOR

Toby Inkster, E<lt>tobyink@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009-2011 by Toby Inkster

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut


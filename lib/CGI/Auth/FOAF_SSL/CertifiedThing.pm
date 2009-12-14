package CGI::Auth::FOAF_SSL::CertifiedThing;

use RDF::Query;
use RDF::Query::Client;
use RDF::Trine;

BEGIN {
	$CGI::Auth::FOAF_SSL::CertifiedThing::VERSION = '0.50';
}

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


package CGI::Auth::FOAF_SSL::CertifiedThing;

BEGIN {
	$CGI::Auth::FOAF_SSL::CertifiedThing::VERSION = '0.01';
}

sub new
{
	my $class = shift;
	my $this  = {};

	$this->{'identity'} = shift;
	$this->{'model'}    = shift;

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

sub getter
{
	my $this  = shift;
	my $key   = shift;
	my @preds = @_;
	
	PREDICATE: foreach my $p (@preds)
	{
		last PREDICATE if defined $this->{ $key };
		
		my $query_string = sprintf("SELECT ?x WHERE { <%s> <%s> ?x . }", $this->identity, $p);
		my $query = RDF::Redland::Query->new($query_string,
			RDF::Redland::URI->new($this->identity),
			undef,
			"sparql");
			
		my $results = $this->model->query_execute($query);
		RESULT: while (!($results->finished || defined $this->{ $key }))
		{
			my $node = $results->binding_value(0);
		
			if ($node->type == $RDF::Redland::Node::Type_Resource)
				{ $this->{ $key } = $node->uri->as_string; }
			elsif ($node->type == $RDF::Redland::Node::Type_Literal)
				{ $this->{ $key } = $node->literal_value; }
		}
	}
	
	return $this->{ $key };
}

1;


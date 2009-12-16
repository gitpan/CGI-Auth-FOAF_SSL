package CGI::Auth::FOAF_SSL::Agent;

use CGI::Auth::FOAF_SSL::CertifiedThing;
@ISA = qw(CGI::Auth::FOAF_SSL::CertifiedThing);

BEGIN {
	$CGI::Auth::FOAF_SSL::Agent::VERSION = '0.52';
}

sub name
{
	my $this = shift;
	return $this->getter('name',
		'http://xmlns.com/foaf/0.1/name',
		'http://www.w3.org/2000/01/rdf-schema#label',
		'http://xmlns.com/foaf/0.1/nick');
}

sub homepage
{
	my $this = shift;
	return $this->getter('homepage',
		'http://xmlns.com/foaf/0.1/homepage',
		'http://xmlns.com/foaf/0.1/weblog',
		'http://xmlns.com/foaf/0.1/page');
}

sub img
{
	my $this = shift;
	return $this->getter('img',
		'http://xmlns.com/foaf/0.1/img',
		'http://xmlns.com/foaf/0.1/depiction');
}

sub mbox
{
	my $this = shift;
	return $this->getter('mbox',
		'http://xmlns.com/foaf/0.1/mbox');
}

1;


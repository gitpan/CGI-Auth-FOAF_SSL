package CGI::Auth::FOAF_SSL::OnlineAccount;

use CGI::Auth::FOAF_SSL::CertifiedThing;
@ISA = qw(CGI::Auth::FOAF_SSL::CertifiedThing);

BEGIN {
	$CGI::Auth::FOAF_SSL::OnlineAccount::VERSION = '0.01';
}

sub name
{
	my $this = shift;
	return $this->getter('name',
		'http://xmlns.com/foaf/0.1/accountName');
}

sub homepage
{
	my $this = shift;
	return $this->getter('homepage',
		'http://xmlns.com/foaf/0.1/accountServiceHomepage');
}

1;


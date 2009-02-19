package CGI::Auth::FOAF_SSL;

BEGIN {
	$CGI::Auth::FOAF_SSL::VERSION = '0.02';
}

=head1 NAME

CGI::Auth::FOAF_SSL - Authentication using FOAF+SSL.

=head1 VERSION

0.02

=head1 SYNOPSIS

 use CGI qw(:all);
 use CGI::Auth::FOAF_SSL;
  
 my $cgi  = CGI->new;
 my $auth = CGI::Auth::FOAF_SSL->new_from_cgi($cgi);
  
 print header("text/html");
  
 if (defined $auth && defined $auth->agent)
 {
 	printf("<p>Hello <a href='%s'>%s</a>! You are logged on with FOAF+SSL.</p>\n",
 		escapeHTML($auth->agent->homepage),
 		escapeHTML($auth->agent->name));
 }
 elsif (defined $auth && $auth->is_secure)
 {
 	print "<p>Hello! You are logged on with FOAF+SSL.</p>\n";
 }
 else
 {
 	print "<p>Greetings stranger. You are unknown in these parts.</p>\n";
 }

=head1 DESCRIPTION

FOAF+SSL is a simple authentication scheme described at
L<http://esw.w3.org/topic/foaf+ssl>. This module provides FOAF+SSL
authentication for CGI scripts.

This requires the web server to be using HTTPS and to be configured to request
client certificates. If you are using Apache, this means that you want to set
the "SSLVerifyClient" directive to "require".

=cut

use Carp;
use CGI::Auth::FOAF_SSL::OnlineAccount;
use CGI::Auth::FOAF_SSL::Agent;
use IPC::Open2;
use LWP::UserAgent;
use RDF::Redland;
use 5.010000;
use strict;
use warnings;

=head1 CONFIGURATION

=over 8

=item $CGI::Auth::FOAF_SSL::path_openssl = '/usr/bin/openssl'

Set the path to the OpenSSL binary.

=item $CGI::Auth::FOAF_SSL::ua_string = 'MyTool/1.0'

Set the User-Agent string for any HTTP requests.

=cut

BEGIN {
	$CGI::Auth::FOAF_SSL::path_openssl = '/usr/bin/openssl';
	$CGI::Auth::FOAF_SSL::ua_string    = "CGI::Auth::FOAF_SSL/" 
	                                   . $CGI::Auth::FOAF_SSL::VERSION
	                                   . " ";
}

=back

=head1 CONSTRUCTORS

=over 8

=item $auth = CGI::Auth::FOAF_SSL->new($pem_encoded)

Performs FOAF+SSL authentication on a PEM-encoded key. If authentication is
completely unsuccessful, returns undef. Otherwise, returns a CGI::Auth::FOAF_SSL
object. Use C<is_secure> to check if authentication was completely successful.

You probably want to use C<new_from_cgi> instead.

=cut

sub new
{
	my $rv = new_smiple(@_);
	$rv->verify_certificate;
	$rv->load_personal_info;
	return $rv;
}

=item $auth = CGI::Auth::FOAF_SSL->new_from_cgi($cgi_object)

Performs FOAF+SSL authentication on a CGI object. This is a wrapper around
C<new> which extracts the PEM-encoded client certificate from the CGI
request. It has the same return values as C<new>.

=cut

sub new_from_cgi
{
	my $class = shift;
	my $cgi   = shift;
	
	return undef unless ($cgi->https);
	return new($class, $cgi->https('SSL_CLIENT_CERT'));
}

=item $auth = CGI::Auth::FOAF_SSL->new_smiple($pem_encoded)

Performs FOAF+SSL authentication on a PEM-encoded key. This is faster than the
usual constructor but performs fewer of the usual checks.

You probably want to use C<new_from_cgi> instead.

=cut

sub new_smiple
{
	my $class = shift;
	my $cert  = shift;
	my $rv    = {};
	
	# Only client certificate secured connections allowed.
	return unless $cert; 
	
	# We use OpenSSL to parse the client certificate. There is an OpenSSL module
	# in CPAN, but it's poorly documented, so we'll just use the command-line
	# client instead. You may want to provide a full path here...
	my $openssl = $CGI::Auth::FOAF_SSL::path_openssl;
	
	# First check certificate dates.
	my $pid = open2(\*READ, \*WRITE, "$openssl x509 -checkend 0");
	croak "Could not use openssl!\n" unless $pid > 0;
	print WRITE "$cert\n";
	my $response = <READ>;
	return unless $response =~ /will not expire/;
	close READ;
	close WRITE;

	# Check certificate extensions. It's ugly but should work...
	$pid = 0;
	$pid = open2(\*READ, \*WRITE, "$openssl x509 -text");
	croak "Could not use openssl!\n" unless $pid > 0;
	print WRITE "$cert\n";
	my $exponent_line;
	while (<READ>)
	{
		$exponent_line = $_ if (/^                Exponent: /);
		last if (/^            Netscape Cert Type:/);
	}
	my $usages = <READ>;
	$usages =~ s/(^\s*|\s*\r?\n?$)//g;
	while (<READ>)
		{ last if (/^            X509v3 Subject Alternative Name:/); }
	my $alt_name = <READ>; 
	$alt_name =~ s/(^\s*|\s*\r?\n?$)//g;
	close READ;
	close WRITE;

	# Unless certificate is specifically allowed to be used for HTTPS, then
	# reject it.
	return unless $usages =~ /SSL Client/i;
	
	# Only allow FOAF+SSL certificates.
	return unless $alt_name =~ /^URI:(.+)$/i;
	$rv->{'cert_subject_uri'} = $1;
	
	# Modulus.
	$pid = 0;
	$pid = open2(\*READ, \*WRITE, "$openssl x509 -modulus");
	croak "Could not use openssl!\n" unless $pid > 0;
	print WRITE "$cert\n";
	$response = <READ>;
	close READ;
	close WRITE;
	return unless $response =~ /^Modulus=([0-9A-F]+)$/i;
	$rv->{'cert_modulus_hex'} = $1;
	
	# Exponent.
	return unless $exponent_line =~ /Exponent: (\d+) \(0x([0-9A-F]+)\)/i;
	$rv->{'cert_exponent_dec'} = $1;
	$rv->{'cert_exponent_hex'} = $2;	
	
	$rv->{'validation'} = 1;
	
	bless $rv, $class;
}

=back

=head1 PUBLIC METHODS

=over 8

=item $auth->verify_certificate

This loads the certificate subject URI and checks that the URI confirms
the certificate's details. If you constructed the object with C<new> or
C<new_from_cgi>, then you do not need to call this. It is only useful if
you constructed the object using C<new_smiple>.

Returns true iff the certificate checks out correctly.

=cut

sub verify_certificate
{
	my $rv = shift;
	return 0 unless ((defined $rv) && ($rv->{'validation'} >= 1));

	my $ua       = LWP::UserAgent->new(agent=>$CGI::Auth::FOAF_SSL::ua_string); 
	my $response = $ua->get($rv->{'cert_subject_uri'});
	
	my $account  = RDF::Redland::URI->new($rv->{'cert_subject_uri'});
	my $storage  = RDF::Redland::Storage->new("hashes", "test", "new='yes',hash-type='memory'");
	my $model    = RDF::Redland::Model->new($storage, "");	
	my $parser   = RDF::Redland::Parser->new(undef, $response->header('content-type'));
	$parser->parse_string_into_model($response->content, $account, $model);
	
	$rv->{'cert_subject_model'} = $model;
	
	my $query_string = sprintf("SELECT ?decExponent ?hexModulus "
	                          ."WHERE { "
	                          ."    ?key <http://www.w3.org/ns/auth/cert#identity> <%s> . "
	                          ."    ?key <http://www.w3.org/ns/auth/rsa#modulus> ?modulus . "
	                          ."    ?modulus <http://www.w3.org/ns/auth/cert#hex> ?hexModulus . "
	                          ."    ?key <http://www.w3.org/ns/auth/rsa#public_exponent> ?exponent . "
	                          ."    ?exponent <http://www.w3.org/ns/auth/cert#decimal> ?decExponent . "
	                          ."}",
	                          $rv->{'cert_subject_uri'});
	my $query   = RDF::Redland::Query->new($query_string, $account, undef, "sparql");
	my $results = $model->query_execute($query);
	if (!$results->finished)
	{
		$rv->{'correct_cert_exponent_dec'} = $results->binding_value(0)->literal_value;
		$rv->{'correct_cert_modulus_hex'}  = $results->binding_value(1)->literal_value;
	}

	$rv->{'correct_cert_exponent_dec'} =~ s/[^0-9]//ig;
	$rv->{'correct_cert_modulus_hex'}  =~ s/[^A-Z0-9]//ig;
	$rv->{'correct_cert_modulus_hex'}  = uc($rv->{'correct_cert_modulus_hex'});

	if (($rv->{'correct_cert_modulus_hex'} eq $rv->{'cert_modulus_hex'})
	&&  ($rv->{'correct_cert_exponent_dec'} == $rv->{'cert_exponent_dec'}))
	{
		$rv->{validation}++;
		delete $rv->{'correct_cert_exponent_dec'};
		delete $rv->{'correct_cert_modulus_hex'};
		return 1;
	}

	return 0;
}

=item $auth->load_personal_info

This loads the certificate subject URI and investigates that entity. If you
constructed the object with C<new> or C<new_from_cgi>, then you do not need
to call this. It is only useful if you constructed the object using
C<new_smiple>.

Returns true iff some personal or account details could be found.

=cut

sub load_personal_info
{
	my $rv = shift;
	
	return 0 unless ((defined $rv) && ($rv->{'validation'} >= 2));
	
	# List of RDF classes that the module understands.
	my @agentTypes   = ('http://xmlns.com/foaf/0.1/Person',
	                    'http://xmlns.com/foaf/0.1/Agent',
	                    'http://xmlns.com/foaf/0.1/Organisation',
	                    'http://xmlns.com/foaf/0.1/Group');
	my @accountTypes = ('http://xmlns.com/foaf/0.1/OnlineAccount',
	                    'http://xmlns.com/foaf/0.1/OnlineChatAccount',
	                    'http://xmlns.com/foaf/0.1/OnlineGamingAccount',
	                    'http://xmlns.com/foaf/0.1/OnlineEcommerceAccount',
	                    'http://rdfs.org/sioc/ns#User');

	# Check to see if this 	
	my $query_string = sprintf("SELECT ?type "
	                          ."WHERE { "
	                          ."    <%s> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type'> ?type . "
	                          ."}",
	                          $rv->{'cert_subject_uri'});
	my $query   = RDF::Redland::Query->new($query_string, RDF::Redland::URI->new($rv->{'cert_subject_uri'}), undef, "sparql");
	my $results = $rv->{'cert_subject_model'}->query_execute($query);
	
	RESULT: while (!$results->finished)
	{
		my $type = $results->binding_value(0)->uri->as_string;
		
		foreach my $t (@agentTypes)
		{
			if ($type eq $t)
			{
				$rv->{'cert_subject_type'} = 'Agent';
				last RESULT;
			}
		}
		
		foreach my $t (@accountTypes)
		{
			if ($type eq $t)
			{
				$rv->{'cert_subject_type'} = 'OnlineAccount';
				last RESULT;
			}
		}
		
		$results->next_result;
	}

	# No explicit rdf:type.
	# Might be able to figure it out from existence of certain predicates:
	#      - foaf:holdsAccount
	#      - foaf:accountServiceHomepage
	#      - foaf:accountName
	#      - http://rdfs.org/sioc/ns#account_of

	my $retrievedAgentUri;

	if (!defined $rv->{'cert_subject_type'}
	||  $rv->{'cert_subject_type'} eq 'OnlineAccount')
	{
		my $query = RDF::Redland::Query->new(
			sprintf('SELECT ?person WHERE { <%s> <http://rdfs.org/sioc/ns#account_of> ?person . }', $rv->{'cert_subject_uri'}),
			RDF::Redland::URI->new($rv->{'cert_subject_uri'}),
			undef,
			'sparql');
		my $results = $rv->{'cert_subject_model'}->query_execute($query);
		if (!$results->finished)
		{
			$rv->{'cert_subject_type'} = 'OnlineAccount';
			$retrievedAgentUri = $results->binding_value(0)->uri->as_string
				unless defined $retrievedAgentUri;
		}
	}

	if (!defined $rv->{'cert_subject_type'}
	||  $rv->{'cert_subject_type'} eq 'OnlineAccount')
	{
		my $query = RDF::Redland::Query->new(
			sprintf('SELECT ?person WHERE { ?person <http://xmlns.com/foaf/0.1/holdsAccount> <%s> . }', $rv->{'cert_subject_uri'}),
			RDF::Redland::URI->new($rv->{'cert_subject_uri'}),
			undef,
			'sparql');
		my $results = $rv->{'cert_subject_model'}->query_execute($query);
		if (!$results->finished)
		{
			$rv->{'cert_subject_type'} = 'OnlineAccount';
			$retrievedAgentUri = $results->binding_value(0)->uri->as_string
				unless defined $retrievedAgentUri;
		}
	}

	unless (defined $rv->{'cert_subject_type'})
	{
		my $query = RDF::Redland::Query->new(
			sprintf('ASK WHERE { <%s> <http://xmlns.com/foaf/0.1/accountName> ?o . }', $rv->{'cert_subject_uri'}),
			RDF::Redland::URI->new($rv->{'cert_subject_uri'}),
			undef,
			'sparql');
		my $results = $rv->{'cert_subject_model'}->query_execute($query);
		if ($results->get_boolean)
			{ $rv->{'cert_subject_type'} = 'OnlineAccount'; }
	}

	unless (defined $rv->{'cert_subject_type'})
	{
		my $query = RDF::Redland::Query->new(
			sprintf('ASK WHERE { <%s> <http://xmlns.com/foaf/0.1/accountServiceHomepage> ?o . }', $rv->{'cert_subject_uri'}),
			RDF::Redland::URI->new($rv->{'cert_subject_uri'}),
			undef,
			'sparql');
		my $results = $rv->{'cert_subject_model'}->query_execute($query);
		if ($results->get_boolean)
			{ $rv->{'cert_subject_type'} = 'OnlineAccount'; }
	}

	if (defined $rv->{'cert_subject_type'} 
	&&  $rv->{'cert_subject_type'} eq 'Agent')
	{
		$rv->{'agent'} = CGI::Auth::FOAF_SSL::Agent->new(
			$rv->{'cert_subject_uri'},
			$rv->{'cert_subject_model'});
			
		$rv->{'thing'} = $rv->{'agent'};

		return 1;
	}
	
	elsif (defined $rv->{'cert_subject_type'} 
	&&  $rv->{'cert_subject_type'} eq 'OnlineAccount')
	{
		$rv->{'account'} = CGI::Auth::FOAF_SSL::OnlineAccount->new(
			$rv->{'cert_subject_uri'},
			$rv->{'cert_subject_model'});

		$rv->{'thing'} = $rv->{'account'};

		if (defined $retrievedAgentUri)
		{
			my $ua       = LWP::UserAgent->new(agent=>$CGI::Auth::FOAF_SSL::ua_string); 
			my $response = $ua->get($retrievedAgentUri);
			
			my $account  = RDF::Redland::URI->new($retrievedAgentUri);
			my $storage  = RDF::Redland::Storage->new("hashes", "test", "new='yes',hash-type='memory'");
			my $model    = RDF::Redland::Model->new($storage, "");	
			my $parser   = RDF::Redland::Parser->new(undef, $response->header('content-type'));
			$parser->parse_string_into_model($response->content, RDF::Redland::URI->new($retrievedAgentUri), $model);
			
			$rv->{'agent'} = CGI::Auth::FOAF_SSL::Agent->new($retrievedAgentUri, $model);
		}
		
		return 1;
	}

	$rv->{'thing'} = CGI::Auth::FOAF_SSL::CertifiedThing->new(
		$rv->{'cert_subject_uri'},
		$rv->{'cert_subject_model'});

	return 0;
}

=item $bool = $auth->is_secure

Returns true iff the authentication process was completely successful.

=cut

sub is_secure
{
	my $this = shift;
	return ($this->{'validation'} >= 2);
}

=item $agent = $auth->agent

Returns an object which represents the agent making the request. This object
includes the following methods: C<name>, C<homepage>, C<mbox> and C<img>.

Another method included is C<identity> which returns the RDF URI representing
the agent.

=cut

sub agent
{
	my $this = shift;
	return $this->{'agent'};
}

=item $account = $auth->account

Returns an object which represents the account making the request. This object
includes the following methods: C<name>, C<homepage>.

Another method included is C<identity> which returns the RDF URI representing
the account.

=cut

sub account
{
	my $this = shift;
	return $this->{'account'};
}

=item $thing = $auth->certified_thing

Returns an object representing the thing which the certificate belongs to.
This object includes a method called C<identity> which returns its RDF URI.

Usually you will want to use C<agent> or C<account> instead.

=cut

sub certified_thing
{
	my $this = shift;
	return $this->{'thing'};
}

1;

__END__

=back

=head1 SEE ALSO

L<CGI>

L<http://esw.w3.org/topic/foaf+ssl>

=head1 AUTHOR

Toby Inkster, E<lt>mail@tobyinkster.co.ukE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Toby Inkster

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut

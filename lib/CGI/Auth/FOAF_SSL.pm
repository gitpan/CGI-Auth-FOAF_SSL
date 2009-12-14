package CGI::Auth::FOAF_SSL;

use 5.008001;
use strict;
use warnings;

BEGIN {
	$CGI::Auth::FOAF_SSL::VERSION = '0.50';
}

=head1 NAME

CGI::Auth::FOAF_SSL - Authentication using FOAF+SSL.

=head1 VERSION

0.50

=head1 SYNOPSIS

 use CGI qw(:all);
 use CGI::Auth::FOAF_SSL;
 
 my $cgi  = CGI->new;
 my $auth = CGI::Auth::FOAF_SSL->new_from_cgi($cgi);
 
 print header('-type' => 'text/html', '-cookie' => $auth->cookie);
 
 if (defined $auth && $auth->is_secure)
 {
 	if (defined $auth->agent)
 	{
 		printf("<p>Hello <a href='%s'>%s</a>! You are logged on with FOAF+SSL.</p>\n",
 			escapeHTML($auth->agent->homepage),
 			escapeHTML($auth->agent->name));
 	}
 	else
 	{
 		print "<p>Hello! You are logged on with FOAF+SSL.</p>\n";
 	}
 }
 else
 {
 	print "<p>Greetings stranger. You are unknown in these parts.</p>\n";
 }

=head1 DESCRIPTION

FOAF+SSL is a simple authentication scheme described at
L<http://esw.w3.org/topic/foaf+ssl>. This module provides FOAF+SSL
authentication for CGI scripts.

This requires the web server to be using HTTPS and to be configured to
request client certificates and to pass the certificate details on as
environment variables for scripts. If you are using Apache, this means
that you want to set the following directives in your SSL virtual host
setup:

 SSLEngine on
 # SSLCipherSuite (see Apache documentation)
 # SSLProtocol (see Apache documentation)
 # SSLCertificateFile (see Apache documentation)
 # SSLCertificateKeyFile (see Apache documentation)
 SSLVerifyClient optional_no_ca
 SSLVerifyDepth  1
 SSLOptions +StdEnvVars +ExportCertData
 
As of version 0.50, this package no longer uses RDF::Redland, using
RDF::Trine and RDF::Query instead.

=cut

use Carp;
use CGI;
use CGI::Auth::FOAF_SSL::OnlineAccount;
use CGI::Auth::FOAF_SSL::Agent;
use CGI::Session;
use IPC::Open2;
use LWP::UserAgent;
use RDF::RDFa::Parser 0.21;
use RDF::Query;
use RDF::Query::Client;
use RDF::Trine 0.111;
use RDF::Trine::Serializer::NTriples;
use WWW::Finger::Fingerpoint;

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
object. Use C<is_secure> to check if authentication was I<completely> successful.

You probably want to use C<new_from_cgi> instead.

=cut

sub new
{
	my $rv = new_smiple(@_);
	
	return undef unless $rv;
	
	my $verified = 0;
	if (defined $rv->{'subject_alt_names'}->{'URI'})
	{
		foreach my $uri (@{ $rv->{'subject_alt_names'}->{'URI'} })
		{
			$verified = $rv->verify_certificate_by_uri($uri);
			last if $verified;
		}
	}
	
	if (defined $rv->{'subject_alt_names'}->{'EMAIL'}
	and !$verified)
	{
		foreach my $e (@{ $rv->{'subject_alt_names'}->{'EMAIL'} })
		{
			$verified = $rv->verify_certificate_by_email($e);
			last if $verified;
		}
	}
	
	$rv->load_personal_info
		if $verified;
	
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
	
	return undef unless $cgi->https;
	
	# This should work, but doesn't!!
	# my $cert = $cgi->https('SSL_CLIENT_CERT');
	
	# This does work, but is less elegant.
	my $cert = $ENV{'SSL_CLIENT_CERT'};

	return $class->new($cert);
}

sub new_smiple
{
	my $class = shift;
	my $cert  = shift;
	my $opts  = shift;
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
		if ($opts->{'check_netscape_cert_type'})
		{
			last if (/^            Netscape Cert Type:/);
		}
		else
		{
			last if (/^            X509v3 Subject Alternative Name:/);
		}
	}
	if ($opts->{'check_netscape_cert_type'})
	{
		my $usages = <READ>;
		$usages =~ s/(^\s*|\s*\r?\n?$)//g;
		while (<READ>)
			{ last if (/^            X509v3 Subject Alternative Name:/); }

		# Unless certificate is specifically allowed to be used for HTTPS, then
		# reject it.
		return unless $usages =~ /SSL Client/i;
	}
	my $alt_name = <READ>; 
	$alt_name =~ s/(^\s*|\s*\r?\n?$)//g;
	close READ;
	close WRITE;

	# Only allow FOAF+SSL certificates.
	$rv->{'subject_alt_names'} = {};
	while ($alt_name =~ /(?:\s|\,|^)(URI|email):([^\s\,]+)(?:\s|\,|$)/ig)
	{
		push @{ $rv->{'subject_alt_names'}->{uc $1} }, $2;
	}
	
	return unless $rv->{'subject_alt_names'};

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

	bless $rv, $class;
}

sub verify_certificate_by_uri
{
	my $rv  = shift;
	my $uri = shift;
	
	my $model = $rv->get_trine_model($uri);
	
	my $query_string = sprintf("PREFIX cert: <http://www.w3.org/ns/auth/cert#> "
	                          ."PREFIX rsa: <http://www.w3.org/ns/auth/rsa#> "
	                          ."SELECT ?decExponent ?hexModulus "
	                          ."WHERE "
	                          ."{ "
	                          ."    ?key "
	                          ."        cert:identity <%s> ; "
	                          ."        rsa:modulus [ cert:hex ?hexModulus ] ; "
	                          ."        rsa:public_exponent [ cert:decimal ?decExponent ] . "
	                          ."}",
	                          $uri);
	my $query   = RDF::Query->new($query_string, $uri);
	my $results = $query->execute($model);
	
	if (my $row = $results->next)
	{
		$rv->{'correct_cert_exponent_dec'} = $row->{'decExponent'}->literal_value;
		$rv->{'correct_cert_modulus_hex'}  = $row->{'hexModulus'}->literal_value;
	}
	
	return 0
		unless $rv->{'correct_cert_modulus_hex'} && $rv->{'correct_cert_exponent_dec'};

	$rv->{'correct_cert_exponent_dec'} =~ s/[^0-9]//ig;
	$rv->{'correct_cert_modulus_hex'}  =~ s/[^A-Z0-9]//ig;
	$rv->{'correct_cert_modulus_hex'}  = uc($rv->{'correct_cert_modulus_hex'});

	if (($rv->{'correct_cert_modulus_hex'} eq $rv->{'cert_modulus_hex'})
	&&  ($rv->{'correct_cert_exponent_dec'} == $rv->{'cert_exponent_dec'}))
	{
		$rv->{'validation'} = 'cert';
		delete $rv->{'correct_cert_exponent_dec'};
		delete $rv->{'correct_cert_modulus_hex'};
		
		$rv->{'cert_subject_uri'}   = $uri;
		$rv->{'cert_subject_model'} = $model;
		
		return 1;
	}

	return 0;
}

sub verify_certificate_by_email
{
	my $rv    = shift;
	my $email = shift;
	
	my $fp = WWW::Finger::Fingerpoint->new($email);
	
	return 0
		unless defined $fp->endpoint and defined $fp->webid;

	my $query_string = sprintf("PREFIX cert: <http://www.w3.org/ns/auth/cert#> "
	                          ."PREFIX rsa: <http://www.w3.org/ns/auth/rsa#> "
	                          ."SELECT ?decExponent ?hexModulus "
	                          ."WHERE "
	                          ."{ "
	                          ."    ?key "
	                          ."        cert:identity <%s> ; "
	                          ."        rsa:modulus [ cert:hex ?hexModulus ] ; "
	                          ."        rsa:public_exponent [ cert:decimal ?decExponent ] . "
	                          ."}",
	                          $fp->webid);
									  
	my $query   = RDF::Query::Client->new($query_string);
	my $results = $query->execute($fp->endpoint, {QueryMethod=>'POST'});
	
	if (my $row = $results->next)
	{
		$rv->{'correct_cert_exponent_dec'} = $row->{'decExponent'}->literal_value;
		$rv->{'correct_cert_modulus_hex'}  = $row->{'hexModulus'}->literal_value;
	}
	
	return 0
		unless $rv->{'correct_cert_modulus_hex'} && $rv->{'correct_cert_exponent_dec'};

	$rv->{'correct_cert_exponent_dec'} =~ s/[^0-9]//ig;
	$rv->{'correct_cert_modulus_hex'}  =~ s/[^A-Z0-9]//ig;
	$rv->{'correct_cert_modulus_hex'}  = uc($rv->{'correct_cert_modulus_hex'});

	if (($rv->{'correct_cert_modulus_hex'} eq $rv->{'cert_modulus_hex'})
	&&  ($rv->{'correct_cert_exponent_dec'} == $rv->{'cert_exponent_dec'}))
	{
		$rv->{'validation'} = 'cert';
		delete $rv->{'correct_cert_exponent_dec'};
		delete $rv->{'correct_cert_modulus_hex'};
		
		$rv->{'cert_subject_uri'}         = $fp->webid;
		$rv->{'cert_subject_endpoint'}    = $fp->endpoint;
		$rv->{'cert_subject_fingerpoint'} = $fp;
		
		return 1;
	}

	return 0;
}

sub _exec_query 
{
	my $rv = shift;
	my $q  = shift;
	
	if (defined $rv->{'cert_subject_model'})
	{
		my $Q = RDF::Query->new($q);
		return $Q->execute($rv->{'cert_subject_model'});
	}
	
	if (defined $rv->{'cert_subject_endpoint'})
	{
		my $Q = RDF::Query::Client->new($q);
		return $Q->execute($rv->{'cert_subject_endpoint'}, {QueryMethod=>'POST'});
	}
}

sub load_personal_info
{
	my $rv = shift;
	
	return 0
		unless defined $rv and $rv->{'validation'} eq 'cert';
	
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

	# Check to see if $self->identity is a foaf:Agent or a foaf:OnlineAccount.
	my $query_string = sprintf("SELECT ?type "
	                          ."WHERE { "
	                          ."    <%s> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> ?type . "
	                          ."}",
	                          $rv->{'cert_subject_uri'});
	my $results = $rv->_exec_query( $query_string );
	
	RESULT: while (my $row = $results->next)
	{
		my $type = $row->{'type'}->uri;
		
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

	# No explicit rdf:type. :-(
	#
	# Might be able to figure it out from existence of certain predicates:
	#      - foaf:holdsAccount
	#      - foaf:accountServiceHomepage
	#      - foaf:accountName
	#      - http://rdfs.org/sioc/ns#account_of

	my $retrievedAgentUri;

	if (!defined $rv->{'cert_subject_type'}
	||  $rv->{'cert_subject_type'} eq 'OnlineAccount')
	{
		my $results = $rv->_exec_query(
			sprintf('SELECT ?person WHERE { <%s> <http://rdfs.org/sioc/ns#account_of> ?person . }', $rv->{'cert_subject_uri'}),
			$rv->{'cert_subject_uri'});
			
		if (my $row = $results->next)
		{
			$rv->{'cert_subject_type'} = 'OnlineAccount';
			$retrievedAgentUri = $row->{'person'}->uri
				unless defined $retrievedAgentUri;
		}
	}

	if (!defined $rv->{'cert_subject_type'}
	||  $rv->{'cert_subject_type'} eq 'OnlineAccount')
	{
		my $results = $rv->_exec_query(
			sprintf('SELECT ?person WHERE { ?person <http://xmlns.com/foaf/0.1/holdsAccount> <%s> . }', $rv->{'cert_subject_uri'}),
			$rv->{'cert_subject_uri'});
			
		if (my $row = $results->next)
		{
			$rv->{'cert_subject_type'} = 'OnlineAccount';
			$retrievedAgentUri = $row->{'person'}->uri
				unless defined $retrievedAgentUri;
		}
	}

	unless (defined $rv->{'cert_subject_type'})
	{
		my $results = $rv->_exec_query(
			sprintf('ASK WHERE { <%s> <http://xmlns.com/foaf/0.1/accountName> ?o . }', $rv->{'cert_subject_uri'}),
			$rv->{'cert_subject_uri'});
		
		if ($results->is_boolean && $results->get_boolean)
			{ $rv->{'cert_subject_type'} = 'OnlineAccount'; }
	}

	unless (defined $rv->{'cert_subject_type'})
	{
		my $results = $rv->_exec_query(
			sprintf('ASK WHERE { <%s> <http://xmlns.com/foaf/0.1/accountServiceHomepage> ?o . }', $rv->{'cert_subject_uri'}),
			$rv->{'cert_subject_uri'});

		if ($results->is_boolean && $results->get_boolean)
			{ $rv->{'cert_subject_type'} = 'OnlineAccount'; }
	}

	if (defined $rv->{'cert_subject_type'} 
	&&  $rv->{'cert_subject_type'} eq 'Agent')
	{
		$rv->{'agent'} = CGI::Auth::FOAF_SSL::Agent->new(
			$rv->{'cert_subject_uri'},
			$rv->{'cert_subject_model'},
			$rv->{'cert_subject_endpoint'});
			
		$rv->{'thing'} = $rv->{'agent'};
		$rv->{'validation'} = 'agent';

		return 1;
	}
	
	elsif (defined $rv->{'cert_subject_type'} 
	&&  $rv->{'cert_subject_type'} eq 'OnlineAccount')
	{
		$rv->{'account'} = CGI::Auth::FOAF_SSL::OnlineAccount->new(
			$rv->{'cert_subject_uri'},
			$rv->{'cert_subject_model'},
			$rv->{'cert_subject_endpoint'});

		$rv->{'thing'} = $rv->{'account'};

		if (defined $retrievedAgentUri)
		{
			my $model = $rv->get_trine_model($retrievedAgentUri);
			$rv->{'agent'} = CGI::Auth::FOAF_SSL::Agent->new($retrievedAgentUri, $model);
			
			if ($model)
			{
				my $query = RDF::Query->new(
					sprintf('ASK WHERE { <%s> <http://xmlns.com/foaf/0.1/holdsAccount> <%s> . }',
						$retrievedAgentUri, $rv->{'cert_subject_uri'}),
					$retrievedAgentUri);
				my $results = $query->execute($model);
				if ($results->is_boolean && $results->get_boolean)
				{
					$rv->{'validation'} = 'agent';
				}
			}
		}
		
		return 1;
	}

	$rv->{'thing'} = CGI::Auth::FOAF_SSL::CertifiedThing->new(
		$rv->{'cert_subject_uri'},
		$rv->{'cert_subject_model'},
		$rv->{'cert_subject_endpoint'});

	return 0;
}

=back

=head1 PUBLIC METHODS

=over 8

=cut

=item $cookie = $auth->cookie

HTTP cookie related to the authentication process. Sending this to the
client isn't strictly necessary, but it allows for a session to be
established, greatly speeding up subsequent accesses.

=cut

sub cookie
{
	my $this = shift;
	return $this->{'session'}->cookie;
}

=item $bool = $auth->is_secure

Returns true iff the authentication process was completely successful.

=cut

sub is_secure
{
	my $this = shift;
	return ($this->{'validation'} eq 'agent');
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

=back

=head1 UTILITY METHOD

=over 8

=item $model = $auth->get_trine_model($uri);

Get an RDF::Trine::Model corresponding to a URI.

=cut

sub get_trine_model
{
	my $this = shift;
	my $uri  = shift;
	
	# Session for caching data into.
	unless (defined $this->{'session'})
	{
		$this->{'session'} = CGI::Session->new('driver:file', undef, {Directory=>'/tmp'});
		$this->{'session'}->expire('+1h');
	}
	
	# Check to see if this URI has already been retrieved.
	if (defined $this->{'session'}->param($uri)
	and length $this->{'session'}->param($uri))
	{
		my $parser = RDF::Trine::Parser::Turtle->new;
		my $model  = RDF::Trine::Model->new( RDF::Trine::Store->temporary_store );
		$parser->parse_into_model( $uri, $this->{'session'}->param($uri) , $model );
		return $model;
	}
	
	my $ua = LWP::UserAgent->new(agent=>$CGI::Auth::FOAF_SSL::ua_string); 
	$ua->default_headers->push_header('Accept' => "application/rdf+xml, application/xhtml+xml, text/html, text/turtle, application/x-turtle, */*");
	my $response = $ua->get($uri);
	return unless length $response->content;
	
	my $model;
	
	# If response is (X)HTML, parse using RDF::RDFa::Parser instead of Trine.
	if ($response->header('content-type')
		=~ m#^(text/html|application/xhtml.xml|image/svg(.xml)?)#i)
	{
		my $opts = $response->header('content-type') =~ m#^(image/svg(.xml)?)#i
			? RDF::RDFa::Parser::OPTS_SVG
			: RDF::RDFa::Parser::OPTS_XHTML ;
		my $parser = RDF::RDFa::Parser->new($response->decoded_content, $uri, $opts);
		$parser->consume;
		$model = $parser->graph;
	}

	# Not RDFa, so let Trine handle it as best it can.
	else
	{
			$model      = RDF::Trine::Model->new( RDF::Trine::Store->temporary_store );
			my $parser  = ($response->header('content-type') =~ /(n3|turtle|text.plain)/i)
							? RDF::Trine::Parser::Turtle->new
							: RDF::Trine::Parser::RDFXML->new;
			$parser->parse_into_model( $uri , $response->decoded_content , $model );
	}
	
	my $serializer = RDF::Trine::Serializer::NTriples->new();
	$this->{'session'}->param($uri,
		$serializer->serialize_model_to_string($model));
	$this->{'session'}->flush;
	
	return $model;
}

1;

__END__

=back

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 SEE ALSO

L<http://lists.foaf-project.org/mailman/listinfo/foaf-protocols>,
L<http://esw.w3.org/topic/foaf+ssl>.

L<CGI>, L<RDF::Trine>.

L<http://httpd.apache.org/docs/2.0/mod/mod_ssl.html>.

L<http://www.perlrdf.org/>.

=head1 AUTHOR

Toby Inkster, E<lt>tobyink@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009 by Toby Inkster

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.1 or,
at your option, any later version of Perl 5 you may have available.

=cut

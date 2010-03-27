package CGI::Auth::FOAF_SSL;

use 5.008;
use strict;
use warnings;

=head1 NAME

CGI::Auth::FOAF_SSL - authentication using FOAF+SSL

=head1 SYNOPSIS

  use CGI qw(:all);
  use CGI::Auth::FOAF_SSL;
  
  my $auth = CGI::Auth::FOAF_SSL->new_from_cgi( CGI->new );
  
  print header('-type' => 'text/html', '-cookie' => $auth->cookie);
  
  if (defined $auth && $auth->is_secure)
  {
    if (defined $auth->agent)
    {
      printf("<p>Hello <a href='%s'>%s</a>!</p>\n",
             escapeHTML($auth->agent->homepage),
             escapeHTML($auth->agent->name));
    }
    else
    {
      print "<p>Hello!</p>\n";
    }
  }
  else
  {
    print "<p>Greetings stranger!</p>\n";
  }

=head1 VERSION

1.00_03

=cut

our $VERSION = '1.00_03';

=head1 DESCRIPTION

FOAF+SSL is a simple authentication scheme described at
L<http://esw.w3.org/topic/foaf+ssl>. This module provides FOAF+SSL
authentication for CGI scripts written in Perl.

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

=cut

use Carp;
use CGI;
use CGI::Auth::FOAF_SSL::Agent;
use CGI::Auth::FOAF_SSL::CertifiedThing;
use CGI::Auth::FOAF_SSL::OnlineAccount;
use CGI::Session;
use Encode qw(encode_utf8);
use File::Spec;
use IPC::Open2;
use LWP::UserAgent;
use Math::BigInt try=>'GMP';
use RDF::TrineShortcuts 0.05;
use WWW::Finger 0.03;

=head2 Configuration

=over 4

=item C<< $CGI::Auth::FOAF_SSL::path_openssl = '/usr/bin/openssl' >>

Set the path to the OpenSSL binary.

=item C<< $CGI::Auth::FOAF_SSL::ua_string = 'MyTool/1.0' >>

Set the User-Agent string for any HTTP requests.

=cut

our $path_openssl = '/usr/bin/openssl';
our $ua_string    = "CGI::Auth::FOAF_SSL/" . $CGI::Auth::FOAF_SSL::VERSION . " ";

=back

=head2 Constructors

=over 4

=item C<< $auth = CGI::Auth::FOAF_SSL->new($pem_encoded) >>

Performs FOAF+SSL authentication on a PEM-encoded key. If authentication is
completely unsuccessful, returns undef. Otherwise, returns a CGI::Auth::FOAF_SSL
object. Use C<is_secure> to check if authentication was I<completely> successful.

You probably want to use C<new_from_cgi> instead.

=cut

sub new
{
	my $class = shift;
	my $self  = $class->new_unauthenticated(@_);
	
	return undef unless $self;
	
	my $verified = 0;
	if (defined $self->{'subject_alt_names'}->{'URI'})
	{
		foreach my $uri (@{ $self->{'subject_alt_names'}->{'URI'} })
		{
			$verified = $self->authenticate_by_uri($uri);
			last if $verified;
		}
	}
	
	if (defined $self->{'subject_alt_names'}->{'EMAIL'}
	and !$verified)
	{
		foreach my $e (@{ $self->{'subject_alt_names'}->{'EMAIL'} })
		{
			$verified = $self->authenticate_by_email($e);
			last if $verified;
		}
	}
	
	$self->load_personal_info
		if $verified;
	
	return $self;
}

=item C<< $auth = CGI::Auth::FOAF_SSL->new_from_cgi($cgi_object) >>

Performs FOAF+SSL authentication on a CGI object. This is a wrapper around
C<new> which extracts the PEM-encoded client certificate from the CGI
request. It has the same return values as C<new>.

If $cgi_object is omitted, uses C<< CGI->new >> instead.

=cut

sub new_from_cgi
{
	my $class = shift;
	my $cgi   = shift || CGI->new;
	
	return undef unless $cgi->https;
	
	# This should work, but doesn't!!
	# my $cert = $cgi->https('SSL_CLIENT_CERT');
	
	# This does work, but is less elegant.
	my $cert = $ENV{'SSL_CLIENT_CERT'};
	
	return $class->new($cert);
}

=item C<< $auth = CGI::Auth::FOAF_SSL->new_unauthenticated($pem_encoded) >>

Creates a CGI::Auth::FOAF_SSL object without doing any authentication.

It's very unlikely you want to do this. If you do create an unauthenticated
object, then you'll probably want to do some authentication using the
authenticate_by_XXX methods.

=cut

sub new_unauthenticated
{
	my $class = shift;
	my $cert  = shift;
	my $self  = {};
	
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
		last if (/^            X509v3 Subject Alternative Name:/);
	}
	my $alt_name = <READ>; 
	$alt_name =~ s/(^\s*|\s*\r?\n?$)//g;
	close READ;
	close WRITE;
	
	# Only allow FOAF+SSL certificates.
	$self->{'subject_alt_names'} = {};
	while ($alt_name =~ /(?:\s|\,|^)(URI|email):([^\s\,]+)(?:\s|\,|$)/ig)
	{
		push @{ $self->{'subject_alt_names'}->{uc $1} }, $2;
	}
	
	return undef unless $self->{'subject_alt_names'};
	
	# Modulus.
	$pid = 0;
	$pid = open2(\*READ, \*WRITE, "$openssl x509 -modulus");
	croak "Could not use openssl!\n" unless $pid > 0;
	print WRITE "$cert\n";
	$response = <READ>;
	close READ;
	close WRITE;
	return unless $response =~ /^Modulus=([0-9A-F]+)$/i;
	$self->{'cert_modulus_hex'} = $1;
	
	# Exponent.
	return unless $exponent_line =~ /Exponent: (\d+) \(0x([0-9A-F]+)\)/i;
	$self->{'cert_exponent_dec'} = $1;
	$self->{'cert_exponent_hex'} = $2;
	
	bless $self, $class;
	
	$self->_calculate_modulus_and_exponent_bigints;
	
	return $self;
}

sub _calculate_modulus_and_exponent_bigints
{
	my $self = shift;
	
	foreach my $part (qw(exponent modulus))
	{
		if ($self->{"cert_${part}_dec"})
		{
			my $dec = $self->{"cert_${part}_dec"};
			$dec =~ s/[^0-9]//g;
			$self->{"cert_${part}"} = Math::BigInt->new($dec);
		}
		elsif ($self->{"cert_${part}_hex"})
		{
			my $hex = $self->{"cert_${part}_hex"};
			$hex =~ s/[^0-9A-F]//ig;
			$self->{"cert_${part}"} = Math::BigInt->from_hex("0x$hex");
		}
	}
}

=back

=head2 Public Methods

=over 4

=item C<< $bool = $auth->is_secure >>

Returns true iff the authentication process was completely successful.

What does it mean for the authentication process to have been partially
successful? There are two such situations:

=over 4

=item * The rdf:type of the URI given in subjectAltName could not be established.

Perhaps no RDF could be found which provides an rdf:type for the URI,
or if an rdf:type is found, it is one that this module does not
recognise.

=item * The subjectAltName URI is established to be a foaf:OnlineAccount, but no account holder is confirmed.

To confirm that the account in question belongs to someone, the
RDF data associated with the account must provide the URI of an
account holder. Whatsmore the RDF data associated with the account
holder's URI must confirm that the account really does belong to
them.

This means that when dereferencing the subjectAltName and finding
that it identifies an account I<?account>, the data must provide
the following triples:

  ?webid foaf:account ?account .
  ?account a foaf:OnlineAccount .

And when I<?webid> is dereferenced, it must also provide this triple:

  ?webid foaf:account ?account .

=back

In either of these two situations, it is probably not safe to trust
any data you get back from the C<agent>, C<account> or C<certified_thing>
methods (except perhaps C<< $auth->certified_thing->identity >>).

=cut

sub is_secure
{
	my $this = shift;
	return $this->{'validation'} eq 'agent';
}

=item C<< $agent = $auth->agent >>

Returns a L<CGI::Auth::FOAF_SSL::Agent> object which represents the agent
making the request. Occasionally undef.

=cut

sub agent
{
	my $this = shift;
	return $this->{'agent'};
}

=item C<< $account = $auth->account >>

Returns a L<CGI::Auth::FOAF_SSL::OnlineAccount> object which represents
the online account of the agent making the request. Usually undef.

=cut

sub account
{
	my $this = shift;
	return $this->{'account'};
}

=item C<< $thing = $auth->certified_thing >>

Returns a L<CGI::Auth::FOAF_SSL::CertifiedThing> object (or a descendent class)
which represents the thing given in the certificate's subjectAltName.

Usually you will want to use C<agent> or C<account> instead.

=cut

sub certified_thing
{
	my $this = shift;
	return $this->{'thing'};
}

=item C<< $cookie = $auth->cookie >>

HTTP cookie related to the authentication process. Sending this to the
client isn't strictly necessary, but it allows for a session to be
established, greatly speeding up subsequent accesses. See also the
COOKIES section of this documentation.

=cut

sub cookie
{
	my $this = shift;
	return $this->{'session'}->cookie;
}

=item C<< $ok = $auth->authenticate_by_uri($uri) >>

Checks if $uri claims that $auth's key identifies it.

This is only relevent if you constructed $auth using C<new_unauthenticated>.

=cut

sub authenticate_by_uri
{
	my $self  = shift;
	my $uri   = shift;
	my $model = $self->get_trine_model($uri);
	
	return $self->authenticate_by_sparql($uri, $model);
}

=item C<< $ok = $auth->authenticate_by_email($email_address) >>

Checks if $email_address claims that $auth's key identifies it
(via WebFinger/Fingerpoint).

This is only relevent if you constructed $auth using C<new_unauthenticated>.

=cut

sub authenticate_by_email
{
	my $self  = shift;
	my $email = shift;
	my $fp    = WWW::Finger->new($email);
	
	return 0 unless defined $fp->endpoint and defined $fp->webid;
	
	return $self->authenticate_by_sparql($fp->webid, $fp->endpoint, $fp);
}

=item C<< $ok = $auth->authenticate_by_sparql($uri, $endpoint) >>

Checks if $endpoint claims that $auth's key identifies $uri. $endpoint may be
a SPARQL endpoint URI or an RDF::Trine::Model.

This is only relevent if you constructed $auth using C<new_unauthenticated>.

=cut

sub authenticate_by_sparql
{
	my ($self, $uri, $model, $fp) = @_;
	
	my $query_string = sprintf("PREFIX cert: <http://www.w3.org/ns/auth/cert#> "
	                          ."PREFIX rsa: <http://www.w3.org/ns/auth/rsa#> "
	                          ."SELECT ?modulus ?exponent ?decExponent ?hexModulus "
	                          ."WHERE "
	                          ."{ "
	                          ."    ?key "
	                          ."        cert:identity <%s> ; "
	                          ."        rsa:modulus ?modulus ; "
	                          ."        rsa:public_exponent ?exponent . "
	                          ."    OPTIONAL { ?modulus cert:hex ?hexModulus . } "
	                          ."    OPTIONAL { ?exponent cert:decimal ?decExponent . } "
	                          ."}",
	                          $uri);
	my $results = rdf_query($query_string, $model);
	
	RESULT: while (my $result = $results->next)
	{
		my $correct_modulus  = $self->make_bigint_from_node(
			$result->{'modulus'},  fallback => $result->{'hexModulus'},  fallback_type=>'hex');
			
		my $correct_exponent = $self->make_bigint_from_node(
			$result->{'exponent'}, fallback => $result->{'decExponent'}, fallback_type=>'dec');

		next RESULT unless $correct_modulus  == $self->{'cert_modulus'};
		next RESULT unless $correct_exponent == $self->{'cert_exponent'};

		$self->{'validation'}       = 'cert';
		$self->{'cert_subject_uri'} = $uri;
		
		if (ref $model && $model->isa('RDF::Trine::Model'))
		{
			$self->{'cert_subject_model'} = $model;
		}
		else
		{
			$self->{'cert_subject_uri'}         = $uri;
			$self->{'cert_subject_endpoint'}    = $model;
			$self->{'cert_subject_fingerpoint'} = $fp
				if defined $fp;
		}
		
		return 1;
	}
	
	return 0;
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
	my $results = $rv->execute_query( $query_string );
	
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
	#      - foaf:account
	#      - foaf:accountServiceHomepage
	#      - foaf:accountName
	#      - http://rdfs.org/sioc/ns#account_of
	
	my $retrievedAgentUri;
	
	if (!defined $rv->{'cert_subject_type'}
	||  $rv->{'cert_subject_type'} eq 'OnlineAccount')
	{
		my $results = $rv->execute_query(
			sprintf('SELECT ?person
				WHERE {
					{ <%s> <http://rdfs.org/sioc/ns#account_of> ?person . }
					UNION { ?person <http://xmlns.com/foaf/0.1/holdsAccount> <%s> . }
					UNION { ?person <http://xmlns.com/foaf/0.1/account> <%s> . }
				}',
				$rv->{'cert_subject_uri'}, $rv->{'cert_subject_uri'}, $rv->{'cert_subject_uri'}),
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
		my $results = $rv->execute_query(
			sprintf('ASK
				WHERE {
					{ <%s> <http://xmlns.com/foaf/0.1/accountName> ?o . }
					UNION { <%s> <http://xmlns.com/foaf/0.1/accountServiceHomepage> ?o . }
				}',
				$rv->{'cert_subject_uri'}, $rv->{'cert_subject_uri'}),
			$rv->{'cert_subject_uri'});
		
		if ($results)
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
					sprintf('ASK
						WHERE {
							{ <%s> <http://rdfs.org/sioc/ns#account_of> <%s> . }
							UNION { <%s> <http://xmlns.com/foaf/0.1/holdsAccount> <%s> . }
							UNION { <%s> <http://xmlns.com/foaf/0.1/account> <%s> . }
						}',
						$rv->{'cert_subject_uri'}, $retrievedAgentUri,
						$retrievedAgentUri, $rv->{'cert_subject_uri'},
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

=head2 Utility Methods

=over 4

=item C<< $model = $auth->get_trine_model($uri) >>

Get an RDF::Trine::Model corresponding to a URI.

=cut

sub get_trine_model
{
	my $this = shift;
	my $uri  = shift;
	
	# Session for caching data into.
	unless (defined $this->{'session'})
	{
		$this->{'session'} = CGI::Session->new('driver:file', undef, {Directory => File::Spec->tmpdir});
		$this->{'session'}->expire('+1h');
	}
	
	# Check to see if this URI has already been retrieved.
	if (defined $this->{'session'}->param($uri)
	and length $this->{'session'}->param($uri))
	{
		return rdf_parse($this->{'session'}->param($uri),
			base=>$uri , type=>'ntriples');
	}
	
	my $ua = LWP::UserAgent->new(agent=>$CGI::Auth::FOAF_SSL::ua_string); 
	$ua->default_headers->push_header('Accept' => "application/rdf+xml, text/turtle, application/x-turtle, application/xhtml+xml;q=0.9, text/html;q=0.9, */*;q=0.1");
	my $response = $ua->get($uri);
	return unless length $response->content;
	my $model    = rdf_parse($response);
	
	$this->{'session'}->param($uri, rdf_string($model, 'ntriples'));
	$this->{'session'}->flush;
	
	return $model;
}

=item C<< $bi = $auth->make_bigint_from_node($trine_node) >>

Turns an RDF::Trine::Node::Literal object into a Math::BigInt representing the
same number.

There are optional named parameters for providing a fallback in the case where
$trine_node has an unrecognised datatype or is not a literal.

  $bi = $auth->make_bigint_from_node(
    $trine_node, fallback=>$other_node, fallback_type=>'hex');

The authenticate_by_XXX methods use this.

=cut

sub make_bigint_from_node
{
	my $self = shift;
	my $node = shift;
	my %opts = @_;
	
	if ($node->is_literal)
	{
		if ($node->literal_datatype eq 'http://www.w3.org/ns/auth/cert#hex')
		{
			my $hex = $node->literal_value;
			$hex =~ s/[^0-9A-F]//ig;
			return Math::BigInt->from_hex("0x$hex");
		}
		elsif ($node->literal_datatype eq 'http://www.w3.org/ns/auth/cert#decimal'
		or     $node->literal_datatype eq 'http://www.w3.org/ns/auth/cert#int'
		or     $node->literal_datatype =~ m'^http://www.w3.org/2001/XMLSchema#(unsigned(Long|Int|Short|Byte)|positiveInteger|nonNegitiveInteger)$')
		{
			my $dec = $node->literal_value;
			$dec =~ s/[^0-9]//ig;
			return Math::BigInt->new("$dec");
		}
		elsif ($node->literal_datatype =~ m'^http://www.w3.org/2001/XMLSchema#(integer|negitiveInteger|nonPositiveInteger|long|short|int|byte)$')
		{
			my $dec = $node->literal_value;
			$dec =~ s/[^0-9-]//ig;
			return Math::BigInt->new("$dec");
		}
		elsif ($node->literal_datatype eq 'http://www.w3.org/2001/XMLSchema#decimal')
		{
			my ($dec, $frac) = split /\./, $node->literal_value, 2;
			$dec =~ s/[^0-9-]//ig;
			return Math::BigInt->new("$dec");
			
			warn "Ignoring fractional part of xsd:decimal number." if defined $frac;
		}
		elsif (! $node->literal_datatype)
		{
			$opts{'fallback'} = $node;
		}
	}
	
	if (defined $opts{'fallback'} && $opts{'fallback'}->is_literal)
	{
		my $node = $opts{'fallback'};
		
		if ($opts{'fallback_type'} eq 'hex')
		{
			my $hex = $node->literal_value;
			$hex =~ s/[^0-9A-F]//ig;
			return Math::BigInt->from_hex("0x$hex");
		}
		else #dec
		{
			my ($dec, $frac) = split /\./, $node->literal_value, 2;
			$dec =~ s/[^0-9]//ig;
			return Math::BigInt->new("$dec");
			
			warn "Ignoring fractional part of xsd:decimal number." if defined $frac;
		}
	}
}

=item C<< $results = $auth->execute_query($sparql) >>

Returns the results of a SPARQL query. Uses the certificate subject's
RDF file as a data source, or the certificate subject's SPARQL endpoint.

See L<RDF::TrineShortcuts> function rdf_query for an explanation of the
return format.

=cut

sub execute_query 
{
	my $rv = shift;
	my $q  = shift;
	
	if (defined $rv->{'cert_subject_model'})
	{
		return rdf_query($q, $rv->{'cert_subject_model'});
	}
	
	if (defined $rv->{'cert_subject_endpoint'})
	{
		return rdf_query($q, $rv->{'cert_subject_endpoint'});
	}
	
	return undef;
}

1;

__END__

=back

=head1 COOKIES

FOAF+SSL is entirely RESTful: there is no state kept between requests.
This really simplifies authentication for both parties (client and
server) for one-off requests. However, because FOAF+SSL requires the
server to make various HTTP requests to authenticate the client, each
request is slowed down significantly.

Cookies provide us with a way of speeding this up. Use of cookies is
entirely optional, but greatly increases the speed of authentication
for the second and subsequent requests a client makes. If your
FOAF+SSL-secured service generally requires clients to make multiple
requests in a short period, you should seriously consider using
cookies to speed this up.

The method works like this: on the first request, authentication happens
as normal. However, all RDF files relevant to authenticating the client
are kept on disk (usually somewhere like '/tmp') in N-Triples format.
They are associated with a session that is given a randomly generated
identifier. This random identifier is sent the client as a cookie. On
subsequent requests, the client includes the cookie and thus
CGI::Auth::FOAF_SSL is able to retrieve the data it needs from disk in
N-Triples format, rather than having to reach out onto the web for
it again.

To use this feature, you must perform authentication before printing
anything back to the client, use CGI::Auth::FOAF_SSL's C<cookie>
method, and then pass that to the client as part of the HTTP response
header.

  use CGI qw(:all);
  use CGI::Auth::FOAF_SSL;
  
  my $auth = CGI::Auth::FOAF_SSL->new_from_cgi;
  
  if (defined $auth && $auth->is_secure)
  {
    print header('-type' => 'text/html',
                 '-cookie' => $auth->cookie);

    my $user = $auth->agent;
    # ...
  }
  else # anonymous access
  {
    print header('-type' => 'text/html');
    
    # ...
  }

Old sessions are automatically purged after an hour of inactivity.

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 SEE ALSO

Helper modules:
L<CGI::Auth::FOAF_SSL::CertifiedThing>,
L<CGI::Auth::FOAF_SSL::Agent>,
L<CGI::Auth::FOAF_SSL::OnlineAccount>.

Related modules:
L<CGI>, L<RDF::Trine>, L<RDF::ACL>.

Information about FOAF+SSL:
L<http://lists.foaf-project.org/mailman/listinfo/foaf-protocols>,
L<http://esw.w3.org/topic/foaf+ssl>.

SSL in Apache:
L<http://httpd.apache.org/docs/2.0/mod/mod_ssl.html>.

Mailing list for general Perl RDF/SemWeb discussion and support:
L<http://www.perlrdf.org/>.

=head1 AUTHOR

Toby Inkster, E<lt>tobyink@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009-2010 by Toby Inkster

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

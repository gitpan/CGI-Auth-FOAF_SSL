package CGI::Auth::FOAF_SSL;

use 5.010;
use common::sense;

use CGI::Auth::FOAF_SSL::Agent 0;
use CGI 0;
use CGI::Session 0;
use Crypt::X509 0.50;
use DateTime 0;
use File::Spec 0;
use LWP::UserAgent 0;
use Math::BigInt 0 try => 'GMP';
use MIME::Base64 0 qw[];
use Object::ID 0;
use RDF::TrineShortcuts 0.100;
use Scalar::Util 0 qw[blessed];

use constant {
	VALIDATION_PEM     => 1,
	VALIDATION_DATES   => 2,
	VALIDATION_WEBID   => 3,
	};
	
our $VERSION;
our $ua_string;

my $WWW_Finger;
my ($AGENT, $MODEL, $SESSION); # inside-out objects

BEGIN
{
	$VERSION = '1.002';
	$ua_string = sprintf('%s/%s ', __PACKAGE__, $VERSION);	

	$WWW_Finger = 0;
	if (0) # DISABLED
	{
		local $@ = undef;
		eval
		{
			require WWW::Finger;
			die "too old"
				if $WWW::Finger::VERSION lt '0.100';
		};
		$WWW_Finger++
			unless defined $@;
	}
	$AGENT   = {};
	$MODEL   = {};
	$SESSION = {};
}

sub new
{
	my ($class, $pem, @params) = @_;
	my $self = $class->new_unauthenticated($pem, @params);
	
	return unless defined $self;
	return unless $self->validation(VALIDATION_PEM);
	
	my $now = DateTime->now;
	return if defined $self->cert_not_before && $now < $self->cert_not_before;
	return if defined $self->cert_not_after  && $now > $self->cert_not_after;

	$self->validation(VALIDATION_DATES);
	
	my $verified;
	
	if (defined $self->{subject_alt_names}{uniformResourceIdentifier})
	{
		foreach my $uri (@{ $self->{subject_alt_names}{uniformResourceIdentifier} })
		{
			$verified = $self->authenticate_by_uri($uri);
			last if $verified;
		}
	}
	
	if (defined $self->{subject_alt_names}{rfc822Name} and !$verified)
	{
		foreach my $e (@{ $self->{subject_alt_names}{rfc822Name} })
		{
			$verified = $self->authenticate_by_email($e);
			last if $verified;
		}
	}
	
	return $self;
}

sub new_from_cgi
{
	my ($class, $cgi, @params) = @_;
	$cgi ||= CGI->new;
	
	return unless $cgi->https;
	
	# This should work, but doesn't!!
	# my $cert = $cgi->https('SSL_CLIENT_CERT');
	
	# This does work, but is less elegant.
	my $cert = $ENV{SSL_CLIENT_CERT};
	
	return $class->new($cert, @params);
}

# Documentation in Advanced.pod
sub new_unauthenticated
{
	my ($class, $pem) = @_;	
	my $self  = bless { pem => $pem }, $class;
	
	# Need a PEM-encoded cert.
	return unless $pem; 

	# Convert PEM to DER - easy!
	my $der = MIME::Base64::decode_base64(join "\n", grep { !/^-----(BEGIN|END) CERTIFICATE-----$/ } split /\n/, $pem);
	
	# Use Crypt::X509 to look inside the DER/ASN.1.
	my $CX = Crypt::X509->new(cert => $der);

	# Cert Expiry - check these in authentication process.
	$self->cert_not_before( $CX->not_before );
	$self->cert_not_after( $CX->not_after );

	# SubjectAltName
	foreach my $san ( @{$CX->SubjectAltName} )
	{
		my ($type, $value) = split /=/, $san, 2;
		push @{ $self->{subject_alt_names}{$type} }, $value;
	}

	# RSA key
	my $rsa = $CX->pubkey_components;
	$self->cert_modulus($rsa->{modulus});
	$self->cert_exponent($rsa->{exponent});
	
	$self->validation(VALIDATION_PEM);
	
	return $self;
}


sub is_secure
{
	my ($self) = @_;
	return ($self->validation == VALIDATION_WEBID) ? 1 : 0;
}

sub subject
{
	my ($self) = @_;

	$AGENT->{ object_id($self) } ||= CGI::Auth::FOAF_SSL::Agent->new(
		$self->subject_uri,
		$self->subject_model,
		$self->subject_endpoint,
		);

	return $AGENT->{ object_id($self) };
}

*certified_thing = \&subject;
*agent           = \&subject;
*account         = sub { return; };

sub cookie
{
	my ($self) = @_;
	return $self->session->cookie;
}

# Documentation in Advanced.pod
sub authenticate_by_uri
{
	my ($self, $uri) = @_;
	my $model = $self->get_trine_model($uri);	
	return $self->authenticate_by_sparql($uri, $model);
}

# Documentation in Advanced.pod
sub authenticate_by_email
{
	return unless $WWW_Finger;	
	
	my ($self, $email) = @_;	
	my $fp = WWW::Finger->new($email);
	
	return unless defined $fp;
	return unless defined $fp->endpoint;
	return unless defined $fp->webid;
	
	return $self->authenticate_by_sparql($fp->webid, $fp->endpoint, $fp);
}

# Documentation in Advanced.pod
sub authenticate_by_sparql
{
	my ($self, $uri, $model, $fp) = @_;
	
	my $query_string = sprintf(<<'SPARQL', $uri);
PREFIX cert: <http://www.w3.org/ns/auth/cert#>
PREFIX rsa: <http://www.w3.org/ns/auth/rsa#>
SELECT
	?modulus
	?exponent
	?decExponent
	?hexModulus
WHERE
{
	{
		?key
			cert:identity <%s> ;
			rsa:modulus ?modulus ;
			rsa:public_exponent ?exponent .
	}
	UNION
	{
		<%s> cert:key ?key .
		?key
			rsa:modulus ?modulus ;
			rsa:public_exponent ?exponent .
	}

	OPTIONAL { ?modulus cert:hex ?hexModulus . }
	OPTIONAL { ?exponent cert:decimal ?decExponent . }
}
SPARQL

	my $results = rdf_query($query_string, $model);
	
	RESULT: while (my $result = $results->next)
	{
		my $correct_modulus  = $self->make_bigint_from_node(
			$result->{modulus},
			fallback      => $result->{hexModulus},
			fallback_type =>'hex',
			);
		next RESULT
			unless $correct_modulus == $self->cert_modulus;
			
		my $correct_exponent = $self->make_bigint_from_node(
			$result->{exponent},
			fallback      => $result->{decExponent},
			fallback_type =>'dec',
			);
		next RESULT
			unless $correct_exponent == $self->cert_exponent;

		$self->validation(VALIDATION_WEBID);
		$self->subject_uri($uri);
		
		if (blessed($model) and $model->isa('RDF::Trine::Model'))
		{
			$self->subject_model($model);
		}
		else
		{
			$self->subject_uri($uri);
			$self->subject_endpoint($model);
		}
		
		return 1;
	}
	
	return 0;
}

# Documentation in Advanced.pod
sub validation
{
	my ($self) = shift;
	if (@_)
	{
		$self->{validation} = shift;
	}
	return $self->{validation};
}

# Documentation in Advanced.pod
sub cert_modulus
{
	my ($self) = shift;
	if (@_)
	{
		my $new = shift;
		$new = Math::BigInt->new($new)
			unless blessed($new) && $new->isa('Math::BigInt');
		$self->{cert_modulus} = $new;
	}
	return $self->{cert_modulus};
}

# Documentation in Advanced.pod
sub cert_exponent
{
	my ($self) = shift;
	if (@_)
	{
		my $new = shift;
		$new = Math::BigInt->new($new)
			unless blessed($new) && $new->isa('Math::BigInt');
		$self->{cert_exponent} = $new;
	}
	return $self->{cert_exponent};
}

# Documentation in Advanced.pod
sub cert_not_before
{
	my ($self) = shift;
	if (@_)
	{
		my $new = shift;
		$new = DateTime->from_epoch(epoch => $new)
			unless blessed($new) && $new->isa('DateTime');
		$self->{cert_not_before} = $new;
	}
	return $self->{cert_not_before};
}

# Documentation in Advanced.pod
sub cert_not_after
{
	my ($self) = shift;
	if (@_)
	{
		my $new = shift;
		$new = DateTime->from_epoch(epoch => $new)
			unless blessed($new) && $new->isa('DateTime');
		$self->{cert_not_after} = $new;
	}
	return $self->{cert_not_after};
}

# Documentation in Advanced.pod
sub subject_uri
{
	my ($self) = shift;
	if (@_)
	{
		$self->{subject_uri} = shift;
	}
	return $self->{subject_uri};
}

# Documentation in Advanced.pod
sub subject_model
{
	my ($self) = shift;
	if (@_)
	{
		$MODEL->{ object_id($self) } = shift;
	}
	return $MODEL->{ object_id($self) };
}

# Documentation in Advanced.pod
sub subject_endpoint
{
	my ($self) = shift;
	if (@_)
	{
		$self->{subject_endpoint} = shift;
	}
	return $self->{subject_endpoint};
}

# Documentation in Advanced.pod
sub session
{
	my ($self) = shift;
	
	if (@_)
	{
		$SESSION->{ object_id($self) } = shift;
	}

	unless (defined $SESSION->{ object_id($self) })
	{
		my $s = CGI::Session->new('driver:file', undef, {Directory => File::Spec->tmpdir});
		$s->expire('+1h');
		$SESSION->{ object_id($self) } = $s;
	}
	
	return $SESSION->{ object_id($self) };
}

# Documentation in Advanced.pod
sub get_trine_model
{
	my ($self, $uri) = @_;
	
	# Check to see if this URI has already been retrieved
	# in our session.
	if (defined $self->session->param($uri)
	and length $self->session->param($uri))
	{
		return rdf_parse($self->session->param($uri),
			base=>$uri , type=>'ntriples');
	}
	
	my $ua = LWP::UserAgent->new(agent => $ua_string); 
	$ua->default_headers->push_header('Accept' => "application/rdf+xml, text/turtle, application/x-turtle, application/xhtml+xml;q=0.9, text/html;q=0.9, */*;q=0.1");
	my $response = $ua->get($uri);
	return unless $response->is_success && length $response->content;
	my $model = rdf_parse($response);
	
	$self->session->param($uri, rdf_string($model, 'ntriples'));
	$self->session->flush;
	
	return $model;
}

# Documentation in Advanced.pod
sub make_bigint_from_node
{
	my ($self, $node, %opts) = @_;
	
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
			
			warn "Ignoring fractional part of xsd:decimal number."
				if defined $frac;
		}
	}
}

# Documentation in Advanced.pod
sub execute_query 
{
	my ($self, $q) = @_;
	
	my $target = $self->subject_model || $self->subject_endpoint;
	return rdf_query($q, $target) if defined $target;
	return;
}

1;

__END__

=head1 NAME

CGI::Auth::FOAF_SSL - authentication using WebID (FOAF+SSL)

=head1 SYNOPSIS

  use CGI qw(:all);
  use CGI::Auth::FOAF_SSL;
  
  my $auth = CGI::Auth::FOAF_SSL->new_from_cgi;
  
  print header(-type=>'text/html', -cookie=>$auth->cookie);
  
  if (defined $auth && $auth->is_secure)
  {
    if (defined $auth->subject)
    {
      printf("<p>Hello <a href='%s'>%s</a>!</p>\n",
             escapeHTML($auth->subject->homepage),
             escapeHTML($auth->subject->name));
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

=head1 DESCRIPTION

FOAF+SSL (a.k.a. WebID) is a simple authentication scheme described
at L<http://esw.w3.org/topic/foaf+ssl>. This module implements the server
end of FOAF+SSL in Perl.

It is suitable for handling authentication using FOAF+SSL over HTTPS.
Your web server needs to be using HTTPS, configured to request client
certificates, and make the certificate PEM available to your script. If you
are using Apache, this means that you want to set the following
directives in your SSL virtual host setup:

 SSLEngine on
 SSLVerifyClient optional_no_ca
 SSLVerifyDepth  1
 SSLOptions +StdEnvVars +ExportCertData

=head2 Configuration

=over 4

=item * C<< $CGI::Auth::FOAF_SSL::ua_string = 'MyTool/1.0' >>

Set the User-Agent string for any HTTP requests.

=back

=head2 Constructors

=over 4

=item * C<< new($pem_encoded) >>

Performs FOAF+SSL authentication on a PEM-encoded key. If authentication is
completely unsuccessful, returns undef. Otherwise, returns a CGI::Auth::FOAF_SSL
object. Use C<is_secure> to check if authentication was I<completely> successful.

You probably want to use C<new_from_cgi> instead.

(DER encoded certificates should work too.)

=item * C<< new_from_cgi($cgi_object) >>

Performs FOAF+SSL authentication on a CGI object. This is a wrapper around
C<new> which extracts the PEM-encoded client certificate from the CGI
request. It has the same return values as C<new>.

If $cgi_object is omitted, uses C<< CGI->new >> instead.

=back

=head2 Public Methods

=over 4

=item * C<< is_secure >>

Returns true iff the FOAF+SSL authentication process was completely successful.

=item * C<< subject >>

Returns a L<CGI::Auth::FOAF_SSL::Agent> object which represents the subject
of the certificate. 

This method has aliases C<agent> and C<certified_thing> for back-compat
reasons.

=item * C<< cookie >>

HTTP cookie related to the authentication process. Sending this to the
client isn't strictly necessary, but it allows for a session to be
established, greatly speeding up subsequent accesses. See also the
COOKIES section of this documentation.

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

Helper module:
L<CGI::Auth::FOAF_SSL::Agent>.

Advanced developer documentation:
L<CGI::Auth::FOAF_SSL::Advanced>.

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

Copyright (C) 2009-2011 by Toby Inkster

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

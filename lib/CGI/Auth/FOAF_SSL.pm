package CGI::Auth::FOAF_SSL;

BEGIN {
	$CGI::Auth::FOAF_SSL::VERSION = '0.01';
}

=head1 NAME

CGI::Auth::FOAF_SSL - Authentication using FOAF+SSL.

=head1 VERSION

0.01

=head1 SYNOPSIS

 use CGI qw(:all);
 use CGI::Auth::FOAF_SSL;

 my $cgi    = CGI->new;
 my $person = CGI::Auth::FOAF_SSL->new_from_cgi($cgi);

 print header("text/html");

 if (defined $person && $person->is_secure)
 {
 	printf("<p>Hello <a href='%s'>%s</a>! You are logged on with FOAF+SSL.</p>\n",
 		escapeHTML($person->homepage),
 		escapeHTML($person->name));
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
use IPC::Open2;
use LWP::UserAgent;
use RDF::Redland;
use 5.010000;
use strict;
use warnings;

# @@TODO - this should be configurable.
sub path_openssl { return '/usr/bin/openssl'; }

# @@TODO - this should be configurable.
sub ua_string { return "CGI::Auth::FOAF_SSL/" . $CGI::Auth::FOAF_SSL::VERSION . " "; }

=head1 CONSTRUCTORS

=over 8

=item $person = CGI::Auth::FOAF_SSL->new($pem_encoded);

Performs FOAF+SSL authentication on a PEM-encoded key. If authentication is
completely unsuccessful, returns undef. Otherwise, returns a CGI::Auth::FOAF_SSL
object. Use C<is_secure> to check if authentication was completely successful.

You probably want to use C<new_from_cgi> instead.

=cut

sub new
{
	return new_full_from_cert(@_);
}

=item $person = CGI::Auth::FOAF_SSL->new_from_cgi($cgi_object);

Performs FOAF+SSL authentication on a CGI object. This is a wrapper around
C<new> which extracts the PEM-encoded client certificate from the CGI
request. It has the same return values as C<new>.

=back

=cut

sub new_from_cgi
{
	my $class = shift;
	my $cgi   = shift;
	
	return undef unless ($cgi->https);
	return new($class, $cgi->https('SSL_CLIENT_CERT'));
}

# Undocumented internally used constructor.

sub new_basic_from_cert
{
	my $class = shift;
	my $cert  = shift;
	my $rv    = {};
	
	# Only client certificate secured connections allowed.
	return unless $cert; 
	
	# We use OpenSSL to parse the client certificate. There is an OpenSSL module
	# in CPAN, but it's poorly documented, so we'll just use the command-line
	# client instead. You may want to provide a full path here...
	my $openssl = path_openssl;
	
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
	$rv->{'account_uri'} = $1;
	
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

# Undocumented internally used constructor.

sub new_intermediate_from_cert
{
	my $rv = new_basic_from_cert(@_);
	return $rv unless ((defined $rv) && ($rv->{'validation'} >= 1));

	my $ua       = LWP::UserAgent->new(agent=>ua_string); 
	my $response = $ua->get($rv->{'account_uri'});
	
	my $account  = RDF::Redland::URI->new($rv->{'account_uri'});
	my $storage  = RDF::Redland::Storage->new("hashes", "test", "new='yes',hash-type='memory'");
	my $model    = RDF::Redland::Model->new($storage, "");	
	my $parser   = RDF::Redland::Parser->new(undef, $response->header('content-type'));
	$parser->parse_string_into_model($response->content, $account, $model);
	
	my $query_string = sprintf("SELECT ?person ?hexModulus ?decExponent "
	                          ."WHERE { "
	                          ."    ?person <http://xmlns.com/foaf/0.1/holdsAccount> <%s> . "
	                          ."    ?key <http://www.w3.org/ns/auth/cert#identity> <%s> . "
	                          ."    ?key <http://www.w3.org/ns/auth/rsa#modulus> ?modulus . "
	                          ."    ?modulus <http://www.w3.org/ns/auth/cert#hex> ?hexModulus . "
	                          ."    ?key <http://www.w3.org/ns/auth/rsa#public_exponent> ?exponent . "
	                          ."    ?exponent <http://www.w3.org/ns/auth/cert#decimal> ?decExponent . "
	                          ."}",
	                          $rv->{'account_uri'}, $rv->{'account_uri'});
	my $query   = RDF::Redland::Query->new($query_string, $account, undef, "sparql");
	my $results = $model->query_execute($query);
	if (!$results->finished)
	{
		$rv->{'identity'}                  = $results->binding_value(0)->uri->as_string;
		$rv->{'correct_cert_modulus_hex'}  = $results->binding_value(1)->literal_value;
		$rv->{'correct_cert_exponent_dec'} = $results->binding_value(2)->literal_value;
	}

	$rv->{'correct_cert_modulus_hex'}  =~ s/[^A-Z0-9]//ig;
	$rv->{'correct_cert_exponent_dec'} =~ s/[^0-9]//ig;
	$rv->{'correct_cert_modulus_hex'}  = uc($rv->{'correct_cert_modulus_hex'});

	if (($rv->{'correct_cert_modulus_hex'} eq $rv->{'cert_modulus_hex'})
	&&  ($rv->{'correct_cert_exponent_dec'} == $rv->{'cert_exponent_dec'}))
	{
		$rv->{validation}++;
		delete $rv->{'correct_cert_exponent_dec'};
		delete $rv->{'correct_cert_modulus_hex'};
	}
	
	$rv->{'account_details'} = $model;
	
	return $rv;
}

# Undocumented internally used constructor.

sub new_full_from_cert
{
	my $rv = new_intermediate_from_cert(@_);
	return $rv unless ((defined $rv) && ($rv->{'validation'} >= 2));

	my $ua       = LWP::UserAgent->new(agent=>ua_string); 
	my $response = $ua->get($rv->{'identity'});
	
	my $account  = RDF::Redland::URI->new($rv->{'identity'});
	my $storage  = RDF::Redland::Storage->new("hashes", "test", "new='yes',hash-type='memory'");
	my $model    = RDF::Redland::Model->new($storage, "");	
	my $parser   = RDF::Redland::Parser->new(undef, $response->header('content-type'));
	$parser->parse_string_into_model($response->content, $account, $model);
	
	my $query_string = sprintf("ASK "
	                          ."WHERE { "
	                          ."    <%s> <http://xmlns.com/foaf/0.1/holdsAccount> <%s> . "
	                          ."}",
	                          $rv->{'identity'}, $rv->{'account_uri'});
	my $query   = RDF::Redland::Query->new($query_string, $account, undef, "sparql");
	my $results = $model->query_execute($query);
	if ($results->is_boolean && $results->get_boolean)
	{
		$rv->{validation}++;
	}
	
	$rv->{'person_details'} = $model;
	
	return $rv;
}

=head1 PUBLIC METHODS

=over 8

=item $person->is_secure;

Returns true iff the authentication process was completely successful.

=cut

sub is_secure
{
	my $this = shift;
	return ($this->{'validation'}==3);
}

=item $person->identity;

Returns an identifying URI for the agent (person, organisation, robot) making
the authenticated HTTP request. This URI is a URI in the RDF sense of the word.
It is not their homepage.

=cut

sub identity
{
	my $this = shift;
	return $this->{'identity'};
}

=item $person->redland;

Returns an RDF::Redland::Model which should contain some data about the
agent making the authenticated HTTP request.

=cut

sub redland
{
	my $this = shift;
	return $this->{'person_details'};
}

=item $person->name;

Returns the name of the agent making the authenticated HTTP request. That is,
if the agent is a person, this will tell you what the person's name is.

Returns undef if unable to determine the name.

=cut

sub name
{
	my $this = shift;
	
	unless (defined $this->{'name'})
	{
		my $model = $this->{'person_details'};
		
		my $query_string = sprintf("SELECT ?name "
										  ."WHERE { "
										  ."    <%s> <http://xmlns.com/foaf/0.1/name> ?name . "
										  ."}",
										  $this->{'identity'});
		my $query   = RDF::Redland::Query->new($query_string, RDF::Redland::URI->new($this->{'identity'}), undef, "sparql");
		my $results = $model->query_execute($query);
		if (!$results->finished)
		{
			$this->{'name'} = $results->binding_value(0)->literal_value;
		}
	}
	
	unless (defined $this->{'name'})
	{
		my $model = $this->{'person_details'};
		
		my $query_string = sprintf("SELECT ?name "
										  ."WHERE { "
										  ."    <%s> <http://xmlns.com/foaf/0.1/nick> ?name . "
										  ."}",
										  $this->{'identity'});
		my $query   = RDF::Redland::Query->new($query_string, RDF::Redland::URI->new($this->{'identity'}), undef, "sparql");
		my $results = $model->query_execute($query);
		if (!$results->finished)
		{
			$this->{'name'} = $results->binding_value(0)->literal_value;
		}
	}
	
	return $this->{'name'};
}

=item $person->homepage;

Returns the homepage of the agent making the authenticated HTTP request. 

Returns undef if unable to determine the homepage.

=cut

sub homepage
{
	my $this = shift;
	
	unless (defined $this->{'homepage'})
	{
		my $model = $this->{'person_details'};
		
		my $query_string = sprintf("SELECT ?homepage "
										  ."WHERE { "
										  ."    <%s> <http://xmlns.com/foaf/0.1/homepage> ?homepage . "
										  ."}",
										  $this->{'identity'});
		my $query   = RDF::Redland::Query->new($query_string, RDF::Redland::URI->new($this->{'identity'}), undef, "sparql");
		my $results = $model->query_execute($query);
		if (!$results->finished)
		{
			$this->{'homepage'} = $results->binding_value(0)->uri->as_string;
		}
	}
	
	unless (defined $this->{'homepage'})
	{
		my $model = $this->{'person_details'};
		
		my $query_string = sprintf("SELECT ?homepage "
										  ."WHERE { "
										  ."    <%s> <http://xmlns.com/foaf/0.1/page> ?homepage . "
										  ."}",
										  $this->{'identity'});
		my $query   = RDF::Redland::Query->new($query_string, RDF::Redland::URI->new($this->{'identity'}), undef, "sparql");
		my $results = $model->query_execute($query);
		if (!$results->finished)
		{
			$this->{'homepage'} = $results->binding_value(0)->uri->as_string;
		}
	}
	
	return $this->{'homepage'};
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

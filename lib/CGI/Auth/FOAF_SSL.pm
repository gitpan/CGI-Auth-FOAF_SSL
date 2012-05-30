package CGI::Auth::FOAF_SSL;

use 5.010;

use CGI::Auth::FOAF_SSL::Agent 0;
use Scalar::Util 0 qw[blessed];
use Web::ID 1.921;
use Web::ID::Util;

use constant 0 {
	VALIDATION_PEM     => 1,
	VALIDATION_DATES   => 2,
	VALIDATION_WEBID   => 3,
	};

BEGIN {
	$CGI::Auth::FOAF_SSL::AUTHORITY = 'cpan:TOBYINK';
	$CGI::Auth::FOAF_SSL::VERSION   = '1.921_00';
}

our $ua_string = sprintf('%s/%s ', __PACKAGE__, __PACKAGE__->VERSION);

use Any::Moose;

has web_id_object => (
	is         => read_only,
	isa        => 'Web::ID',
	writer     => '_set_web_id_object',
	required   => false,
	handles    => {
		subject_uri   => 'uri',
		subject_model => 'profile',
		is_secure     => 'valid',
		},
	);

has session => (
	is         => read_only,
	isa        => 'CGI::Session',
	lazy_build => true,
	handles    => [qw[cookie]],
	);

has subject => (
	is         => read_only,
	isa        => 'CGI::Auth::FOAF_SSL::Agent',
	lazy_build => true,
	);

sub BUILDARGS
{
	my $class = shift;
	
	if ($_[0] =~ /-----BEGIN CERTIFICATE-----/)
	{
		my $web_id_object = Web::ID->new(certificate => shift);
		return +{ web_id_object => $web_id_object };
	}
	
	elsif (ref $_[0] eq 'HASH')
	{
		return shift;
	}
	
	else
	{
		return +{ @_ };
	}
}

sub new_from_cgi
{
	require CGI;
	
	my ($class, $cgi, @params) = @_;
	$cgi ||= CGI->new;	
	return unless $cgi->https;
	return $class->new($ENV{SSL_CLIENT_CERT}, @params);
}

sub new_unauthenticated
{
	shift->new(@_);
}

sub _build_subject
{
	my ($self) = @_;

	CGI::Auth::FOAF_SSL::Agent->new(
		scalar $self->subject_uri,
		scalar $self->subject_model,
		scalar $self->subject_endpoint,
		scalar $self->web_id_object,
	);
}

*certified_thing = sub { shift->subject; };
*agent           = sub { shift->subject; };
*account         = sub { return; };

sub validation
{
	my $self = shift;
	return VALIDATION_WEBID if $self->web_id_object->valid;
	return VALIDATION_DATES if $self->web_id_object->certificate->timely;
	return VALIDATION_PEM   if $self->web_id_object->certificate;
	return;
}

sub cert_modulus
{
	my $self = shift;
	$self->web_id_object->certificate->modulus(@_);
}

sub cert_exponent
{
	my $self = shift;
	$self->web_id_object->certificate->exponent(@_);
}

sub cert_not_before
{
	my $self = shift;
	$self->web_id_object->certificate->not_before(@_);
}

sub cert_not_after
{
	my $self = shift;
	$self->web_id_object->certificate->not_after(@_);
}

sub subject_endpoint
{
	my $self = shift;
	if ($self->is_secure and $self->web_id_object->first_valid_san->can('finger'))
	{
		return $self->web_id_object->first_valid_san->finger->endpoint;
	}
	return;
}

sub _build_session
{
	require CGI::Session;
	
	my $s = CGI::Session->new('driver:file', undef, {Directory => File::Spec->tmpdir});
	$s->expire('+1h');
	return $s;
}

1;

__END__

=head1 NAME

CGI::Auth::FOAF_SSL - authentication using WebID (FOAF+SSL)

=head1 DEPRECATION

CGI::Auth::FOAF_SSL was the original WebID module for Perl, but it is
now deprecated in favour of L<Web::ID>.

L<Web::ID> has a cleaner interface and is less CGI-specific. It should
work equally well in other HTTPS contexts. It has L<Plack> middleware
(but its core does not rely on Plack). Use it.

CGI::Auth::FOAF_SSL 1.9xx and above is now just a backwards-compatibility
wrapper around L<Web::ID>. It will be maintained until at least June 2013.

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

Copyright (C) 2009-2012 by Toby Inkster

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

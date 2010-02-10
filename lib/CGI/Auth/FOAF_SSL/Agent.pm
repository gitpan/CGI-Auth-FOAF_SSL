package CGI::Auth::FOAF_SSL::Agent;

use base 'CGI::Auth::FOAF_SSL::CertifiedThing';

our $VERSION = '1.00_01';

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

__END__

=head1 NAME

CGI::Auth::FOAF_SSL::Agent - an agent (in the FOAF sense)

=head1 SYNOPSIS

  my $auth = CGI::Auth::FOAF_SSL->new_from_cgi;
  if ($auth->is_secure)
  {
    my $user = $auth->agent;
    if ($user)
    {
      my $name = $user->name;
      my $link = $user->homepage;
    }
  }

=head1 DESCRIPTION

CGI::Auth::FOAF_SSL::Agent inherits from
L<CGI::Auth::FOAF_SSL::CertifiedThing>, so any methods that apply
to a CertifiedThing apply to agents too.

CGI::Auth::FOAF_SSL::Agent provides some additional methods.

=head2 Public Methods

=over 4

=item C<< $user->name >>

The name of an agent (e.g. a person's name).

=item C<< $user->homepage >>

Gets the URL of the agent's homepage.

=item C<< $user->img >>

Gets the URL of an image or depiction of the agent.

=item C<< $user->mbox >>

Gets an e-mail address (including "mailto:") to communicate with
the agent.

=back

=head1 BUGS

Please report any bugs to L<http://rt.cpan.org/>.

=head1 SEE ALSO

L<CGI::Auth::FOAF_SSL>, L<CGI::Auth::FOAF_SSL::CertifiedThing>.

=head1 AUTHOR

Toby Inkster, E<lt>tobyink@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2009-2010 by Toby Inkster

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8 or,
at your option, any later version of Perl 5 you may have available.

=cut


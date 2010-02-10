package CGI::Auth::FOAF_SSL::OnlineAccount;

use base 'CGI::Auth::FOAF_SSL::CertifiedThing';

our $VERSION = '1.00_01';

sub name
{
	my $this = shift;
	return $this->getter('name',
		'http://xmlns.com/foaf/0.1/accountName',
		'http://www.w3.org/2000/01/rdf-schema#label',
		'http://xmlns.com/foaf/0.1/name');
}

sub homepage
{
	my $this = shift;
	return $this->getter('homepage',
		'http://xmlns.com/foaf/0.1/accountProfilePage',
		'http://xmlns.com/foaf/0.1/page');
}

sub service_homepage
{
	my $this = shift;
	return $this->getter('homepage',
		'http://xmlns.com/foaf/0.1/accountServiceHomepage');
}


1;

__END__

=head1 NAME

CGI::Auth::FOAF_SSL::OnlineAccount - an online account (in the FOAF sense)

=head1 SYNOPSIS

  my $auth = CGI::Auth::FOAF_SSL->new_from_cgi;
  if ($auth->is_secure)
  {
    my $online_acct = $auth->account;
    if ($online_acct)
    {
      my $acct_name = $online_acct->name;
      my $acct_link = $online_acct->homepage;
    }
  }

=head1 DESCRIPTION

CGI::Auth::FOAF_SSL::OnlineAccount inherits from
L<CGI::Auth::FOAF_SSL::CertifiedThing>, so any methods that apply
to a CertifiedThing apply to accounts too.

CGI::Auth::FOAF_SSL::OnlineAccount provides some additional methods.

=head2 Public Methods

=over 4

=item C<< $account->name >>

Gets the username associated with the account.

=item C<< $account->homepage >>

Gets the URL of the profile page associated with the account.

=item C<< $account->service_homepage >>

Gets the URL for the homepage of the account I<provider>.

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

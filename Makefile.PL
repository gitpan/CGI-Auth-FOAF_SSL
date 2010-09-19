use strict;
use warnings;

use inc::Module::Install;

my $dist = 'CGI-Auth-FOAF_SSL';
my $fn   = "lib/$dist.pm"; $fn =~ s#-#/#g;

name                $dist;
perl_version_from   $fn;
version_from        $fn;
abstract_from       $fn;
readme_from         $fn;
author              'Toby Inkster <tobyink@cpan.org>';
license             'perl';

requires            'CGI'                => 0;
requires            'CGI::Session'       => 0;
requires            'common::sense'      => 0;
requires            'Crypt::OpenSSL::X509' => 0;
requires            'Crypt::X509'        => 0;
requires            'DateTime'           => 0;
requires            'DateTime::Format::Strptime' => 0;
requires            'LWP::UserAgent'     => 0;
requires            'Math::BigInt'       => 0;
requires            'MIME::Base64'       => 0;
requires            'RDF::TrineShortcuts'=> '0.100';
test_requires       'Test::More'         => '0.61';
recommends          'WWW::Finger'        => '0.100';

resources(
	'homepage'   => "http://search.cpan.org/dist/$dist/",
	'repository' => "http://goddamn.co.uk/viewvc/perlmods/$dist/",
	'bugtracker' => "http://rt.cpan.org/Dist/Display.html?Queue=$dist",
	);

keywords 'WebID', 'FOAF', 'SSL', 'FOAF+SSL', 'Authentication', 'Security', 'HTTPS';

write_doap_changes;
write_doap_changes_xml;

include 'Test::Signature';
auto_install;
WriteAll(
	'meta' => 1,
	'sign' => 1,
	);

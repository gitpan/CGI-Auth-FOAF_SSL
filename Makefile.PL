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

test_requires       'Test::More' => '0.61';

requires            'Carp'               => 0;
requires            'CGI'                => 0;
requires            'CGI::Session'       => 0;
requires            'Encode'             => 0;
requires            'IPC::Open2'         => 0;
requires            'LWP::UserAgent'     => 0;
requires            'Math::BigInt'       => 0;
requires            'RDF::TrineShortcuts'=> '0.100';
requires            'WWW::Finger'        => '0.100';

# install_script 'fingerw';

requires_external_bin 'openssl';

resources(
	'homepage'   => "http://search.cpan.org/dist/$dist/",
	'repository' => "http://goddamn.co.uk/viewvc/perlmods/$dist/",
	'bugtracker' => "http://rt.cpan.org/Dist/Display.html?Queue=$dist",
	);
	
write_doap_changes;
write_doap_changes_xml;

include 'Test::Signature';
auto_install;
WriteAll(
	'meta' => 1,
	'sign' => 1,
	);

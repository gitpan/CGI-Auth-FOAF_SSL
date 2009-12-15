use strict;
use warnings;

use inc::Module::Install;

license             'perl';

name                'CGI-Auth-FOAF_SSL';
author              'Toby Inkster <tobyink@cpan.org>';
perl_version_from   'lib/CGI/Auth/FOAF_SSL.pm';
version_from        'lib/CGI/Auth/FOAF_SSL.pm';
abstract_from       'lib/CGI/Auth/FOAF_SSL.pm';
readme_from         'lib/CGI/Auth/FOAF_SSL.pm';

test_requires       'Test::More'         => '0.61';

requires            'Carp'               => 0;
requires            'CGI'                => 0;
requires            'CGI::Session'       => 0;
requires            'IPC::Open2'         => 0;
requires            'LWP::UserAgent'     => 0;
requires            'RDF::Query'         => '2.200';
requires            'RDF::Query::Client' => '0.03';
requires            'RDF::RDFa::Parser'  => '0.21';
requires            'RDF::Trine'         => '0.112';
requires            'WWW::Finger'        => '0.03';

requires_external_bin 'openssl';

auto_set_homepage;
auto_set_bugtracker;

include 'Test::Signature';

auto_install;
WriteAll(
	'meta' => 1,
	'sign' => 1,
	);

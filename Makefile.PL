use strict;
use warnings;

use inc::Module::Install;

license             'perl';

name                'CGI-Auth-FOAF_SSL';
author              'Toby Inkster <tobyink@cpan.org>';
perl_version_from   'lib/CGI/Auth/FOAF_SSL.pm';
version_from        'lib/CGI/Auth/FOAF_SSL.pm';
abstract_from       'lib/CGI/Auth/FOAF_SSL.pm';

test_requires       'Test::More'         => '0.61';

requires            'Carp'               => 0;
requires            'CGI'                => 0;
requires            'CGI::Session'       => 0;
requires            'IPC::Open2'         => 0;
requires            'LWP::UserAgent'     => 0;
requires            'RDF::Query'         => '2.200';
requires            'RDF::Query::Client' => '0.03';
requires            'RDF::RDFa::Parser'  => '0.21';
requires            'RDF::Trine'         => '0.111';
requires            'WWW::Finger'        => '0.01';

requires_external_bin 'openssl';

include 'Test::Signature';

auto_install;
WriteAll(
	'meta' => 1,
	'sign' => 1,
	);

use Pod::Text;
my $parser = Pod::Text->new (sentence => 0, width => 78);
$parser->parse_from_file('lib/CGI/Auth/FOAF_SSL.pm', 'README');

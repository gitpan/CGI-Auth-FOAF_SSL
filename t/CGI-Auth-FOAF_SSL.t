#########################

use Test::More tests => 3;
BEGIN { use_ok('CGI::Auth::FOAF_SSL') };

#########################

ok(-x '/usr/bin/openssl', '/usr/bin/openssl exists and is executable');

ok(CGI::Auth::FOAF_SSL::ua_string =~ /^CGI::Auth::FOAF_SSL\/\d/, 'UA String looks sane');

# Any serious testing involves making HTTP connections, which is a privacy
# concern, so we'll just leave it at that for now.

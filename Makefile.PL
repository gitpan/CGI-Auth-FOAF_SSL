use 5.010000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'CGI::Auth::FOAF_SSL',
    VERSION_FROM      => 'lib/CGI/Auth/FOAF_SSL.pm', # finds $VERSION
    PREREQ_PM         => {
    	'RDF::Redland' => 1,
    	'CGI'          => 3,
    	'Carp'         => 1,
    	'IPC::Open2'   => 1,
    }, 
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/CGI/Auth/FOAF_SSL.pm', # retrieve abstract from module
       AUTHOR         => 'Toby Inkster <mail@tobyinkster.co.uk>') : ()),
);

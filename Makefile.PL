package Uttu::Framework::Uttu;

use lib q:/usr/local/apache/perl/uttu/lib:;
use Uttu::MakeMaker;

WriteMakefile(
  NAME         => __PACKAGE__,
  VERSION_FROM => 'Uttu.pm',
  AUTHOR       => 'James Smith <jgsmith@cpan.org>',
  ABSTRACT_FROM => 'Uttu.pm',
  PREREQ_PM    => {
		   Uttu::MakeMaker => 0.01,
                  },
);

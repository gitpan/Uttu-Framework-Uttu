package Uttu::Framework::Uttu;

use Uttu::Framework;

use vars qw{ @ISA $VERSION };

@ISA = qw{ Uttu::Framework };

$VERSION = 0.01;

1;

__END__

=head1 NAME

Uttu::Framework::Uttu - framework for Uttu site

=head1 SYNOPSIS

 [global]
  
 content_handler = mason
 framework = Uttu

=head1 DESCRIPTION

This is the framework for the L<uttu.tamu.edu|http://uttu.tamu.edu/> site
and serves as an example of how a framework is built.

The framework provides authentication and authorization services as well as
session and context management.

=head1 CONFIGURATION

A minimal configuration file is included in the distribution C<conf>
directory.

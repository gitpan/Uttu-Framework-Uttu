package Uttu::Framework::Uttu::Auth;

# configuration info for Mason
use AppConfig qw- :argcount -;
use strict;

sub init {
  Uttu -> define(
    auth_sidebar => {
	ARGCOUNT => ARGCOUNT_ONE,
	DEFAULT => 0,
	VALIDATE => q:^\d+$:,
	ACTION => sub { Uttu->register_component("sidebar", 
				$_[2], 'auth/general/sidebar'); },
    },
    auth_title => {
	ARGCOUNT => ARGCOUNT_ONE,
	DEFAULT => 'Login',
    },
    auth_authenticated_title => {
        ARGCOUNT => ARGCOUNT_ONE,
	DEFAULT => 'Logged In',
    },
    auth_method => {
	ARGCOUNT => ARGCOUNT_ONE,
	VALIDATE => sub {
	    no strict 'refs';
	    my $value = $_[1];

            local(@INC) = @INC;
	    eval {
                push @INC, map { Apache -> server_root_relative($_) } @{Uttu -> config -> global_lib || []};
	    };

	    eval qq{require Uttu::Framework::Uttu::Auth::$value};
	    return if $@;
	    eval {
	        "Uttu::Framework::Uttu::Auth::$value" -> init_config();
            };
	    return 1 unless $@;
            },
    },
    auth_priority => {
	ARGCOUNT => ARGCOUNT_ONE,
	VALIDATE => q:^\d+$:,
	ACTION => sub { Uttu->register_component("initializer", 
				$_[2], 'auth/general/init'); }
    },
  );

  1;
}

1;

package Uttu::Framework::Uttu::Auth::krb5;
use strict;

# configuration info for krb5 authentication
use AppConfig qw- :argcount -;
use Authen::Krb5 ();
use Error qw= :try =;

our %servers;
our %conversions;

sub init_config {
    Uttu -> define(
	auth_krb5_realm => {
	    ARGCOUNT => ARGCOUNT_ONE,
            VALIDATE => \&_validate_realm,
        },
	auth_krb5_username_filter => {
	    ARGCOUNT => ARGCOUNT_ONE,
	    VALIDATE => q{^(\w+(::|->))*\w+$},
        },
	auth_krb5_username_suffix => {
	    ARGCOUNT => ARGCOUNT_ONE,
	    DEFAULT => '',
        },
	auth_krb5_username_prefix => {
	    ARGCOUNT => ARGCOUNT_ONE,
	    DEFAULT => '',
        },
    );
}

BEGIN {
  try {
    Authen::Krb5::init_context();
    Authen::Krb5::init_ets();
  } otherwise {
    # already initialized, perhaps
  };
}

sub valid_realm {
    my($value) = @_;

    return 1 if $servers{$value};

    my $ret = 0;

    try {
        my $server = "krbtgt/$value\@$value";
        $servers{$value} = Authen::Krb5::parse_name($server) or throw Error::Simple "Unable to parse server name ($server)\n";
	$ret = 1;
    } otherwise {
        # ignore error, but spit it out during server startup
        warn((shift -> text)."\n");
    };

    return $ret;
}

sub _validate_realm {
    my($variable, $value) = @_;

    return valid_realm($value);
}

sub authenticate {
    my($self, $username, $password) = @_;

    my $c = Uttu -> config;
    my $realm = $c -> auth_krb5_realm;

    return unless valid_realm($realm);

    Uttu::_log("authenticate($username, password)\n");

    Uttu::_log("server => $servers{$realm}\n");
    return unless $servers{$realm};

    my $uc;

    if($uc = $c -> auth_krb5_username_filter) {
        no strict 'refs';
	$conversions{$uc} = eval qq{sub { $uc \$_[0] } } unless $conversions{$uc};
        $username = $conversions{$uc} -> ($username);
    }
    $username = $c -> auth_krb5_username_prefix . $username . $c -> auth_krb5_username_suffix;

    length $password < 30 or throw Error::Simple "Password is too long.";
    my $u = Authen::Krb5::parse_name(join('@', $username, $realm) )
                                 or throw Error::Simple "Unable to understand username.";
    my $cc= Authen::Krb5::cc_resolve("MEMORY:")
                                 or throw Error::Simple "Unable to resolve cache.";
    Authen::Krb5::get_in_tkt_with_password($u, $servers{$realm}, $password, $cc)
                                 or return 0;

    return 1;
}

1;

__END__

=head1 NAME

Uttu::Framework::Uttu::Auth::krb5 - Kerberos V authentication

=head1 SYNOPSIS

 [auth]
 method krb5
 krb5_realm  MY.KRB5.DOMAIN
 krb5_username_filter lc
 krb5_username_suffix /web

=head1 DESCRIPTION

This module provides Kerberos V authentication for the Uttu framework.

=head1 CONFIGURATION

All configuration variables are in the [auth] configuration block.

=over 4

=item krb5_realm

This is the Kerberos V realm.  The realm must be a valid realm.

=item krb5_username_filter

This is the name of a function the username will be passed to.  The return
value is used in place of the username.

 krb5_username_filter lc

This will lowercase the username.

 krb5_username_filter My::Module->username_transform

This will call C<My::Module->username_transform($username)> and use the
return value in place of the username.

=item krb5_username_prefix

This string is prepended to the username after the username is passed through the
username filter.

=item krb5_username_suffix

This string is appended to the username after the username is passed
through the username filter.

=back 4

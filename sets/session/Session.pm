package Uttu::Framework::Uttu::Session;

use AppConfig qw- :argcount -;
use Apache::Session::Flex;
use Uttu::Tools ();
use strict;

sub _check_asf {
  my($tier1, $tier2) = @_;
  no strict 'refs';

  local(@INC) = @INC;
  eval {
      push @INC, map { Apache -> server_root_relative($_) } @{Uttu -> config -> global_lib || []};
  };

  eval qq{require Apache::Session::$tier1\::$tier2};
  return 1 unless $@;
  warn "$@\n";
  return;
}


sub init {
  Uttu -> define(
    session_store => {
        ARGCOUNT => ARGCOUNT_ONE,
        VALIDATE => sub { _check_asf('Store', $_[1]); },
    },
    session_lock => {
        ARGCOUNT => ARGCOUNT_ONE,
        VALIDATE => sub { _check_asf('Lock', $_[1]); },
    },
    session_generate => {
        ARGCOUNT => ARGCOUNT_ONE,
        VALIDATE => sub { _check_asf('Generate', $_[1]); },
    },
    session_serialize => {
        ARGCOUNT => ARGCOUNT_ONE,
        VALIDATE => sub { _check_asf('Serialize', $_[1]); },
    },
    session_option => {
        ARGCOUNT => ARGCOUNT_HASH,
    },
    Uttu::Tools::define_db("session_db"),
    session_cookie_name => {
        ARGCOUNT => ARGCOUNT_ONE,
        DEFAULT => 'SESSION_ID',
        VALIDATE => q:^\S+$:,
    },
    session_priority => {
        ARGCOUNT => ARGCOUNT_ONE,
        VALIDATE => q:^\d+$:,
        ACTION => sub { Uttu->register_component("initializer",
                                $_[2], 'session/init'); }
    },
  );

  1;
}

sub new {
  my($class) = shift;

  my $u = Uttu -> new;

  Uttu::_log("new session: u => $u\n");

  return unless $u;

  my $c = $u -> config;

  Uttu::_log("new session: c => $c\n");

  return unless $c;

  my $dbh = $u -> query_dbh("session_db", Write => 1);

  Uttu::_log("new session: dbh => $dbh\n");

  return unless $dbh;

  my %session;

  eval {
    tie %session, 'Apache::Session::Flex', undef, {
      %{$c -> session_option || {}},
      Store => $c -> session_store,
      Lock  => $c -> session_lock,
      Generate => $c -> session_generate,
      Serialize => $c -> session_serialize,
      Handle => $dbh,
      Commit => 1 };

    $class = ref $class || $class;
    return bless \%session => $class;
  };
  Uttu::_log("new session error: $@\n");
  return;
}

sub retrieve {
  my($class, $session_id) = @_;

  my $u = Uttu -> new;

  return unless $u;

  my $c = $u -> config;

  return unless $c;

  my $dbh = $u -> query_dbh("session_db", Write => 1);

  return unless $dbh;

  my %session;

  eval {
    tie %session, 'Apache::Session::Flex', $session_id, {
      %{$c -> session_option || {}},
      Store => $c -> session_store,
      Lock  => $c -> session_lock,
      Generate => $c -> session_generate,
      Serialize => $c -> session_serialize,
      Handle => $dbh,
      Commit => 1 };

    $class = ref $class || $class;
    return bless \%session => $class;
  };
  return;
}

sub delete {
  my($self, $session_id) = @_;

  my $s = $self -> retrieve($session_id);

  tied(%$s) -> delete if $s;
}

1;

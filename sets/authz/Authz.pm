package Uttu::Framework::Uttu::Authz;

#use lib q:/usr/local/apache/perl/uttu/lib:;
use Uttu::Tools;
use AppConfig qw- :argcount -;
use Quantum::Superpositions qw: all any :;

sub init {
  Uttu -> define(
    Uttu::Tools::define_db("authz_db"),
    Uttu::Tools::define_cache("authz_cache"),
    'authz_realm' => {
        DEFAULT => 'uttu',
	ARGCOUNT => ARGCOUNT_ONE,
    },
    'authz_path_seperater' => {
        DEFAULT => '/',
        ARGCOUNT => ARGCOUNT_ONE,
     },
  );

  1;
}

#create table access (
#   type char(8) not null,
#   id   char(48) not null,
#   domain char(32) not null,
#   resource_type char(16) not null,
#   resource_path char(255) not null,
#   allow char(16),
#   deny  char(16)
# );
#
#alter table access add index(type,id,domain,resource_type);
#alter table access add index(domain,resource_type,resource_path);
#
#create table access_groups (
#   type char(8) not null,
#   id   char(48) not null,
#   name char(48) not null
# );
#
#alter table access_groups add index(type,id);
#alter table access_groups add index(name);

sub query_attrs {
  my($self, $type, $path) = @_;

  my $u = Uttu -> new;

  my $cache = $u -> query_cache("authz_cache");

  my $perms = $cache -> get("perm:$type:$path");

  unless($perms) {
    my $dbh = $u -> query_dbh("authz_db");
    my $sth = $dbh -> prepare_cached(q{
        SELECT type,id,allow,deny 
        FROM access 
        WHERE domain=? AND resource_type=? AND resource_path=?
    });
    $perms = { };
    if($sth -> execute($c -> authz_realm, $type, $path)) {
      my @row;
      my $lkey;
      while(@row = $sth -> fetchrow_array) {
        $lkey = "$row[0]:$row[1]";
        $perms->{$lkey} ||= [ [], [] ];
        push @{$perms->{$lkey}->[0]}, $row[2];
        push @{$perms->{$lkey}->[1]}, $row[3];
      }
      $sth -> finish;
    }
    $cache -> set("perm:$type:$path", $perms);
  }

  return $perms;
}

sub query_groups {
  my($self, $type, $id) = @_;

  return [] if !$id || !$type || ($type eq "group" && $id eq "EVERYTHING");

  my $u = Uttu -> new;

  my $cache = $u -> query_cache("authz_cache");

  my $groups = $cache -> get("group:$type:$id");

  unless($groups) {
    my $dbh = $u -> query_dbh("authz_db");
    my $sth = $dbh -> prepare_cached(q{SELECT name FROM access_groups WHERE domain=? AND type=? AND id=?});
    $groups = [ ];
    if($sth -> execute($c -> authz_realm, $type, $id)) {
      push @$groups, @row while @row = $sth -> fetchrow;
      $sth -> finish;
    }
    $cache -> set("group:$type:$id", $groups);
  }

  return $groups;
}

sub query_member {
  my($self, $type, $id, $group) = @_;

  return 1 if $group eq any(@{$self -> query_groups($type, $id)});
  return 0;
}

sub query_attributes {
  my($self, $type, $id, $rtype, $rpath, $cache_exp) = @_;

  my $u = Uttu -> new;

  my $cache = $u -> query_cache("authz_cache");

  my $attrs = $cache->get("attrs:$type:$id");

  unless($attrs) {
    $attrs = { };
    my @bits = split($c -> authz_path_seperater, $rpath);
    my $p;
    for(my $i = 0; $i < sizeof(@bits); $i++) {
      $p = join($c -> authz_path_seperater, @bits[0..$i]);
      my $a = $self -> _query_attributes($id, $type, $rtype, $p);
      if($a) {
        delete @{$attrs}{@{$a->[1]}};
        @{$attrs}{@{$a->[0]}} = ( );
      }
    }
    $attrs = [ keys %$attrs ];
    $cache->set("attrs:$type:$id", $attrs, $cache_exp);
  }

  return [ @{$attrs} ];
}

sub _query_attributes {
  my($self, $type, $id, $rtype, $path) = @_;

  my(%allowed, %disallowed);

  my $groups = $self -> query_groups($type, $id);
  my $found;

  foreach my $g (@$groups) {
    my $p = $self -> _query_attributes("group", $g, $rtype, $path);
    if($p) {
      @allowed{@{$p->[0] || []}} = ( );
      @disallowed{@{$p->[1] || []}} = ( );
      $found = 1;
    }
  }

  my $a = $self -> query_attrs($rtype, $path);
  if(exists $a -> {"$type:$id"}) {
    @allowed{@{$a->{"$type:$id"}->[0]}} = ();
    @disallowed{@{$a->{"$type:$id"}->[1]}} = ();
    $found = 1;
  }

  return [ [ keys %allowed ], [ keys %disallowed ] ] if $found;

  return 0;
}

# example:
#   ->has_attributes($type, $id, $rtype, $rpath, all(qw:read write execute:))
# or
#   ->has_attributes($type, $id, $rtype, $rpath, any(qw:write modify:))
# in which case, calling eigenstates() on the returned value will give the
#   attributes which matched
sub has_attributes {
  my($self, %args) = @_;

  my $p = $self -> query_attributes(@args{qw:uid_type uid resource_type resource CACHE_EXPIRE:});

  return $args{attributes} eq any($p);
}

sub user_has_attributes {
  my $self = shift;
  my $u = Uttu -> new;
  return $self -> has_attributes(uid_type => "user", uid => $u -> note("uid"), @_);
}

###
### now to do the granting stuff...
###

### grant - allows one person to grant their allowed list to another
###         allows one person to deny their allowed list to another
### authz_admin - allows one to grant/deny any attribute

sub test_modify_attributes {
  my($self, %args) = @_;

  $allowed = $args{allowed} || [];
  $denied  = $args{denied}  || [];

  return if any(@{$allowed}) eq any(@{$denied});

  return unless $self -> user_has_attributes (
      resource_type => $args{resource_type},
      resource      => $args{resource},
      attributes => all (
	  any(qw< grant authz_admin >), 
	  all(@{$allowed}), 
	  all(@{$denied})
      ) 
  );

  return if ("grant" eq any(@{$allowed}) || "grant" eq any(@{$denied})) 
	  && !$self -> user_has_attributes($rtype, $rpath, "authz_admin");

  return 1;
}

sub _modify_attributes {
  my($self, %args) = @_;

  $allowed = $args{allowed} || [];
  $denied = $args{denied} || [];

  my $ad = any(@{$denied});
  my $aa = any(@{$allowed});

  return if $ad eq $aa;

  my $u = Uttu -> new;
  my $c = $u -> config;

  my $dbh = $u -> query_dbh("authz_db", Write => 1);

  return unless $dbh;

  # do the actual modification here...
  # delete from table where domain=? AND type=$ttype AND id=$tid AND resource_type=$rtype AND resource_id=$rpath
  # insert into table (domain, type, id, resource_type, resource_id, allowed, disallowed) values (?,?,?,?,?,?,?)
  # cycle through allowed/denied in pairs until all used up

#   type char(8) not null,
#   id   char(48) not null,
#   domain char(32) not null,
#   resource_type char(16) not null,
#   resource_path char(255) not null,
#   allow char(16),
#   deny  char(16)

  my @dargs = ($c -> authz_realm, @args{qw:uid_type uid resource_type resource:});

  my $sth = $dbh -> prepare_cached("SELECT allow,deny FROM access WHERE domain=? AND type=? AND id=? AND resource_type=? AND resource_id=?");
  if($sth -> execute(@dargs)) {
    while(@row = $sth -> fetchrow) {
      push @{$allowed}, $row[0] unless $row[0] eq $ad;
      push @{$denied}, $row[1] unless $row[1] eq $aa;
    }
    $sth -> finish;
  }

  $sth = $dbh -> prepare_cached("DELETE FROM access WHERE domain=? AND type=? AND id=? AND resource_type=? AND resource_id=?");
  $sth -> finish if $sth -> execute(@dargs);

  my $n = @{$allowed};
  $n = @{$denied} if @{$denied} > $n;

  $sth = $dbh -> prepare_cached("INSERT INTO access (domain, type, id, resource_type, resource_id, allow, deny) values (?,?,?,?,?,?,?)");
  for($i = 0; $i < $n; $i++) {
    $sth -> execute(@dargs, $allowed->[$i], $denied->[$i]);
  }

  return 1;
}

sub modify_attributes {
  my($self, %args) = @_;

  return unless $self -> test_modify_attributes(%args);

  return $self -> _modify_attributes(%args);
}

1;

__END__

=head1 NAME

Uttu::Framework::Uttu::Authz - authorization support for the Uttu framework

=head1 SYNOPSIS

 [authz_db]
   database
   username
   password
   driver
   option
 [authz_cache]
   namespace
   expiration
   auto_purge_interval
   size_limit
   sharedmemory

=head1 DESCRIPTION



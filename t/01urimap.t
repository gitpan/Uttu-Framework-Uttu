#!/usr/local/bin/perl

use strict;
use warnings FATAL => 'all';;

use Apache::Test;
use Apache::TestRequest;

unless(open FH, "< ./conf/urimap") {
  plan tests => 1;
  ok 0;
  exit;
}

my $n = 1;

while(<FH>) {
  next if /^s*$/;
  next if /^s*#/;
  $n++;
}

close FH;

open FH, "< ./conf/urimap";

plan tests => $n;

ok 1;

while(<FH>) {
  chomp;
  next if /^s*$/;
  next if /^s*#/;
  my @bits = split(/s+/, $_);
  # bits = qw: uri file status :;
  if($bits[2] && $bits[2] ne 'OK') {
    ok do something else
  } else {
    ok GET $bits[0];
  }
}

close FH;

#!/usr/local/bin/perl

use strict;
use warnings FATAL => 'all';

use Apache::Test;

plan tests => 4;

ok require 5.005002;
ok require mod_perl;
ok $mod_perl::VERSION >= 1.24;
ok require Uttu;

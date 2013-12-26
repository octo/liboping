# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Oping.t'

#########################

# change 'tests => 2' to 'tests => last_test_to_print';

use Test::More tests => 5;
BEGIN { use_ok('Net::Oping') };

my $obj = Net::Oping->new ();
ok (defined ($obj), 'Constructor');

ok ($obj->timeout (2.0), 'Set timeout');
ok ($obj->ttl (64), 'Set TTL');

is ($obj->get_error (), 'Success', 'Get error')

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.


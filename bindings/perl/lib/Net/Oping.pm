#
# Net-Oping - lib/Net/Oping.pm
# Copyright (C) 2007       Olivier Fredj
# Copyright (C) 2008,2009  Florian octo Forster
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; only version 2 of the License is
# applicable.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#
# Authors:
#   Olivier Fredj <ofredj at proxad.net>
#   Florian octo Forster <ff at octo.it>
#

package Net::Oping;

=head1 NAME

Net::Oping - ICMP latency measurement module using the oping library.

=head1 SYNOPSIS

  use Net::Oping ();

  my $obj = Net::Oping->new ();
  $obj->host_add (qw(one.example.org two.example.org));
  
  my $ret = $obj->ping ();
  print "Latency to `one' is " . $ret->{'one.example.org'} . "\n";

=head1 DESCRIPTION

This Perl module is a high-level interface to the
L<oping library|http://noping.cc/>. Its purpose it to send C<ICMP ECHO_REQUEST>
packets (also known as "ping") to a host and measure the time that elapses
until the reception of an C<ICMP ECHO_REPLY> packet (also known as "pong"). If
no such packet is received after a certain timeout the host is considered to be
unreachable.

The used I<oping> library supports "ping"ing multiple hosts in parallel and
works with IPv4 and IPv6 transparently. Other advanced features that are
provided by the underlying library, such as setting the data sent, are not yet
supported by this interface.

=cut

use 5.006;

use strict;
use warnings;

use Carp (qw(cluck confess));

our $VERSION = '1.21';

require XSLoader;
XSLoader::load ('Net::Oping', $VERSION);
return (1);

=head1 INTERFACE

The interface is kept simple and clean. First you need to create an object to
which you then add hosts. Using the C<ping> method you can request a latency
measurement and get the current values returned. If necessary you can remove
hosts from the object, too.

The constructor and methods are defined as follows:

=over 4

=item I<$obj> = Net::Oping-E<gt>B<new> ();

Creates and returns a new object.

=cut

sub new
{
  my $pkg = shift;
  my $ping_obj = _ping_construct ();

  my $obj = bless ({ c_obj => $ping_obj }, $pkg);
  return ($obj);
}

sub DESTROY
{
  my $obj = shift;
  _ping_destroy ($obj->{'c_obj'});
}

=item I<$status> = I<$obj>-E<gt>B<timeout> (I<$timeout>);

Sets the timeout before a host is considered unreachable to I<$timeout>
seconds, which may be a floating point number to specify fractional seconds.

=cut

sub timeout
{
  my $obj = shift;
  my $timeout = shift;
  my $status;

  $status = _ping_setopt_timeout ($obj->{'c_obj'}, $timeout);
  if ($status != 0)
  {
    $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    return;
  }

  return (1);
}

=item I<$status> = I<$obj>-E<gt>B<ttl> (I<$ttl>);

Sets the I<Time to Live> (TTL) of outgoing packets. I<$ttl> must be in the
range B<1>E<nbsp>...E<nbsp>B<255>. Returns true when successful and false
when an error occurred.

=cut

sub ttl
{
  my $obj = shift;
  my $ttl = shift;
  my $status;

  $status = _ping_setopt_ttl ($obj->{'c_obj'}, $ttl);
  if ($status != 0)
  {
    $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    return;
  }

  return (1);
}

=item I<$status> = I<$obj>-E<gt>B<bind> (I<$ip_addr>);

Sets the source IP-address to use. I<$ip_addr> must be a string containing an
IP-address, such as "192.168.0.1" or "2001:f00::1". As a side-effect this will
set the address-family (IPv4 or IPv6) to a fixed value, too, for obvious
reasons.

=cut

sub bind
{
  my $obj = shift;
  my $addr = shift;
  my $status;

  $status = _ping_setopt_source ($obj->{'c_obj'}, $addr);
  if ($status != 0)
  {
    $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    return;
  }

  return (1);
}

=item I<$status> = I<$obj>-E<gt>B<device> (I<$device>);

Sets the network device used for communication. This may not be supported on
all platforms.

I<Requires liboping 1.3 or later.>

=cut

sub device
{
  my $obj = shift;
  my $device = shift;
  my $status;

  $status = _ping_setopt_device ($obj->{'c_obj'}, $device);
  if ($status == -95) # Feature not supported.
  {
    $obj->{'err_msg'} = "Feature not supported by your version of liboping.";
  }
  elsif ($status != 0)
  {
    $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    return;
  }

  return (1);
}

=item I<$status> = I<$obj>-E<gt>B<host_add> (I<$host>, [I<$host>, ...]);

Adds one or more hosts to the Net::Oping-object I<$obj>. The number of
successfully added hosts is returned. If this number differs from the number of
hosts that were passed to the method you can use B<get_error> (see below) to
get the error message of the last failure.

=cut

sub host_add
{
  my $obj = shift;
  my $i;

  $i = 0;
  for (@_)
  {
    my $status = _ping_host_add ($obj->{'c_obj'}, $_);
    if ($status != 0)
    {
      $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    }
    else
    {
      $i++;
    }
  }

  return ($i);
}

=item I<$status> = I<$obj>-E<gt>B<host_remove> (I<$host>, [I<$host>, ...]);

Same semantic as B<host_add> but removes hosts.

=cut

sub host_remove
{
  my $obj = shift;
  my $i;

  $i = 0;
  for (@_)
  {
    my $status = _ping_host_remove ($obj->{'c_obj'}, $_);
    if ($status != 0)
    {
      $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    }
    else
    {
      $i++;
    }
  }
  return ($i);
}

=item I<$latency> = I<$obj>-E<gt>B<ping> ()

The central method of this module sends ICMP packets to the hosts and waits for
replies. The time it takes for replies to arrive is measured and returned.

The returned scalar is a hash reference where each host associated with the
I<$obj> object is a key and the associated value is the corresponding latency
in milliseconds. An example hash reference would be:

  $latency = { host1 => 51.143, host2 => undef, host3 => 54.697, ... };

If a value is C<undef>, as for "host2" in this example, the host has timed out
and considered unreachable.

=cut

sub ping
{
  my $obj = shift;
  my $iter;
  my $data = {};
  my $status;

  $status = _ping_send ($obj->{'c_obj'});
  if ($status < 0)
  {
    $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    return;
  }

  $iter = _ping_iterator_get ($obj->{'c_obj'});
  if (!$iter)
  {
    $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    return;
  }

  while ($iter)
  {
    my $host = _ping_iterator_get_hostname ($iter);
    if (!$host)
    {
      $iter = _ping_iterator_next ($iter);
      next;
    }

    my $latency = _ping_iterator_get_latency ($iter);
    if ($latency < 0.0)
    {
      $latency = undef;
    }

    $data->{$host} = $latency;

    $iter = _ping_iterator_next ($iter);
  }

  return ($data);
} # ping

=item I<$dropped> = I<$obj>-E<gt>B<get_dropped> ()

Returns a hash reference holding the number of "drops" (echo requests which
were not answered in time) for each host. An example return
values would be:

  $droprate = { host1 => 0, host2 => 3, host3 => undef, ... };

Hosts to which no data has been sent yet will return C<undef> ("host3" in thie
example).

=cut

sub get_dropped
{
  my $obj = shift;
  my $iter;
  my $data = {};

  $iter = _ping_iterator_get ($obj->{'c_obj'});
  if (!$iter)
  {
    $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    return;
  }

  while ($iter)
  {
    my $host = _ping_iterator_get_hostname ($iter);
    if (!$host)
    {
      $iter = _ping_iterator_next ($iter);
      next;
    }

    my $dropped = _ping_iterator_get_dropped ($iter);
    if ($dropped < 0)
    {
      $dropped = undef;
    }

    $data->{$host} = $dropped;

    $iter = _ping_iterator_next ($iter);
  }

  return ($data);
} # get_dropped

=item I<$ttl> = I<$obj>-E<gt>B<get_recv_ttl> ()

Returns a hash reference holding the I<Time to Live> (TTL) of the last received
packet for each host. An example return value would be:

  $ttl = { host1 => 60, host2 => 41, host3 => 243, ... };

To signal an invalid or unavailable TTL, a negative number is returned.

=cut

sub get_recv_ttl
{
  my $obj = shift;
  my $iter;
  my $data = {};

  $iter = _ping_iterator_get ($obj->{'c_obj'});
  if (!$iter)
  {
    $obj->{'err_msg'} = "" . _ping_get_error ($obj->{'c_obj'});
    return;
  }

  while ($iter)
  {
    my $host = _ping_iterator_get_hostname ($iter);
    if ($host)
    {
      $data->{$host} = _ping_iterator_get_recv_ttl ($iter);
    }

    $iter = _ping_iterator_next ($iter);
  }

  return ($data);
} # get_recv_ttl

=item I<$errmsg> = I<$obj>-E<gt>B<get_error> ();

Returns the last error that occurred.

=cut

sub get_error
{
  my $obj = shift;
  return ($obj->{'err_msg'} || 'Success');
}

=back

=head1 CAVEATS

The I<oping> library opens a raw socket to be able to send ICMP packets. On
most systems normal users are not allowed to do this. This is why on most
systems the L<ping(1)> utility is installed as SetUID-root. Since, when using
this module, no external process is spawned B<this> process needs the
appropriate permissions. This means that either your script has to run as
superuser or, under Linux, needs the C<CAP_NET_RAW> capability.

=head1 SEE ALSO

L<liboping(3)>

The I<liboping> homepage may be found at L<http://noping.cc/>.
Information about its mailing list may be found at
L<http://mailman.verplant.org/listinfo/liboping>.

=head1 AUTHORS

First XSE<nbsp>port by Olivier Fredj, extended XS functionality and high-level
Perl interface by Florian Forster.

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Olivier Fredj E<lt>ofredjE<nbsp>atE<nbsp>proxad.netE<gt>

Copyright (C) 2008,2009 by Florian Forster E<lt>ffE<nbsp>atE<nbsp>octo.itE<gt>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.7 or,
at your option, any later version of Perl 5 you may have available.

Please note that I<liboping> is licensed under the GPLv2. Derived works of
both, I<Net::Oping> and I<liboping>, (i.E<nbsp>e. binary packages) may
therefore be subject to stricter licensing terms than the source code of this
package.

=cut

# vim: set shiftwidth=2 softtabstop=2 tabstop=8 :

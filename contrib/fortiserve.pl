#!/usr/bin/env perl

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (C) 2015 Lubomir Rintel

=head1 NAME

fortiserve.pl - mockup SSLVPN server

=head1 SYNOPSIS

fortiserve.pl
[-h|--help|-H|--man] |
--cert <file>
--key <file>
--listen <address>:<port>

=head1 DESCRIPTION

B<fortiserve.pl> creates a server for SSLVPN client. It tries to mimic
the Fortinet-compatible behavior for the purposes of testing the client.

=cut

use HTTP::Daemon::SSL;
use HTTP::Request;
use HTTP::Response;
use IO::Pty;
use IO::Poll;
use Getopt::Long;
use Pod::Usage;

use strict;
use warnings;

# Gereate a RFC 1662 (appendix C.1) FCS-16 table
sub fcs16
{
	my @fcs16;

	for (my $b = 0; $b < 256; $b++) {
		my $v = $b;
		$v = ($v & 1) ? ($v >> 1) ^ 0x8408 : ($v >> 1) foreach (0..7);
		push @fcs16, $v & 0xffff;
	}

	return @fcs16;
}

# Calculate a RFC 1662 FCS-16 checksum
sub checksum
{
	my @bytes = map { ord ($_) } split '', shift;
	my $sum = 0xffff;

	our @fcs16;
	BEGIN { @fcs16 = fcs16 () };

	$sum = ($sum >> 8) ^ $fcs16[0xff & ($sum ^ $_)] foreach @bytes;
	return $sum;
}

# Decode one HDLC-like frame without the 0x7e boundaries,
# returns the payload without checksum and address control word
sub decode
{
	my @bytes = map { ord ($_) } split '', shift;
	my $buf = '';

	while (@bytes) {
		my $byte = shift @bytes;

		if ($byte == 0x7d) {
			die unless @bytes;
			$byte = (shift @bytes) ^ 0x20;
		} elsif ($byte < 0x20) {
			next;
		}

		$buf .= chr ($byte);
	}

	my $cksum = checksum ($buf);
	warn if $cksum ne 0xf0b8;

	# Checksum
	$buf =~ s/..$//;

	# Control word: Address
	$buf =~ s/^\xff\x03//;

	return $buf;
}

# Encode one HDLC-like frame, with a 0x7e delimiter at the end
sub encode
{
	my $packet = "\xff\x03".shift;
	my $cksum = checksum ($packet) ^ 0xffff;
	$packet .= chr ($cksum & 0xff).chr ($cksum >> 8);
	my @bytes = map { ord ($_) } split '', $packet;
	my $buf = '';

	while (@bytes) {
		my $byte = shift @bytes;
		my $byte7 = $byte & 0x7f;

		if ($byte < 0x20 or $byte7 == 0x7d or $byte7 == 0x7e) {
			$buf .= "\x7d";
			$byte ^= 0x20;
		}
		$buf .= chr ($byte);
	}

	$buf .= "\x7e";

	return $buf;
}

# Decode the HDLC-like frame and extend with the VPNSSL header
sub pty_decode
{
	my $in = shift;
	my $out = shift;

	my $data;
	($data, $$in) = $$in =~ /(.*\x7e)(.*)/ or return;
	$data =~ s/^\x7e//;
	my @packets = split "\x7e", $data;

	foreach my $packet (@packets) {
		my $decoded = decode ($packet);
		my $len = length $decoded;
		$$out .= pack ('nnna*', $len + 6, 0x5050, $len, $decoded);
	}
}

# Chop off the VPNSSL header, returning the HDLC-like packet
sub client_decode
{
	my $in = shift;
	my $out = shift;

	while (length $$in >= 6) {
		my ($l2, $magic, $len, $data) = unpack ('nnn a*', $$in);

		warn unless $magic == 0x5050;
		warn unless $l2 == $len + 6;
		last unless length $data >= $len;
		($data, $$in) = unpack ("a$len a*", $data);
		$$out .= encode ($data);
	}
}

# Spawn PPP and connect it to the HTTP client socket
sub do_ppp
{
	my $client = shift;

	my $poll = new IO::Poll;
	my $pty = new IO::Pty;
	my $pppd = fork;

	my $client_in = '';
	my $pty_in = '';
	my $client_out = '';
	my $pty_out = "\x7e";

	die $! unless defined $pppd;

	# This disables echo. pppd would disable it too, however the client
	# might race for a chance to talk to us before pppd sets things up and
	# then the client's traffic would be just looped back.
	$pty->slave->set_raw;
	$pty->set_raw;

	$pty->blocking (0);
	$client->blocking (0);

	# debug logfile chudak
	exec ('pppd', $pty->ttyname, qw/38400 noipdefault noaccomp noauth
		ms-dns 6.6.6.7 ms-dns 8.8.8.8 noccp
		default-asyncmap nopcomp nodefaultroute :1.1.1.2 nodetach
		lcp-max-configure 40 usepeerdns mru 1024/) or die $! unless $pppd;

	$poll->mask ($_ => IO::Poll::POLLIN | IO::Poll::POLLERR)
		foreach ($client, $pty);

	do {
		die $! if $poll->poll == -1;

		if ($poll->events ($client) == IO::Poll::POLLIN) {
			my $buf;
			$client->sysread ($buf, 4096);
			exit unless length $buf;
			goto LOGOUT if $buf =~ /^GET/; # *Le sigh* ...
			$client_in .= $buf;
			client_decode (\$client_in, \$pty_out);
		}
		if ($poll->events ($pty) == IO::Poll::POLLIN) {
			my $buf;
			$pty->sysread ($buf, 4096);
			exit unless length $buf;
			$pty_in .= $buf;
			pty_decode (\$pty_in, \$client_out);
		}

		# XXX: these can fail; poll for POLLOUT too!
		if ($client_out) {
			print $client $client_out;
			$client->flush;
			$client_out = '';
		}
		if ($pty_out) {
			print $pty $pty_out;
			$pty->flush;
			$pty_out = '';
		}
	} until ($poll->handles (IO::Poll::POLLERR));

LOGOUT:
	$client->blocking (1);

	kill 'TERM' => $pppd;
}

# Dispatch a response for an URI
sub serve_request
{
	my $client = shift;
	my $request = shift;

	my $response;

	if ($request->uri eq '/remote/logincheck') {
		$response = new HTTP::Response (200 => 'OK', [], 'something');
		$response->header ('Set-Cookie' => 'SVPNCOOKIE=something;');
	} elsif ($request->uri eq '/remote/index') {
		$response = new HTTP::Response (200 => 'OK', [], 'something');
	} elsif ($request->uri eq '/remote/fortisslvpn') {
		$response = new HTTP::Response (200 => 'OK', [], "\x00\x06\x50\x50\x00\x00");
	} elsif ($request->uri eq '/remote/sslvpn-tunnel') {
		do_ppp ($client);
		$response = new HTTP::Response (200 => 'OK', 'something');
	} elsif ($request->uri eq '/remote/logout') {
		$response = new HTTP::Response (200 => 'OK', 'something');
	} else {
		$response = new HTTP::Response (404 => 'Not funny', [Connection => 'close']);
	}

	$client->send_response ($response) if $response;
	#$client->close;
}

# Handle a HTTP keep-alive connection
sub serve_client
{
	my $client = shift;

	while (my $request = $client->get_request) {
		serve_request ($client, $request);
	}

	$client->close;
	exit;
}

=head1 OPTIONS

=over 4

=item B<-h>, B<--help>

Print a brief help message and exits.

=item B<-H>, B<--man>

Prints the manual page and exits.

=item B<--listen> B<< <address>:<port> >>

Listen for connections on then specified address.

Defaults to C<0.0.0.0:10443>.

=item B<--cert> B<< <file> >>

Use the specified server certificate for incoming connections.

Defaults to F<server.crt>.

=item B<--key> B<< <file> >>

Use the specified key to decrypt the server certificate.

Defaults to F<server.key>.

=back

=cut

my $local = '0.0.0.0:10443';
my $cert = 'server.crt';
my $key = 'server.key';

new Getopt::Long::Parser (config => ['no_ignore_case'])->getoptions (
	'local=s' => \$local,
	'cert=s' => \$cert,
	'key=s' => \$key,
	'h|help' => sub { pod2usage (-exitval => 0, -verbose => 1) },
	'H|man' => sub { pod2usage (-exitval => 0, -verbose => 2) },
) or pod2usage (2);

my $server = new HTTP::Daemon::SSL (
	LocalAddr => $local,
	SSL_cert_file => $cert,
	SSL_key_file => $key,
	ReuseAddr => 1,
	ReusePort => 1,
) or die;

while (1) {
	my $client = $server->accept or warn $!;
	next unless $client;
	my $pid = fork;
	die $! unless defined $pid;
	serve_client ($client) if not $pid;
}

=head1 EXAMPLES

=over

=item B<openssl req -out server.crt -newkey rsa:1024 -batch -nodes -x509 -keyout server.key>

Generate a certificate for use with B<fortiserve.pl>.

=item B<fortiserve.pl --cert server.crt --key server.key>

Listen on the default C<localhost:10443> address.

=item B<openfortivpn -u user -p passwd localhost:10443>

Open a connection using the L<openfortivpn(1)> client.

=back

=head1 BUGS

The protocol is not documented.

The server is not suitable for production use and is mostly intended for
interoperability testing.

The pppd settings such as the addresses or DNS are hardcoded.

Certain resources such as FortiOS 5 XML network settings are not implemented.

Does not work with the official client.

Implements no security and authentication.

Sends bogus response bodies just so that L<HTTP::Daemon> has some
C<Content-Size> to use and doesn't terminate HTTP/1.1 Keep-Alive.

=head1 SEE ALSO

L<openfortivpn(1)>

=head1 COPYRIGHT

Copyright 2015 Lubomir Rintel

This program is free software; you can redistribute it and/or modify it
under the same terms as NetworkManager-fortisslvpn itself.

=head1 AUTHOR

Lubomir Rintel C<lkundrak@v3.sk>

=cut

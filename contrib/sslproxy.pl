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

use IO::Socket::SSL;
use IO::Poll;
use Getopt::Long;
use Pod::Usage;

use strict;
use warnings;

=head1 NAME

sslproxy.pl - SSL traffic logging proxy for protocol analysis

=head1 SYNOPSIS

sslproxy.pl
[-h|--help|-H|--man] |
--cert <file>
--key <file>
--listen <address>:<port>
--backend <address>:<port>

=head1 DESCRIPTION

B<sslproxy.pl> connects to the backend and listens on connections,
forwarding the traffic back and forth to the backend while intercepting
the SSL encryption. It logs the unencrypted traffic on the standard output.

You need to specify a certificate/key pair for the client-facing
connections used instead of the pair used by the backend so that the proxy
can decrypt it.

=cut

sub dump_chunk
{
	print join ' ', shift."[$$]:",
		map { sprintf '%02x', ord ($_) }
		split '', shift;
	print "\n";
}

sub serve_client
{
	my $client = shift;

	my $backend = new IO::Socket::SSL (
		SSL_verify_mode => SSL_VERIFY_NONE,
		SSL_cipher_list => 'ALL',
		PeerAddr => shift,
	) or die $!;

	my $poll = new IO::Poll;
	$poll->mask ($_ => IO::Poll::POLLIN | IO::Poll::POLLERR)
		foreach ($client, $backend);

	print "connected: $$\n";
	do {
		die $! if $poll->poll == -1;

		if ($poll->events ($client) == IO::Poll::POLLIN) {
			my $buf;
			$client->sysread ($buf, 4096);
			dump_chunk ('client', $buf);
			exit unless length $buf;
			print $backend $buf;
		}
		if ($poll->events ($backend) == IO::Poll::POLLIN) {
			my $buf;
			$backend->sysread ($buf, 4096);
			dump_chunk ('backend', $buf);
			exit unless length $buf;
			print $client $buf;
		}
	} until ($poll->handles (IO::Poll::POLLERR));

	exit;
}

=head1 OPTIONS

=over 4

=item B<-h>, B<--help>

Print a brief help message and exits.

=item B<-H>, B<--man>

Prints the manual page and exits.

=item B<--local> B<< <address>:<port> >>

Listen for connections on then specified address.

Defaults to C<0.0.0.0:1443>.

=item B<--backend> B<< <address>:<port> >>

Connect to the specified address.

Defaults to C<localhost:10443>.

=item B<--cert> B<< <file> >>

Use the specified server certificate for incoming connections.

Defaults to F<server.crt>.

=item B<--key> B<< <file> >>

Use the specified key to decrypt the server certificate.

Defaults to F<server.key>.

=back

=cut

my $local = '0.0.0.0:1443';
my $backend = 'localhost:10443';
my $cert = 'server.crt';
my $key = 'server.key';

new Getopt::Long::Parser (config => ['no_ignore_case'])->getoptions (
	'local=s' => \$local,
	'backend=s' => \$backend,
	'cert=s' => \$cert,
	'key=s' => \$key,
	'h|help' => sub { pod2usage (-exitval => 0, -verbose => 1) },
	'H|man' => sub { pod2usage (-exitval => 0, -verbose => 2) },
) or pod2usage (2);

my $server = new IO::Socket::SSL (
	Listen => 10,
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
	serve_client ($client, $backend) if not $pid;
}

=head1 EXAMPLES

=over

=item B<openssl req -out server.crt -newkey rsa:1024 -batch -nodes -x509 -keyout server.key>

Generate a certificate for use with B<sslproxy.pl>.

=item B<sslproxy.pl --cert server.crt --key server.key --backend google.com:443>

Listen on the default C<localhost:1443> address, forwarding requests to C<google.com:443>.

=item B<curl -k https://localhost:1443/>

Issue a request against the logging backend with L<curl(1)>.

=back

=head1 BUGS

The certificate of the backend server is not verified.

=head1 SEE ALSO

L<req(1)>, L<s_server(1)>, L<s_client(1)>

=head1 COPYRIGHT

Copyright 2015 Lubomir Rintel

This program is free software; you can redistribute it and/or modify it
under the same terms as NetworkManager-fortisslvpn itself.

=head1 AUTHOR

Lubomir Rintel C<lkundrak@v3.sk>

=cut

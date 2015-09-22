#!/usr/bin/env perl


# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# (C) 2015 Lubomir Rintel

=head1 NAME

antipppd.pl - mockup PPP server

=head1 SYNOPSIS

antipppd.pl
[-h|--help]
[-H|--man]
[<tty>] ...

=head1 DESCRIPTION

B<antipppd.pl> creates a mockup PPP server. It's intended for L<openfortivpn(1)>
testing, does not implement full PPP protocol, only replays one particular session.

It's smart enough to recognize and replace the random cookies.

=cut

use Getopt::Long;
use Pod::Usage;

use strict;
use warnings;

# Captured traffic from the working version
my $log_ofic = <<'EOF';
client[7548]: 00 16 50 50 00 10 c0 21 01 01 00 0e 01 04 05 4a 05 06 f1 81 bf 52
backend[7548]: 00 12 50 50 00 0c c0 21 01 01 00 0a 05 06 f0 0f a0 33
client[7548]: 00 12 50 50 00 0c c0 21 02 01 00 0a 05 06 f0 0f a0 33
backend[7548]: 00 16 50 50 00 10 c0 21 02 01 00 0e 01 04 05 4a 05 06 f1 81 bf 52
client[7548]: 00 17 50 50 00 11 80 fd 01 01 00 0f 1a 04 78 00 18 04 78 00 15 03 2f
client[7548]: 00 24 50 50 00 1e 80 21 01 01 00 1c 02 06 00 2d 0f 01 03 06 00 00 00 00 81 06 00 00 00 00 83 06 00 00 00 00
backend[7548]: 00 12 50 50 00 0c 80 21 01 01 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 01 00 0a 03 06 01 01 01 01
backend[7548]: 00 1f 50 50 00 19 c0 21 08 02 00 17 80 fd 01 01 00 0f 1a 04 78 00 18 04 78 00 15 03 2f 00 00
backend[7548]: 00 1e 50 50 00 18 80 21 04 01 00 16 02 06 00 2d 0f 01 81 06 00 00 00 00 83 06 00 00 00 00
backend[7548]: 00 12 50 50 00 0c 80 21 01 02 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 01 02 00 0a 03 06 00 00 00 00
client[7548]: 00 12 50 50 00 0c 80 21 03 02 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 03 02 00 0a 03 06 c0 a8 01 06
client[7548]: 00 12 50 50 00 0c 80 21 01 03 00 0a 03 06 c0 a8 01 06
backend[7548]: 00 12 50 50 00 0c 80 21 01 03 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 03 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 02 03 00 0a 03 06 c0 a8 01 06
backend[7548]: 00 12 50 50 00 0c 80 21 01 04 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 04 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 05 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 05 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 06 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 06 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 07 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 07 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 08 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 08 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 09 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 09 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 0a 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 0a 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 0b 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 0b 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 0c 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 0c 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 0d 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 0d 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 0e 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 0e 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 0f 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 0f 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 10 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 10 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 11 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 11 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 12 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 12 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 13 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 13 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 14 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 14 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 15 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 15 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 16 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 16 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 17 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 17 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 18 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 18 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 19 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 19 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 1a 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 1a 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 1b 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 1b 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 1c 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 1c 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 1d 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 1d 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 1e 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 1e 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 1f 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 1f 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 20 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 20 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 21 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 21 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 22 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 22 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 23 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 23 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 24 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 24 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 25 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 25 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 26 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 26 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 27 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 27 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 28 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 28 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 29 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 29 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 2a 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 2a 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 2b 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 2b 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 2c 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 2c 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 2d 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 2d 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 2e 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 2e 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 2f 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 2f 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 30 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 30 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 31 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 31 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 32 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 32 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 33 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 33 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 34 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 34 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 35 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 35 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 36 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 36 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 37 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 37 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 38 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 38 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 39 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 39 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 3a 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 3a 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 3b 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 3b 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 3c 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 3c 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 3d 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 3d 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 3e 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 3e 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 3f 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 3f 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 40 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 40 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 41 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 41 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 42 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 42 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 43 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 43 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 44 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 44 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 45 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 45 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 46 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 46 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 47 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 47 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 48 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 48 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 49 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 49 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 4a 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 4a 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 4b 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 4b 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 4c 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 4c 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 4d 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 4d 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 4e 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 4e 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 4f 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 4f 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 50 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 50 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 51 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 51 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 52 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 52 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 53 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 53 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 54 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 54 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 55 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 55 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 56 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 56 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 57 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 57 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 58 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 58 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 59 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 59 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 5a 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 5a 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 5b 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 5b 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 5c 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 5c 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 5d 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 5d 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 5e 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 5e 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 5f 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 5f 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 60 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 60 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 61 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 61 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 62 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 62 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 63 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 63 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 64 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 03 64 00 0a 03 06 01 01 01 01
backend[7548]: 00 12 50 50 00 0c 80 21 01 65 00 0a 03 06 b9 67 92 8a
client[7548]: 00 12 50 50 00 0c 80 21 04 65 00 0a 03 06 b9 67 92 8a
backend[7548]: 00 16 50 50 00 10 80 21 01 66 00 0e 01 0a b9 67 92 8a c0 a8 01 06
client[7548]: 00 16 50 50 00 10 80 21 04 66 00 0e 01 0a b9 67 92 8a c0 a8 01 06
backend[7548]: 00 0c 50 50 00 06 80 21 01 67 00 04
client[7548]: 00 0c 50 50 00 06 80 21 02 67 00 04
EOF

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

my $log = $log_ofic;
my @log = map { [/^([^\[]+)\[\d+\]: \S\S \S\S 50 50 \S\S \S\S (.*)/] } split "\n", $log;
my %xlat;
my $us = 'backend';
my $them = 'client';

sub feed
{
	my $msg = shift;

	unless (@log) {
		warn "EMPTY FEED";
		return undef;
	}


	my ($dir, $string) = @{$log[0]};
	die if $dir ne $them;

	shift @log;
	my ($l1, $t1) = $string =~ /(.*) (\S\S \S\S \S\S \S\S)$/;
	my ($l2, $t2) = $msg =~ /(.*) (\S\S \S\S \S\S \S\S)$/;
	if ($l1 eq $l2) {
		$xlat{$t1} = $t2 if $t1 ne $t2;
	} else {
		warn "MISMATCH: got '$l2', expected '$l1'";
	}
}

sub get
{
	unless (@log) {
		warn "EMPTY GET";
		return undef;
	}

	my ($dir, $string) = @{$log[0]};
	return undef if $dir ne $us;
	shift @log;

	my ($l, $t) = $string =~ /(.*) (\S\S \S\S \S\S \S\S)$/;
	$string =~ s/\S\S \S\S \S\S \S\S$/$xlat{$t}/ if $xlat{$t};

	return $string;
}

sub str { join ' ', map { sprintf '%02x', ord ($_) } split '', shift; } 
sub unstr { join '', map { chr (hex ($_)) } split ' ', shift; }


=head1 OPTIONS

=over 4

=item B<-h>, B<--help>

Print a brief help message and exits.

=item B<-H>, B<--man>

Prints the manual page and exits.

=item B<< <tty> >>

Use this particular tty. Must be the first arguments.

Defaults to standard input/output.

=back

Other arguments are ignored for compatibility with L<pppd(8)>.

=cut

new Getopt::Long::Parser (config => ['no_ignore_case'])->getoptions (
        'h|help' => sub { pod2usage (-exitval => 0, -verbose => 1) },
        'H|man' => sub { pod2usage (-exitval => 0, -verbose => 2) },
) or pod2usage (2);

my $tty = shift @ARGV;
if ($tty) {
	open (OUT, '>', $tty);
	open (IN, '<', $tty);
} else {
	open (OUT, '>&STDOUT');
	open (IN, '<&STDIN');
}

print OUT "\x7e";
do {
	my $get = get ();
	if ($get) {
		print OUT encode (unstr ($get));
		flush OUT;
	} else {
		my $buf = '';
		while (sysread (IN, $_, 1)) {
			if ($_ eq "\x7e") {
				next if not length $buf;
				last;
			}
			$buf .= $_;
		}
		exit unless length $buf;
		feed (str (decode ($buf)));
	}
} while (1);

=head1 EXAMPLES

=over

=item B<fortiserve.pl --pppd ./antipppd.pl>

Run with the Fortigate mockup with B<antipppd.pl>.

=item B</usr/sbin/pppd 38400 pty ./antipppd.pl nodetach debug logfd 2
noipdefault noaccomp noauth default-asyncmap nopcomp nodefaultroute
:1.1.1.1 lcp-max-configure 40 usepeerdns receive-all mru 1354>

Run the actual L<pppd(8)> with the mocked-up session.

=back

=head1 BUGS

It exists.

=head1 SEE ALSO

L<openfortivpn(1)>, L<pppd(8)>

=head1 COPYRIGHT

Copyright 2015 Lubomir Rintel

This program is free software; you can redistribute it and/or modify it
under the same terms as NetworkManager-fortisslvpn itself.

=head1 AUTHOR

Lubomir Rintel C<lkundrak@v3.sk>

=cut

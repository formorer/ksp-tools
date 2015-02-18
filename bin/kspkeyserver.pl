#!/usr/bin/perl
# Copyright (C) 2007 Alexander Wirt <formorer@formorer.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
#

use HTTP::Daemon;
use strict;
use CGI::Util qw/ unescape /;    #needed to escape the HTML stuff
use File::Temp qw/ tempfile /;
use Log::LogLite;
use Net::hostent;
use Getopt::Long;
use Proc::Reliable;

my $config;

$config->{homedir} = defined $ENV{'KSP_HOMEDIR'} ? $ENV{'KSP_HOMEDIR'} : '/home/ksp';
$config->{port} = 11371
    ; # this is used by the hkp protocol, for some weird reason its listed with tcp/udp but thats stupid
$config->{basedir}   = $config->{homedir} . "/keys";
$config->{gpg}       = '/usr/bin/gpg';
$config->{vhostmode} = 1;
$config->{bind}      = '0.0.0.0';
$config->{daemonize} = 1;
$config->{LOG_FILE}  = $config->{homedir} . "/kspkeyserver.log";
$config->{LOG_LEVEL} = 7;
$config->{configfile} = 'keyserver.conf';

GetOptions ( 
    "configfile=s" => \$config->{configfile},
    "daemonize!" => \$config->{daemonize}
);

# parse a simple configuration format
if (-e $config->{configfile}) {
    open (my $cfg, '<', $config->{configfile})
        or die "Could not open configuration file " . $config->{configfile} . ": $!";
    while (<$cfg>) {
        chomp;                  # no newline
        s/#.*//;                # no comments
        s/^\s+//;               # no leading white
        s/\s+$//;               # no trailing white
        next unless length;     # anything left?
        my ($var, $value) = split(/\s*=\s*/, $_, 2);
        $config->{$var} = $value;
    }
}

die "Basedir " . $config->{basedir} . "does not exist" unless -d $config->{basedir};
if ( !-d $config->{basedir} . "/gpg" ) {
    mkdir $config->{basedir} . "/gpg", 0700 or die "Could not create gpg home: $!";
}

my $log = new Log::LogLite( $config->{LOG_FILE}, $config->{LOG_LEVEL} );

my $d = HTTP::Daemon->new(
    LocalAddr => $config->{bind},
    LocalPort => $config->{port},
    Reuse     => 1,
) or die "Could not create HTTP::Daemon: $!";

$log->write( "Now listening on " . $d->url, 5 );

if ($config->{daemonize}) {
    open STDIN,  '/dev/null'  or die "Can't read /dev/null: $!";
    open STDERR, '>/dev/null' or die "Can't write to /dev/null: $!";
    open STDOUT, '>/dev/null' or die "Can't write to /dev/null: $!";
    defined( my $pid = fork ) or die "Can't fork: $!";
    if ($pid) {
        $log->write( "Forked into background ($pid)", 5 );
        exit if $pid;
    }

}

while ( my $c = $d->accept ) {
    $log->write( "New connection from " . $c->peerhost(), 7 );
    while ( my $r = $c->get_request ) {
        if ( $r->method eq 'POST' and $r->url->path eq "/pks/add" ) {
            my $tmphost = $r->header('Host');
            my ( $targethost, $port ) = split( /:/, $tmphost );

            #sanitize the hostname
            $targethost =~ s/[^a-z0-9-]/_/ig;
            $targethost = lc($targethost);

            $log->write(
                $c->peerhost() . " wants to submit a key to ksp $targethost",
                7
            );
            my $content = $r->decoded_content;
            if ( $content =~ m/keytext=(.*)$/ ) {
                my $key = unescape("$1");
                my ( $fh, $filename ) = tempfile();
                print $fh "$key";
                open( GPG, '-|',
                    $config->{gpg} . " -q --no-options --homedir=" . $config->{basedir} . "/gpg --with-colons $filename "
                ) or print "Could not open gpg: $!\n";
                while (<GPG>) {
                    if (/^pub:/) {
                        my ($type,           $trust,  $keylength,
                            $algorithm,      $keyid,  $creationdate,
                            $expirationdate, $serial, $ownertrust,
                            $uid,            $rest
                        ) = split( /:/, $_ );
                        if ( $keyid ne "" && $uid ne "" ) {
                            my $new_key;
                            if ($config->{vhostmode}) {
                                $new_key = $config->{basedir} . "/$targethost/keys/$keyid";
                            } else {
                                $new_key = $config->{basedir} . "/$keyid";
                            }
                            if ( !-f $config->{basedir} . "/$targethost/locked" ) {
                                if ( open( OUTKEY, ">", "$new_key" ) ) {
                                    print OUTKEY "$key";
                                    close(OUTKEY);
                                    $log->write(
                                        "$uid (Keyid: $keyid) successfully submitted to $targethost by "
                                            . $c->peerhost(),
                                        5
                                    );

                                    my $response = HTTP::Response->new(200)
                                        ;    # Put together a response
                                    $response->content(
                                        "<html><body>Key added!</body></html>"
                                    );

                   #				$response->content("document.write('OK $i<br \/>');");
                                    $response->header(
                                        "Content-Type" => "text/html" );
                                    $c->send_response($response);
                                    if ($config->{updatehook}) {
                                        $log->write("Run updatehook for new key");
                                        my $cmd = $config->{updatehook};
                                        # replace %f in the command with the
                                        # filename of the key
                                        $cmd =~ s/%f/$new_key/g;
                                        $cmd =~ s/%v/$targethost/g;
                                        my $proc = Proc::Reliable->new();
                                        $proc->want_single_list(0);
                                        my ($stdout, $stderr, $status, $msg) = $proc->run($cmd);
                                        if ($status) {
                                            $log->write("There was a problem in running the updatehook:\nStdout: $stdout\nStderr: $stderr");
                                        }
                                    }
                                } else {
                                    $log->write(
                                        "Could not write $keyid to $new_key: $!",
                                        2
                                    );
                                    $c->send_error(500);
                                }
                            } else {
                                $log->write("KSP $targethost locked");
                                $c->send_error(500);
                            }
                        } else {

                            # key not valid
                            $log->write(
                                "Invalid submission by " . $c->peerhost(),
                                4 );
                            $c->send_error(400);
                        }
                    }
                }
                close(GPG);
            }
        } else {
            $log->write( "Illegal request by " . $c->peerhost(), 4 );
            $c->send_error(400);
        }
    }
    $c->close;
    undef($c);
}


# vim: syntax=perl sw=4 ts=4 et shiftround

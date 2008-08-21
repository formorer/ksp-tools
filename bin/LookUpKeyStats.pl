#!/usr/bin/perl -w

################################################################################
# This script is meant to add some useful statistical data like
#  o number of cross-signatures
#  o number of already signed keys
#  o Mean-Shortest-Distance (MSD)
#  o rank
# to the so called "List of participants" which people receive prior
# to Keysigning-Parties.
# 
# 
# Usage: LookUpKeyStats.pl ksp-xxx.txt > ksp-xxx_final.txt
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#                               -- Karlheinz Geyer "streng" <streng@ftbfs.de>
#
################################################################################
use URI::Escape;
use LWP::UserAgent;

$ua = LWP::UserAgent->new();

$urlBase = "http://pgp.cs.uu.nl/stats/[:KEY:].html";

$state = 0;

resetValues();

while (<>) {
  chomp;
  SWITCH: {
    $state == 0 && do {
      /^pub / && do {
        $state=1;
        $thekey=$_;
        $thekey =~ s/^[^\/]*\/(........).*/$1/gi;
        lookupStats($thekey);
      };
      print "$_\n"; last SWITCH; };
    $state == 1 && do {
        /^--* */ && do {
        $state=0;
        printf("Signatures:[%05d]   Keys signed:[%06d]   MSD:[%1.4f]   Rank:[%06d]\n", $signatures, $keyssigned, $msd, $rank);
        resetValues();
      };
      print "$_\n"; last SWITCH; };
  }

  
}


sub lookupStats {
  my $fk = shift;
  my $url = $urlBase;
  $url =~ s/\[:KEY:\]/$fk/g;
        
  my $request = HTTP::Request->new('GET', $url);
    
  my $response = $ua->request($request);
    
  if ( $response->is_error() ) {
    print STDERR "Could not load statistics for key $fk:\n";
    print STDERR "Error received when loading: $url\n";
    print STDERR "Error-Code    : ", $response->code() ,    "\n";
    print STDERR "Error-Message : ", $response->message() , "\n";
  }
  else {
    for (split("\n",$response->content())){
      /^\<TR\>\<TD *\>signatures/ && do {
        chomp;
        s/\<[^\>]*\>//gi;
        s/[a-z\(\)\<\> \t]//gi;
        $signatures=$_;};
      /^\<TR\>\<TD \>keys signed/ && do {
        chomp;
        s/\<[^\>]*\>//gi;
        s/[a-z\(\)\<\> \t]//gi;
        $keyssigned=$_;};
      /^\<TR\>\<TD \>mean shortest distance/ && do {
        chomp;
        s/\<[^\>]*\>//gi;
        s/[a-z\(\)\<\> \t]//gi;
        $msd=$_;};
      /^\<TR\>\<TD \>msd ranking/ && do {
        chomp;
        s/\<[^\>]*\>//gi;
        s/[a-z\(\)\<\> \t]//gi;
        $rank=$_;};
    }
    
  }

}

sub resetValues {
  $thekey="";
  $signatures=0;
  $keyssigned=0;
  $msd=0.0;
  $rank=0;
}


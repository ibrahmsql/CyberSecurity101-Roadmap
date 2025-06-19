#!/usr/bin/env perl
# dir_enum.pl – Simple directory brute-forcer demo
# Usage: perl dir_enum.pl https://target.com wordlist.txt
use strict; use warnings;
use LWP::UserAgent;

my ($base, $wordlist) = @ARGV;
if (not $base or not $wordlist) {
    die "Usage: $0 <base_url> <wordlist>\n";
}

my $ua = LWP::UserAgent->new(timeout => 5);
open my $fh, '<', $wordlist or die "Cannot open $wordlist: $!\n";

while (<$fh>) {
    chomp;
    my $url = "$base/$_";
    my $res = $ua->get($url);
    print "[+] $url\n" if $res->is_success;
}
close $fh;

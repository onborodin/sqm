#!/usr/bin/env perl

use strict;
use warnings;
use Mojo::Util qw(dumper);
use Time::Local;

my %user;
my %host;

my $tmpl = '^access.log';
my $dir = '/var/log/squid';

my $time = time;
my ($sec, $min, $hour, $day, $month, $year) = (localtime($time))[0,1,2,3,4,5];
$year += 1900;
my $begin = timelocal(0, 0, 0, 1, $month, $year);

opendir(my $dh, $dir);

while (my $file = readdir $dh) {
    next if $file eq '.';
    next if $file eq '..';

    next unless $file =~ /$tmpl/;

    open my $fh, '<', "$dir/$file" or next;

    while (my $line = readline $fh) {
        my ($time, $code, $source, $mode, $size, $req, $url, $user) = split(/\s+/, $line);
        next if $user eq '-';
        next unless $user;

        $time = int($time);
        next if $time < $begin;

        my $str = localtime(int($time));

        $user{$user}{size} += $size;
        $user{$user}{source}{$source} = 1;
        my $host = $url;
        $host =~ s,^http://,,;
        $host =~ s,^https://,,;
        $host =~ s,^ftp://,,;
        ($host) = split /\//, $host;
        ($host) = split /:/, $host;

        $user{$user}{host}{$host} += $size;
        $host{$host}{host} += $size;
    }
    close $fh;
}

#print dumper \%user;



#foreach my $name (sort keys %user) {
#    my $total_size = int($user{$name}{size}/(1024*1024)+0.5);
#    foreach my $host (keys %{$user{$name}{host}}) {
#        my $size = $user{$name}{host}{$host};
#        print "$name $host $size\n";
#    }

#    print "$name $size\n";
#    foreach my $host (keys %{$user{host}}) {
#        my $size = $user{$name}{host}{$host};
#        print "$name  $host   $size\n";
#    }

}

#EOF

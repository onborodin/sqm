#!/usr/bin/env perl

use strict;
use warnings;
use Mojo::Util qw(b64_decode dumper camelize);
use Digest::SHA qw(sha512_base64);


my %user;

open my $fh, '<', 'password' or exit 1;
while (my $line = readline $fh) {
    chomp $line;
    my ($login, $hash, $dummy) = split (/:/, $line);

    $user{$login}{hash} = $hash;
    $user{$login}{salt} = substr($hash, 0, 2) unless $hash =~ /\$/;

}
close $fh;

open $fh, '<', 'password.plain' or exit 1;
while (my $line = readline $fh) {
    chomp $line;
    my ($login, $password, $dummy) = split (/:/, $line);

    $user{$login}{password} = $password;
    my $salt = $user{$login}{salt};
    next unless $salt;
    $user{$login}{new} = crypt($password, $salt);
}
close $fh;

#print dumper \%user;

my $num = 10;
foreach my $login (keys %user) {
    my $password = $user{$login}{password} || '';
    my $hash = $user{$login}{hash} || '';
    my $new = $user{$login}{new} || 'xxx';

    my $new_salt = substr(sha512_base64(sprintf("%X", rand(2**31-1))), 4, 16);
    my $new_hash = crypt($password,'$6$'.$new_salt.'$');

    
    my $gecos = $login;
    $gecos =~ s/_/__/g;
    $gecos = camelize $gecos;

    $password = 'xxxxxxx' if $hash ne $new;
    $new_hash = $hash if $hash ne $new;

    print "insert into users (id, name, password, gecos, hash, quota) values ($num, '$login', '$password', '$gecos', '$new_hash', 10240);\n";
#    print "login=$login \t password=$password \t hash=$new_hash\n" if $hash eq $new;
#    print "login=$login \t password='xxxxxx' \t hash=$hash\n" if $hash ne $new;
    $num += 1;
}

#EOF

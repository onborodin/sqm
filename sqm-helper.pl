#!@perl@

#
# $Id$
#

package aConfig;

use strict;
use warnings;

sub new {
    my ($class, $file) = @_;
    my $self = {
        file => $file
    };
    bless $self, $class;
    $self;
}

sub file {
    my ($self, $name) = @_;
    return $self->{'file'} unless $name;
    $self->{'file'} = $name;
    $self;
}

sub read {
    my $self = shift;
    return undef unless -r $self->file;
    open my $fh, '<', $self->file;
    my %res;
    while (my $line = readline $fh) {
        chomp $line;
        $line =~ s/^\s+//g;

        next if $line =~ /^#/;
        next if $line =~ /^;/;
        next unless $line =~ /[=:]/;

        $line =~ s/[\"\']//g;
        my ($key, $rawvalue) = split(/==|=>|[=:]/, $line);
        next unless $rawvalue and $key;

        my ($value, $comment) = split(/[#;,]/, $rawvalue);

        $key =~ s/^\s+|\s+$//g;
        $value =~ s/^\s+|\s+$//g;

        $res{$key} = $value;
    }
    close $fh;
    \%res;
}

1;

#----------
#--- DB ---
#----------

package aDBI;

use strict;
use warnings;
use DBI;
use DBD::Pg;

sub new {
    my ($class, %args) = @_;
    my $self = {
        host => $args{host} || '',
        login => $args{login} || '',
        password => $args{password} || '',
        database => $args{database} || '',
        engine => $args{engine} || 'SQLite',
        error => ''
    };
    bless $self, $class;
    return $self;
}

sub login {
    my ($self, $login) = @_;
    return $self->{login} unless $login;
    $self->{login} = $login;
    $self;
}

sub password {
    my ($self, $password) = @_;
    return $self->{password} unless $password;
    $self->{password} = $password;
    $self;
}

sub host {
    my ($self, $host) = @_;
    return $self->{host} unless $host;
    $self->{host} = $host;
    $self;
}

sub database {
    my ($self, $database) = @_;
    return $self->{database} unless $database;
    $self->{database} = $database;
    $self;
}

sub error {
    my ($self, $error) = @_;
    return $self->{error} unless $error;
    $self->{error} = $error;
    $self;
}

sub engine {
    my ($self, $engine) = @_;
    return $self->{engine} unless $engine;
    $self->{engine} = $engine;
    $self;
}

sub exec {
    my ($self, $query) = @_;
    return undef unless $query;

    my $dsn = 'dbi:'.$self->engine.
                ':dbname='.$self->database.
                ';host='.$self->host;
    my $dbi;
    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
    };
    $self->error($@);
    return undef if $@;

    my $sth;
    eval {
        $sth = $dbi->prepare($query);
    };
    $self->error($@);
    return undef if $@;

    my $rows = $sth->execute;
    my @list;

    while (my $row = $sth->fetchrow_hashref) {
        push @list, $row;
    }
    $sth->finish;
    $dbi->disconnect;
    \@list;
}

sub exec1 {
    my ($self, $query) = @_;
    return undef unless $query;

    my $dsn = 'dbi:'.$self->engine.
                ':dbname='.$self->database.
                ';host='.$self->host;
    my $dbi;
    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
    };
    $self->error($@);
    return undef if $@;

    my $sth;
    eval {
        $sth = $dbi->prepare($query);
    };
    $self->error($@);
    return undef if $@;

    my $rows = $sth->execute;
    my $row = $sth->fetchrow_hashref;

    $sth->finish;
    $dbi->disconnect;
    $row;
}

sub do {
    my ($self, $query) = @_;
    return undef unless $query;
    my $dsn = 'dbi:'.$self->engine.
                ':dbname='.$self->database.
                ';host='.$self->host;
    my $dbi;
    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
    };
    $self->error($@);
    return undef if $@;
    my $rows;
    eval {
        $rows = $dbi->do($query);
    };
    $self->error($@);
    return undef if $@;

    $dbi->disconnect;
    $rows*1;
}

1;

#------------
#--- USER ---
#------------

package aUser;

use strict;
use warnings;

sub new {
    my ($class, $db) = @_;
    my $self = { 
        db => $db
    };
    bless $self, $class;
    return $self;
}

sub db {
    my ($self, $db) = @_;
    return $self->{db} unless $db;
    $self->{db} = $db;
    $self;
}

sub to64 {
    my $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    my ($v, $n) = @_;
    my ($ret)  = '';
    while (--$n >= 0) {
        $ret .= substr($itoa64, $v & 0x3f, 1);
        $v >>= 6;
    }
    $ret;
}

sub apr1 {
    my($self, $pw, $salt) = @_;
    return undef unless $pw;
    return undef unless $salt;

    my $passwd;
    my $magic = '$apr1$';

    $salt =~ s/^\Q$magic//;        # Take care of the magic string if present.
    $salt =~ s/^(.*)\$.*$/$1/;        # Salt can have up to 8 chars...
    $salt = substr($salt, 0, 8);

    my $ctx = Digest::MD5->new;        # Here we start the calculation.
    $ctx->add($pw);                        # Original password...
    $ctx->add($magic);                # ...our magic string...
    $ctx->add($salt);                        # ...the salt...

    my $final = Digest::MD5->new;
    $final->add($pw);
    $final->add($salt);
    $final->add($pw);

    $final = $final->digest;
    for (my $pl = length($pw); $pl > 0; $pl -= 16) {
                $ctx->add(substr($final, 0, $pl > 16 ? 16 : $pl) );
    }
    # Now the 'weird' xform.
    for (my $i = length($pw); $i; $i >>= 1) {
        if ($i & 1) {
            $ctx->add(pack('C', 0) );
        } else {
        # This comes from the original version, where a
        # memset() is done to $final before this loop.
                        $ctx->add(substr($pw, 0, 1) );
        }
    }

    $final = $ctx->digest;
    # The following is supposed to make things run slower.
    # In perl, perhaps it'll be *really* slow!
    for (my $i = 0; $i < 1000; $i++) {

        my ($ctx1) = Digest::MD5->new;
        if ($i & 1) {
            $ctx1->add($pw);
        } else {
            $ctx1->add(substr($final, 0, 16) );
        }

        if ($i % 3) { $ctx1->add($salt); }
        if ($i % 7) { $ctx1->add($pw); }
        if ($i & 1) { 
            $ctx1->add(substr($final, 0, 16) ); 
        } else {
            $ctx1->add($pw);
        }

        $final = $ctx1->digest;
    }

    $passwd = '';
    $passwd .= to64(int(unpack('C', (substr($final, 0, 1))) << 16)
        | int(unpack('C', (substr($final, 6, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 12, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', (substr($final, 1, 1))) << 16)
        | int(unpack('C', (substr($final, 7, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 13, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', (substr($final, 2, 1))) << 16)
        | int(unpack('C', (substr($final, 8, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 14, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', (substr($final, 3, 1))) << 16)
        | int(unpack('C', (substr($final, 9, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 15, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', (substr($final, 4, 1))) << 16)
        | int(unpack('C', (substr($final, 10, 1) ) ) << 8)
        | int(unpack('C', (substr($final, 5, 1) ) ) ), 4);
    $passwd .= to64(int(unpack('C', substr($final, 11, 1))), 2);

    $magic . $salt . '$' . $passwd;
}




# --- USER ---

sub user_exist {
    my ($self, $name) = @_;
    return undef unless $name;
    my $res = $self->db->exec1("select * from users where users.name = '$name' limit 1");
    $res->{id};
}

sub user_profile {
    my ($self, $id) = @_;
    return undef unless $id;
    $self->db->exec1("select * from users where id = $id limit 1");
}

sub user_list {
    my ($self) = @_;
    $self->db->exec('select * from users order by name');
}

sub user_check {
    my ($self, $login, $password) = @_;
    return undef unless $login;
    return undef unless $password;

    return undef unless length $login;
    return undef unless length $password;

    my $user_id = $self->user_exist($login);
    return undef unless $user_id;

    my $profile = $self->user_profile($user_id);
    return undef unless $profile;

    my $pro_hash = $profile->{hash};
    my ($dummy, $type, $salt, $digest) = split (/\$/, $pro_hash);

    my $new_hash = '';
    if ($type =~ /^[1256]$/) {
        $new_hash = crypt($password,'$6$'.$salt.'$');
    }

    if ($type =~ /^apr1/) {
        $new_hash = $self->apr1($password, $salt);
    }

    return 1 if $pro_hash eq $new_hash;

    my $pro_password = $profile->{password};
    return 1 if $pro_password eq $password;

    return undef;
}


1;

#############
#--- MAIN ---
#############

use strict;
use warnings;
use IO::Handle;
use Mojo::Util qw(dumper getopt);

my $appname = 'sqm-helper';

STDOUT->autoflush(1);

my %config;
my $config = \%config;

$config->{conffile} = '@app_confdir@/sqm.conf';
$config->{dbname} =  '@app_datadir@/sqm.db';
$config->{dbhost} =  '';
$config->{dblogin} =  '';
$config->{dbpassword} =  '';
$config->{dbengine} =  'sqlite3';

if (-r $config->{conffile}) {
    my $c = aConfig->new($config->{conffile});
    my $hash = $c->read;
    foreach my $key (keys %$hash) {
        $config->{$key} = $hash->{$key};
    }
}

my $engine = 'SQLite' if $config->{dbengine} =~ /sqlite/i;
$engine = 'Pg' if $config->{dbengine} =~ /postgres/i;

my $dbi = aDBI->new(
            database => $config->{dbname},
            host => $config->{dbhost},
            login => $config->{dblogin},
            password => $config->{dbpassword},
            engine => $engine
);

my $u = aUser->new($dbi);

while (my $line = readline (STDIN)) {
    chomp $line;
    my ($user, $password) = split(/\s/, $line);

    unless ($user) { print "ERR\n"; next; };
    unless ($password) { print "ERR\n"; next; };

#    my $user_id = $u->user_exist($user);
#    unless ($user_id) { print "ERR\n"; next; };
#
#    my $profile = $u->user_profile($user_id);
#    unless ($profile) { print "ERR\n"; next; };

    if ($u->user_check($user, $password)) {
        print "OK\n";
    } else {
        print "ERR\n";
    }
}

#EOF

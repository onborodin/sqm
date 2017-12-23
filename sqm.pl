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
#--- aDBI ---
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
#    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
#    };
    $self->error($@);
    return undef if $@;

    my $sth;
#    eval {
        $sth = $dbi->prepare($query);
#    };
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
#    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
#    };
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
#    eval {
        $dbi = DBI->connect($dsn, $self->login, $self->password, {
            RaiseError => 1,
            PrintError => 0,
            AutoCommit => 1
        });
#    };
    $self->error($@);
    return undef if $@;
    my $rows;
#    eval {
        $rows = $dbi->do($query);
#    };
    $self->error($@);
    return undef if $@;

    $dbi->disconnect;
    $rows*1;
}

1;


#---------------
#--- COUNTER ---
#---------------

package aCounter;

use strict;
use warnings;
use Digest::SHA qw(sha512_base64);
use Mojo::Util qw(dumper);
use Time::Local;

sub new {
    my ($class, $db, $logdir, $logtmpl) = @_;
    my $self = {
        db => $db,
        logdir => $logdir,
        logtmpl => $logtmpl
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

sub logdir {
    my ($self, $logdir) = @_;
    return $self->{logdir} unless $logdir;
    $self->{logdir} = $logdir;
    $self;
}

sub logtmpl {
    my ($self, $logtmpl) = @_;
    return $self->{logtmpl} unless $logtmpl;
    $self->{logtmpl} = $logtmpl;
    $self;
}

sub count {
    my $self = shift;

    my %user;
    my %host;

    my $tmpl = '^access.log';
    my $dir = '/var/log/squid';

    my $time = time;
    my ($sec, $min, $hour, $day, $month, $year) = (localtime($time))[0,1,2,3,4,5];
    $year += 1900;

    # Start time is 1th day of month
    my $begin = timelocal(0, 0, 0, 1, $month, $year);

    opendir(my $dh, $dir);

    while (my $file = readdir $dh) {
        next if $file eq '.';
        next if $file eq '..';

        next unless $file =~ /$tmpl/;

        open my $fh, '<', "$dir/$file" or next;

        while (my $line = readline $fh) {
            my ($time, $code, $source, $mode, $size, $req, $url, $user) = split(/\s+/, $line);
            next unless $user;
            next if $user eq '-';

            $time = int($time);
            next if $time < $begin;

            my $str = localtime(int($time));

            $user{$user}{size} += int($size/(1024)+0.5);
            $user{$user}{source}{$source} = 1;
            my $host = $url;
            $host =~ s,^http://,,;
            $host =~ s,^https://,,;
            $host =~ s,^ftp://,,;
            ($host) = split /\//, $host;
            ($host) = split /:/, $host;

            $user{$user}{hosts}{$host}{size} += int($size/(1024)+0.5);
#            $host{$host}{size} += int($size/(1024)+0.5);
        }
        close $fh;
    }
    \%user;
}

1;


#------------
#--- USER ---
#------------

package aUser;

use strict;
use warnings;
use Digest::SHA qw(sha512_base64);

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

sub user_nextid {
    my $self = shift;
    my $res = $self->db->exec1('select id from users order by id desc limit 1');
    my $id = $res->{id} || 0;
    $id += 1;
}

sub user_add {
    my ($self, $name, $password, $gecos, $quota) = @_;
    return undef unless $name;
    return undef unless $password;
    return undef unless $gecos;
    $quota ||= 1024*100;

    return undef if $self->user_exist($name);

    my $next_id = $self->user_nextid;
    my $salt = substr(sha512_base64(sprintf("%X", rand(2**31-1))), 4, 16);
    my $hash = crypt($password,'$6$'.$salt.'$');

    $self->db->do("insert into users (id, name, password, gecos, hash, quota)
                    values ($next_id, '$name', '$password', '$gecos', '$hash', $quota)");
    $self->user_exist($name);
}

sub user_update {
    my ($self, $id, %args) = @_;
    my $prof = $self->user_profile($id);
    return undef unless $prof;

    my $name = $args{name} || $prof->{name};
    my $gecos = $args{gecos} || $prof->{gecos};
    my $password = $args{password} || $prof->{password};
    my $hash = $prof->{hash};

    if ($args{password}) {
        my $salt = substr(sha512_base64(sprintf("%X", rand(2**31-1))), 4, 16);
        $hash = crypt($password,'$6$'.$salt.'$');
    }

    my $quota = $args{quota} || $prof->{quota};

    $args{size} ||= -1;
    my $size = $prof->{size};
    $size = $args{size} if $args{size} >= 0;
    $size ||= 0;

    my $q = "update users set name = '$name',
                                password = '$password',
                                gecos = '$gecos',
                                size = $size,
                                quota = $quota,
                                hash = '$hash'
                            where id = $id";
    $self->db->do($q);
    my $res = $self->user_profile($id);
    return undef unless $res->{name} eq $name;
    return undef unless $res->{password} eq $password;
    $id ;
}

sub user_delete {
    my ($self, $id) = @_;
    return undef unless $id;
#    return $id unless $self->user_profile($id);
    $self->db->do("delete from users where id = $id");
    return undef if $self->user_profile($id);
    $id;
}

# --- HOSTS INFO ---

sub host_exist {
    my ($self, $host, $user_id) = @_;
    return undef unless $user_id;
    my $res = $self->db->exec1("select * from hosts where name = '$host' and user_id = $user_id limit 1");
    $res->{size};
}

sub host_clean {
    my ($self, $user_id) = @_;
    my $where = "where user_id = $user_id" if $user_id;
    $where ||= '';
    $self->db->do("delete from hosts $where");
}

sub host_update {
    my ($self, $host, $user_id, $size) = @_;
    return undef unless $host;
    return undef unless $user_id;
    $size ||= 0;
    $self->host_delete($host, $user_id);
    $self->db->do("insert into hosts (user_id, name, size)
                              values ($user_id, '$host', $size)");
}

sub host_delete {
    my ($self, $host, $user_id) = @_;
    return undef unless $host;
    return undef unless $user_id;
    $self->db->do("delete from hosts where user_id = $user_id and name = '$host'");
}

sub export_passwd {
    my ($self, $file) = @_;
    return undef unless $file;

    my $file_bak = "$file.bak";
    my $file_tmp = "$file.tmp";
    my $str;
    foreach my $rec (@{$self->user_list}) {
        $str .= $rec->{name}.":".$rec->{hash}."\n";
    }
    open(my $fh, '>', $file_tmp) or return undef;
    print $fh $str or return undef;
    close $fh;
    rename($file, $file_bak) if -f $file; # or return undef;
    link($file_tmp, $file) or return undef ;
    unlink $file_tmp;
    $file;
}

1;

#--------------
#--- DAEMON ---
#--------------

package Daemon;

use strict;
use warnings;
use POSIX qw(getpid setuid setgid geteuid getegid);
use Cwd qw(cwd getcwd chdir);
use Mojo::Util qw(dumper);

sub new {
    my ($class, $user, $group)  = @_;
    my $self = {
        user => $user,
        group => $group
    };
    bless $self, $class;
    return $self;
}

sub fork {
    my $self = shift;

    my $pid = fork;
    if ($pid > 0) {
        exit;
    }
    chdir("/");

    my $uid = getpwnam($self->{user}) if $self->{user};
    my $gid = getgrnam($self->{group}) if $self->{group};

    setuid($uid) if $uid;
    setgid($gid) if $gid;

    open(my $stdout, '>&', STDOUT); 
    open(my $stderr, '>&', STDERR);
    open(STDOUT, '>>', '/dev/null');
    open(STDERR, '>>', '/dev/null');
    getpid;
}

1;

#-------------
#--- TAIL ----
#-------------

package Tail;

use strict;
use warnings;

sub new {
    my ($class, $file) = @_;
    my $self = {
        file => $file,
        pos => 0
    };
    bless $self, $class;
    return $self;
}

sub file {
    my ($self, $name) = @_;
    return $self->{'file'} unless $name;
    $self->{'file'} = $name;
}

sub pos {
    my ($self, $pos) = @_;
    return $self->{'pos'} unless $pos;
    $self->{'pos'} = $pos;
}

sub first {
    my $self = shift;
    open my $fh, '<', $self->file;
    seek $fh, -2000, 2;
    readline $fh;
    my @res;
    while (my $line = readline $fh) {
        push @res, $line;
    }
    $self->pos(tell $fh);
    \@res;
}

sub last {
    my $self = shift;
    open my $fh, '<', $self->file;
    seek $fh, $self->pos, 0;
    my @res;
    while (my $line = readline $fh) {
        push @res, $line;
    }
    $self->pos(tell $fh);
    \@res;
}

1;

#--------------------
#--- CONTROLLER 1 ---
#--------------------

package SQM::Controller;

use strict;
use warnings;
use Mojo::Base 'Mojolicious::Controller';
use Mojo::Util qw(dumper);
use Mojo::JSON qw(decode_json encode_json);

use Apache::Htpasswd;

# --- AUTH ---

sub pwfile {
    my ($self, $pwfile) = @_;
    return $self->app->config('pwfile') unless $pwfile;
    $self->app->config(pwfile => $pwfile);
}

sub log {
    my ($self, $log) = @_;
    return $self->app->log unless $log;
    $self->app->log = $log;
}

sub ucheck {
    my ($self, $login, $password) = @_;
    return undef unless $password;
    return undef unless $login;
    my $pwfile = $self->pwfile or return undef;
    my $res = undef;
    eval {
        my $ht = Apache::Htpasswd->new({ passwdFile => $pwfile, ReadOnly => 1 });
        $res = $ht->htCheckPassword($login, $password);
    };
    1; #$res;
}

sub login {
    my $self = shift;
    return $self->redirect_to('/') if $self->session('login');

    my $login = $self->req->param('login') || undef;
    my $password = $self->req->param('password') || undef;

    return $self->render(template => 'login') unless $login and $password;

    if ($self->ucheck($login, $password)) {
        $self->session(login => $login);
        return $self->redirect_to('/');
    }
    $self->render(template => 'login');
}

sub logout {
    my $self = shift;
    $self->session(expires => 1);
    $self->redirect_to('/');
}

# --- HELLO ---

sub hello {
    my $self = shift;
    $self->render(template => 'hello');
}

# --- USER ---

sub user_list {
    my $self = shift;
    $self->render(template => 'user-list');
}

sub user_add_form {
    my $self = shift;
    $self->render(template => 'user-add-form');
}
sub user_add_handler {
    my $self = shift;
    $self->render(template => 'user-add-handler');
}

sub user_delete_form {
    my $self = shift;
    $self->render(template => 'user-delete-form');
}
sub user_delete_handler {
    my $self = shift;
    $self->render(template => 'user-delete-handler');
}

sub user_update_form {
    my $self = shift;
    $self->render(template => 'user-update-form');
}

sub user_update_handler {
    my $self = shift;
    $self->render(template => 'user-update-handler');
}

sub user_rename_form {
    my $self = shift;
    $self->render(template => 'user-rename-form');
}

sub user_rename_handler {
    my $self = shift;
    $self->render(template => 'user-rename-handler');
}


1;

#-----------
#--- APP ---
#-----------

package SQM;

use strict;
use warnings;
use Mojo::Base 'Mojolicious';

sub startup {
    my $self = shift;
}

1;


#############
#--- MAIN ---
#############

use strict;
use warnings;
use Mojo::Server::Prefork;
use Mojo::Util qw(dumper getopt);
use File::stat;

my $appname = 'sqm';

#--------------
#--- GETOPT ---
#--------------

getopt
    'h|help' => \my $help,
    'c|config=s' => \my $conffile,
    'f|nofork' => \my $nofork,
    'u|user=s' => \my $user,
    'g|group=s' => \my $group;

if ($help) {
    print qq(
Usage: app [OPTIONS]

Options
    -h | --help           This help
    -c | --config=path    Path to config file
    -u | --user=user      System owner of process
    -g | --group=group    System group
    -f | --nofork         Dont fork process

The options override options from configuration file
    )."\n";
    exit 0;
}

#------------------
#--- APP CONFIG ---
#------------------

my $server = Mojo::Server::Prefork->new;
my $app = $server->build_app('SQM');
$app = $app->controller_class('SQM::Controller');

$app->secrets(['6d578e453b88260e0375a1a35fd7954b']);

$app->static->paths(['@app_libdir@/public']);
$app->renderer->paths(['@app_libdir@/templs']);

$app->config(conffile => $conffile || '@app_confdir@/sqm.conf');
$app->config(pwfile => '@app_confdir@/sqm.pw');
$app->config(logfile => '@app_logdir@/sqm.log');
$app->config(loglevel => 'info');
$app->config(pidfile => '@app_rundir@/sqm.pid');
$app->config(crtfile => '@app_confdir@/sqm.crt');
$app->config(keyfile => '@app_confdir@/sqm.key');

$app->config(listenaddr4 => '0.0.0.0');
$app->config(listenaddr6 => '[::]');
$app->config(listenport => '8087');

$app->config(logpattern => 'access');
$app->config(logdir => '/var/log/squid');
$app->config(pwfile => '/tmp/squid-password');

$app->config(dbname => '@app_datadir@/sqm.db');
$app->config(dbhost => '');
$app->config(dblogin => '');
$app->config(dbpassword => '');
$app->config(dbengine => 'sqlite3');

$app->config(user => $user || '@app_user@');
$app->config(group => $group || '@app_group@');

if (-r $app->config('conffile')) {
    $app->log->debug("Load configuration from ".$app->config('conffile'));

    my $c = aConfig->new($app->config('conffile'));

    my $hash = $c->read;
    foreach my $key (keys %$hash) {
        $app->config($key => $hash->{$key});
    }
}

#---------------
#--- HELPERS ---
#---------------
$app->helper(
    tail => sub {
        state $tail = Tail->new($app->config('sqlog'));
});

$app->helper(
    db => sub {
        my $engine = 'SQLite' if $app->config('dbengine') =~ /sqlite/i;
        $engine = 'Pg' if $app->config('dbengine') =~ /postgres/i;
        state $db = aDBI->new(
            database => $app->config('dbname'),
            host => $app->config('dbhost'),
            login => $app->config('dblogin'),
            password => $app->config('dbpassword'),
            engine => $engine
        );
});

$app->helper(
    user => sub {
        state $user = aUser->new($app->db); 
});

$app->helper(
    counter => sub {
        state $couner = aCounter->new($app->db,
                                    $app->config('logpattern'),
                                    $app->config('logdir')
        );
});


$app->helper('reply.not_found' => sub {
        my $c = shift; 
        return $c->redirect_to('/login') unless $c->session('login'); 
        $c->render(template => 'not_found.production');
});


#--------------
#--- ROUTES ---
#--------------

my $r = $app->routes;

$r->add_condition(
    auth => sub {
        my ($route, $c) = @_;
        $c->session('login');
    }
);

$r->any('/login')->to('controller#login');
$r->any('/logout')->over('auth')->to('controller#logout');

$r->any('/')->over('auth')->to('controller#user_list' );
$r->any('/hello')->over('auth')->to('controller#hello');

$r->any('/user/list')->over('auth')->to('controller#user_list' );
$r->any('/user/add/form')->over('auth')->to('controller#user_add_form' );
$r->any('/user/add/handler')->over('auth')->to('controller#user_add_handler' );
$r->any('/user/update/form')->over('auth')->to('controller#user_update_form' );
$r->any('/user/update/handler')->over('auth')->to('controller#user_update_handler' );
$r->any('/user/delete/form')->over('auth')->to('controller#user_delete_form' );
$r->any('/user/delete/handler')->over('auth')->to('controller#user_delete_handler' );
$r->any('/user/rename/form')->over('auth')->to('controller#user_rename_form' );
$r->any('/user/rename/handler')->over('auth')->to('controller#user_rename_handler' );

#----------------
#--- LISTENER ---
#----------------

my $tls = '?';
$tls .= 'cert='.$app->config('crtfile');
$tls .= '&key='.$app->config('keyfile');

my $listen4;
if ($app->config('listenaddr4')) {
    $listen4 = "https://";
    $listen4 .= $app->config('listenaddr4').':'.$app->config('listenport');
    $listen4 .= $tls;
}

my $listen6;
if ($app->config('listenaddr6')) {
    $listen6 = "https://";
    $listen6 .= $app->config('listenaddr6').':'.$app->config('listenport');
    $listen6 .= $tls;
}

my @listen;
push @listen, $listen4 if $listen4;
push @listen, $listen6 if $listen6;

$server->listen(\@listen);
$server->heartbeat_interval(3);
$server->heartbeat_timeout(60);


#--------------
#--- DAEMON ---
#--------------

unless ($nofork) {
    my $user = $app->config('user');
    my $group = $app->config('group');
    my $d = Daemon->new($user, $group);

    $d->fork;

    $app->log(Mojo::Log->new(
                path => $app->config('logfile'),
                level => $app->config('loglevel')
    ));
}

$server->pid_file($app->config('pidfile'));

#---------------
#--- WEB LOG ---
#---------------

$app->hook(before_dispatch => sub {
        my $c = shift;

        my $remote_address = $c->tx->remote_address;
        my $method = $c->req->method;

        my $base = $c->req->url->base->to_string;
        my $path = $c->req->url->path->to_string;
        my $loglevel = $c->app->log->level;
        my $url = $c->req->url->to_abs->to_string;

        my $login  = $c->session('login') || 'undef';

        unless ($loglevel eq 'debug') {
            #$c->app->log->info("$remote_address $method $base$path $login");
            $c->app->log->info("$remote_address $method $url $login");
        }
        if ($loglevel eq 'debug') {
            $c->app->log->debug("$remote_address $method $url $login");
        }
});


# Set signal handler
local $SIG{HUP} = sub {
    $app->log->info('Catch HUP signal'); 
    $app->log(Mojo::Log->new(
                    path => $app->config('logfile'),
                    level => $app->config('loglevel')
    ));
};


my $sub = Mojo::IOLoop::Subprocess->new;
$sub->run(
    sub {
        my $subproc = shift;
        my $loop = Mojo::IOLoop->singleton;
        my $id = $loop->recurring(
            300 => sub {
		$app->log->info('Begin count');
		my $bill = $app->counter->count;
		$app->user->host_clean;
		foreach my $name (keys %{$bill}) {
		    my $size = $bill->{$name}{size};
		    my $user_id = $app->user->user_exist($name);
		    $app->log->debug("Count user=$name user_id=$user_id size=$size");
		    $app->user->user_update($user_id, size => $size) if $user_id;
		}
		$app->log->info('Done count');
            }
        );
        $loop->start unless $loop->is_running;
        1;
    },
    sub {
        my ($subprocess, $err, @results) = @_;
        $app->log->info('Exit subprocess');
        1;
    }
);

my $pid = $sub->pid;
$app->log->info("Subrocess $pid start ");

$server->on(
    finish => sub {
        my ($prefork, $graceful) = @_;
        $app->log->info("Subrocess $pid stop");
        kill('INT', $pid);
        sleep 1;
        kill('KILL', $pid);
    }
);

#my $bill = $app->counter->count;

##$app->user->host_clean;

#foreach my $name (keys %{$bill}) {
#    my $size = $bill->{$name}{size};
#    my $user_id = $app->user->user_exist($name);
#    $app->user->user_update($user_id, size => $size);
#    print "$name $size\n";
#}

#foreach my $name (keys %{$bill}) {
#    my $user_id = $app->user->user_exist($name);
#    next unless $user_id;
#
#    my $hosts = $bill->{$name}{hosts};
#
#    if ($user_id) {
#        $app->user->host_clean($user_id);
#        foreach my $host (keys %{$hosts}) {
#            my $size = $hosts->{$host}->{size};
#            $size ||= 0;
#            $app->user->host_update($host, $user_id, $size);
#            print "$user_id $host $size\n";
#        }
#    }
#}

#$app->user->export_passwd("/tmp/aaa.txt");

$server->run;
#EOF

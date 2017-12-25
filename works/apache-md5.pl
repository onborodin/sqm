
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
    my($pw, $salt) = @_;
    return undef unless $pw;
    return undef unless $salt;

    my $passwd;
    my $magic = '$apr1$';

    $salt =~ s/^\Q$magic//;        # Take care of the magic string if present.
    $salt =~ s/^(.*)\$.*$/$1/;        # Salt can have up to 8 chars...
    $salt = substr($salt, 0, 8);

    my($ctx) = Digest::MD5->new;        # Here we start the calculation.
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


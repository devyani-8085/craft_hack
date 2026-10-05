#!/usr/bin/perl
# Language: Perl (Digest::*, Crypt::CBC, Crypt::DES, Crypt::RSA, IO::Socket::SSL)
# Expected artifacts: MD5, SHA-1, SHA-256 | DES, Blowfish, Rijndael (AES) via Crypt::CBC | RSA-1024 | SSL_version TLSv1 | rand() (weak)
use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(sha1_hex sha256_hex);
use Crypt::CBC;
use Crypt::RSA;
use IO::Socket::SSL;

my $HARDCODED_KEY = "0123456789abcdef";
md5_hex("data"); sha1_hex("data"); sha256_hex("data");
Crypt::CBC->new(-key => $HARDCODED_KEY, -cipher => "DES");
Crypt::CBC->new(-key => $HARDCODED_KEY, -cipher => "Blowfish");
Crypt::CBC->new(-key => $HARDCODED_KEY, -cipher => "Rijndael");
Crypt::RSA->new->keygen(Size => 1024);
IO::Socket::SSL->new(PeerAddr => "example.com:443", SSL_version => "TLSv1", SSL_verify_mode => 0);
my $weak = rand(1000);

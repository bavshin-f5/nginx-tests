#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Aleksei Bavshin
# (C) Nginx, Inc.

# Tests for http ssl module, loading "store:..." certificates from OpenSSL
# providers.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

plan(skip_all => 'win32') if $^O eq 'MSWin32';

# plan(skip_all => 'may not work, incompatible with sanitizers')
#	unless $ENV{TEST_NGINX_UNSAFE};

my $t = Test::Nginx->new()->has(qw/http http_ssl geo proxy openssl:3/)
	->has_daemon('openssl')->has_daemon('softhsm2-util')
	->has_daemon('pkcs11-tool');

# plan(skip_all => 'not yet') unless $t->has_version('1.29.5');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

env SOFTHSM2_CONF;

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8081 ssl;
        listen       127.0.0.1:8080;
        server_name  localhost;

        ssl_certificate     "store:pkcs11:token=NginxZero;object=nx_key_0";
        ssl_certificate_key "store:pkcs11:token=NginxZero;object=nx_key_0";

        ssl_password_file pin.txt;

        proxy_ssl_name localhost;
        proxy_ssl_server_name on;
        proxy_ssl_trusted_certificate root.crt;
        proxy_ssl_verify on;
		proxy_ssl_verify_depth 10;

        location / {
            # index index.html by default
        }

        location /proxy {
            proxy_pass https://127.0.0.1:8081/;
        }

        location /var {
            proxy_pass https://127.0.0.1:8082/;
        }
    }

    geo $geo {
        default nx_key_0;
    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  localhost;

        ssl_certificate     "store:pkcs11:token=NginxZero;object=$geo";
        ssl_certificate_key "store:pkcs11:token=NginxZero;object=$geo";

        ssl_password_file pin.txt;

        location / {
            # index index.html by default
        }
    }
}

EOF

# Create a SoftHSM token with a secret key, and configure OpenSSL to access it
# using the pkcs11 provider (https://github.com/latchset/pkcs11-provider).
#
# Note that library paths vary on different systems,
# and may need to be adjusted.

my $libsofthsm2_path;
my @so_paths = (
	'/usr/lib/softhsm',		# Debian-based
	'/usr/local/lib/softhsm',	# FreeBSD
	'/opt/local/lib/softhsm',	# MacPorts
	'/lib64',			# RHEL-based
	split /:/, $ENV{TEST_NGINX_SOFTHSM} || ''
);

for my $so_path (@so_paths) {
	$so_path .= '/libsofthsm2.so';
	if (-e $so_path) {
		$libsofthsm2_path = $so_path;
		last;
	}
};

plan(skip_all => "libsofthsm2.so not found") unless $libsofthsm2_path;

my $d = $t->testdir();

my $openssl_conf = <<EOF;
openssl_conf = openssl_def

[openssl_def]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
pkcs11-module-path = $libsofthsm2_path
pkcs11-module-cache-pins = cache
# https://github.com/latchset/pkcs11-provider/commit/ab6370fd
pkcs11-module-quirks = no-deinit no-operation-state
module = /usr/local/lib/ossl-modules/pkcs11.so
activate = 1

[ ca ]
default_ca = myca

[ myca ]
new_certs_dir = $d
database = $d/certindex
default_md = sha256
policy = myca_policy
serial = $d/certserial
default_days = 1
x509_extensions = myca_extensions

[ myca_policy ]
commonName = supplied

[ myca_extensions ]
basicConstraints = critical,CA:TRUE

[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

$openssl_conf =~ s|^(?=module)|# |m if $^O ne 'freebsd';
$t->write_file('openssl.conf', $openssl_conf);

$t->write_file('softhsm2.conf', <<EOF);
directories.tokendir = $d/tokens/
objectstore.backend = file
EOF

mkdir($d . '/tokens');

$ENV{SOFTHSM2_CONF} = "$d/softhsm2.conf";
$ENV{OPENSSL_CONF} = "$d/openssl.conf";

foreach my $name ('root') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. '-extensions myca_extensions '
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('certserial', '1000');
$t->write_file('certindex', '');
$t->write_file('chain.crt', '');

my @INTERMEDIATES = (
	'int1',
#	'int2',
);
my $issuer = 'root';

# generate chain of certificates, each signed by the previous one

foreach my $name (@INTERMEDIATES) {
	system("openssl req -new "
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. '-extensions myca_extensions '
		. "-out $d/$name.csr -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";

	system("openssl ca -batch -config $d/openssl.conf "
		. "-keyfile $d/$issuer.key -cert $d/$issuer.crt "
		. "-subj /CN=$name/ -in $d/$name.csr -out $d/$name.crt "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't sign certificate for $name: $!\n";

	$issuer = $name;
}

foreach my $name ('localhost') {
	system('softhsm2-util --init-token --slot 0 --label NginxZero '
		. '--pin 1234 --so-pin 1234 '
		. ">>$d/openssl.out 2>&1");

	system("openssl genrsa -out $d/$name.key 2048 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create private key: $!\n";
    
	system("softhsm2-util --import $d/$name.key --id 00 --label nx_key_0 "
		. '--token NginxZero --pin 1234 '
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't import private key: $!\n";

	system('openssl req -new '
		. "-subj /CN=$name/ -out $d/$name.csr -text -passin pass:1234 "
		. '-key "pkcs11:token=NginxZero;object=nx_key_0" '
		. ">>$d/openssl.out 2>&1") == 0
		or plan(skip_all => "missing pkcs11-provider");

	system("openssl ca -batch -config $d/openssl.conf "
		. "-keyfile $d/$issuer.key -cert $d/$issuer.crt "
		. "-subj /CN=$name/ -in $d/$name.csr -out $d/$name.crt "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't sign certificate for $name: $!\n";
}

# push the whole chain excluding root to the SoftHSM token

foreach my $name ('localhost', (reverse @INTERMEDIATES)) {
	system('pkcs11-tool --verbose '
		. "--module=$libsofthsm2_path "
		. '--token-label NginxZero --pin 1234 --login '
		. "--write-object $d/$name.crt --type cert --label nx_key_0 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't store certificate to pkcs11 token: $!\n";
}

$t->write_file('pin.txt', '1234');
$t->write_file('index.html', '');

$t->run()->plan(2);

###############################################################################

like(http_get('/proxy'), qr/200 OK/, 'ssl provider certificate');
like(http_get('/var'), qr/200 OK/, 'ssl_certificate with variable');

###############################################################################

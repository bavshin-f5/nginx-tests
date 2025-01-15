#!/usr/bin/perl

# (C) Sergey Kandaurov
# (C) Aleksei Bavshin
# (C) Nginx, Inc.

# Tests for http ssl module, loading "store:..." keys.

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

# swtpm tcti wants two adjacent ports
plan(skip_all => 'requires contiguous port allocation')
	unless $ENV{TEST_NGINX_UNSAFE};

my $t = Test::Nginx->new()->has(qw/http proxy http_ssl/)->has_daemon('openssl')
	# closer to the real usage, but needs a DBus session
	# ->has_daemon('tpm2-abrmd')
	->has_daemon('swtpm')->has_daemon('tpm2_createek');

plan(skip_all => "not yet") unless $t->has_version('1.27.4');
plan(skip_all => 'no providers') unless $t->has_feature('openssl:3');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

env OPENSSL_CONF;
# env TPM2OPENSSL_TCTI;

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        proxy_ssl_name $arg_scheme.example.com;
        proxy_ssl_server_name on;

        location / {
            proxy_pass https://127.0.0.1:8081/;
        }

        location /var {
            proxy_pass https://127.0.0.1:8082/;
        }
    }

    server {
        listen      127.0.0.1:8081 ssl;
        server_name file.example.com;

        ssl_certificate file.example.com.crt;
        ssl_certificate_key store:file:%%TESTDIR%%/file.example.com.key;

        location / {
            # index index.html by default
        }

    }

    server {
        listen      127.0.0.1:8081 ssl;
        server_name handle.example.com;

        ssl_certificate handle.example.com.crt;
        ssl_certificate_key store:handle:0x81000000;

        location / {
            # index index.html by default
        }

    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  file.example.com;

        ssl_certificate $ssl_server_name.crt;
        ssl_certificate_key store:file:%%TESTDIR%%/file.example.com.key;

        location / {
            # index index.html by default
        }
    }

    server {
        listen       127.0.0.1:8082 ssl;
        server_name  handle.example.com;

        ssl_certificate $ssl_server_name.crt;
        ssl_certificate_key store:handle:0x81000000;

        location / {
            # index index.html by default
        }
    }
}

EOF

my $d = $t->testdir();

my $swtpm_port = port(8321);
my $swtpm_control = port(8322);
my $tcti = "swtpm:host=localhost,port=${swtpm_port}";

$t->run_daemon('swtpm', 'socket', '--tpm2',
	'--server', "port=${swtpm_port}",
	'--ctrl', "type=tcp,port=${swtpm_control}",
	'--flags', 'not-need-init,startup-clear',
	'--tpmstate', "dir=$d",
	'--seccomp', 'action=none');

# requires DBus session
#
# $t->run_daemon('tpm2-abrmd', '--allow-root', '--session', '--tcti', $tcti,
# 	'--dbus-name', "com.intel.tss2.Tabrmd${swtpm_port}");
# $tcti = "tabrmd:bus_name=com.intel.tss2.Tabrmd${swtpm_port},bus_type=session";
# select undef, undef, undef, 1.0;

$t->write_file('openssl.conf', <<EOF);
openssl_conf = openssl_def

[openssl_def]
providers = provider_sect

[provider_sect]
default = default_sect
tpm2 = tpm2_sect

[default_sect]
activate = 1

[tpm2_sect]
activate = 1

[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

$ENV{OPENSSL_CONF} = "$d/openssl.conf";
$ENV{TPM2TOOLS_TCTI} = $tcti;
$ENV{TPM2OPENSSL_TCTI} = $tcti;

foreach my $name ('file.example.com') {
	system('openssl req -x509 '
		. "-config $d/openssl.conf -provider tpm2 -provider default -propquery '?provider=tpm2' "
		. "-subj /CN=$name/ -out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die('openssl req'); 
}

foreach my $name ('handle.example.com') {
	system('tpm2_createek -G ecc -c ek_ecc.ctx'
		. ">>$d/openssl.out 2>&1") == 0
		or die('tpm2_createek failed');

	system('tpm2_createak -C ek_ecc.ctx -G ecc -g sha256 -s ecdsa -c ak_ecc.ctx'
		. ">>$d/openssl.out 2>&1") == 0
		or die('tpm2_createak failed');

	system('tpm2_flushcontext -t'
		. ">>$d/openssl.out 2>&1") == 0
		or die('tpm2_flushcontext failed');

	system('tpm2_evictcontrol -c ak_ecc.ctx 0x81000000'
		. ">>$d/openssl.out 2>&1") == 0
		or die('tpm2_evictcontrol failed');

	system('openssl req -x509 -new '
		. "-subj /CN=$name/ -out $d/$name.crt -text "
		. "-provider tpm2 -key handle:0x81000000 "
		. ">>$d/openssl.out 2>&1") == 0
		or plan(skip_all => "missing provider");
}

$t->run()->plan(4);

$t->write_file('index.html', '');

###############################################################################

like(http_get('/?scheme=file'), qr/200 OK/, 'tpm2 provider file:...');
like(http_get('/?scheme=handle'), qr/200 OK/, 'tpm2 provider handle:...');

like(http_get('/var?scheme=handle'), qr/200 OK/,
	'tpm2 provider handle:... with variable');

SKIP: {
skip 'fails without tpm2-abrmd', 1 unless $tcti =~ /^tabrmd:/;

like(http_get('/var?scheme=file'), qr/200 OK/,
	'tpm2 provider file:... with variable');
}

###############################################################################

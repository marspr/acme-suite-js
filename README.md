ACME Suite for node.js
======================

[![Build Status](https://travis-ci.org/marspr/acme-suite-js.svg?branch=master)]
(https://travis-ci.org/marspr/acme-suite-js)

Intro
-----

Let's Encrypt-compatible implementation of the
Automated Certificate Management Environment (ACME) protocol proposed by:
[draft-ietf-acme-acme-01](https://tools.ietf.org/html/draft-ietf-acme-acme-01)

Benefits
--------

* Easy to use CLI and API
* Leaves web server untouched
* Runnable as unprivileged user

The original Let's Encrypt client and derivations usally try to automatically
configure Apache or Nginx. However, this leads to either unnecessary downtime
or rather complex fiddling. Therefore, this should be left to dedicated server
plugins or scripts.

ACME Suite may provide such scripts in the future,
especially for challenges other than http-01, but does not at the moment.
Check out the [Wiki on Github](https://github.com/marspr/acme-suite-js/wiki)
to learn how to easily prepare Nginx for http-01 challenge and certificate
installation.

Features
--------

* Client API and CLI
* Account creation and information
* Certificate signing
* Domain authorization using http-01 challenge
* Local or remote use
* Does not require root privileges

**Planned**
* Server API and CLI
* Account recovery
* Certificate revocation
* Domain authorization using tls-sni-01 or proofOfPossession-01 challenge

Components
----------

* AcmeClient - Automated Certificate Management Environment client API
* AcmeHelper - ACME command line interface helper API
* JWebClient - JSON Web Token HTTPS client API used with ACME client
* acme-client-cli - Command line interface using ACME client API

Requirements
------------

Requires working `openssl` command to generate account or certificate key as
well as the certificate signing request (CSR). OpenSSL must be properly
configured. The repository contains a small configuration file for OpenSSL
if needed. Its path can be set as `OPENSSL_CONF` and also works on Windows.

Setup
-----

Make sure `openssl` is working. Any recent version should be OK.

`acme-client-cli` will automatically generate a new account key for you.
You can also generate your own:

    openssl genrsa 4096 > account.key

Challenge data will be written to the `.well-known` directory in the
working directory upon domain authorization. This directory must be
published on the web server for the http-01 challenge to complete.

Signed certificates and associated private keys will be saved in the
working directory. Filenames will correspond to the domain name like this:
`www.example.com.der` and `www.example.com.key`. In rare cases filenames
may not match domain name in order to avoid forbidden characters.

Publishing of challenge data and certificate deployment can be automated
using scripts if desired.

Remember that Let's Encrypt provides its staging API for testing purposes.
This should be used to test your setup before going productive.

Usage
-----

CLI
---

Register new account

    acme-client -c=reg -e=hostmaster@example.com

Authorize new domain and write challenge data to server web root

    acme-client -c=add -d=www.example.com -w=/var/www -y
	
Authorize new domain and write challenge data to working directory and wait for
user to confirm transfer of challenge data to server in order to proceed

    acme-client -c=add -d=www.example.com
	
Create and submit certificate signing request (validity period 90 days)

    acme-client -c=csr -d=www.example.com -l=US -n=90 -o="Example Inc."
	
Get profile info

    acme-client -c=info

**Parameters:**

Action to perform

    -c=ACTION - add (authorize domain), csr, info (profile) or reg (register)
	
Certificate details

    -d=DOMAIN, -e=EMAIL, -l=COUNTRY, -n=DAYSVALID -o=ORGANIZATION
	
Configuration

    -k=FILE - Specifiy account key file name, default is ./account.key
    -r=BIT - RSA key size, default is 4096 (some devices may only support 2048)
    -u=URL - ACME URL, e.g. https://api.example.com
	-w=PATH - Path where .well-known directory shall be created
	-y - Useful if acme client and web server are running on the same machine
	
Help

    -h - Display a help with explanation of parameters like this
	
Verbose mode

    -v - Use this to get insight about what is sent and received
	
API
---

Documentation of API can be found on Github.

New instance

    var JWebClient = require('acme-suite').JWebClient;
    var AcmeClient = require('acme-suite').AcmeClient;
	var acme_client = new AcmeClient(
        "https://acme-v01.api.letsencrypt.org/directory",
        new JWebClient()
    );
	
Configuration

	acme_client.days_valid = DAYSVALID; // validity period in days
	acme_client.defaultRsaKeySize = BIT; // RSA key size
	acme_client.emailOverride = EMAIL; // email addresss to use
	acme_client.webroot = PATH; // path to server web root
	acme_client.withInteraction = YES; // avoid user interaction
	
Get profile info and print ID

    acme_client.getProfile(function (profile) {
    	process.stdout.write("User ID: " + profile["id"] + "\n");
    });
	
Create and submit certificate signing request

    acme_client.requestCertificate(domain, organization, country,
    function (success) {
		process.stdout.write("Success: " + success);
    });

Security considerations
-----------------------

* `acme-client` should be run as non-priviledged user
* This user must have
    * write permissions for working directory
    * write permissions for `.well-known` directory under web root
    * read permissions for existing `account.key`
	* execute permissions for `openssl`
* RSA key size should not be lower than 2048 bit
* Verbose mode may output sensitive data

License
-------
	
This software is free and open source. See LICENSE for details.
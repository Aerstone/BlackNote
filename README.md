BlackNote
=========
[![Build Status](https://travis-ci.org/Aerstone/BlackNote.svg?branch=testing)](https://travis-ci.org/Aerstone/BlackNote)

**WARNING:** There has been no formal security review of the current BETA version. Use at your own risk.

BlackNote is a paste tool for sharing quick and temporary secrets. Everything except storage is done clientside with NaCl secretbox

Use Case
--------
In a perfect world passwords (even temporary ones) should not be shared. But often, an administrator will need to set a temporary password in order to allow a user to log in to change their password. Instead of sending the password in plaintext through email, they can now instead send a BlackNote link.

Installation
------------
In order to get a quick running version:

```
git clone git@github.com:Aerstone/BlackNote.git
cd ./blacknote
go run blacknote.go 
```
or to build binaries

```
git clone git@github.com:Aerstone/BlackNote.git
cd ./blacknote
go build blacknote.go
./blacknote
```

This will require certificates and keys as HTTPS is forced by default. Certificates are defined by:

* `-c`: For the certificate (default: `./server.crt`)
* `-k`: For the keys (default: `./server.key`)
* `-I`: Insecure mode without HTTPS (not suggested ever)

The suggested installation is to use BlackNote behind a proxy (such as nginx) in order to handle maximum upload size and a couple of other corner cases.

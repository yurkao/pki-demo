# pki-demo
## start Demo
```shell
docker-compose up
```
This will bring up 4 running containers:
1. `root-ca`
2. `intermediate-ca`
3. `server`, used for testing HTTPS server
4. `client`, used for testing HTTPS client

The local `tmp` folder is shared between running containers, and it's mounted as `/tmp` in-container folder.

Store only public files (non-sensitive) files in `/tmp` folder.


## Setting up Root CA
Configuration file is located in `/usr/local/openssl/opnssl-rca.cnf` in `root-ca` container.

### Generate Root CA key and certificate (self-signed)
Open `root-ca` container CLI and run following to generate RootCA key and certificate
```shell
RCA_DIR="/usr/local/openssl"
RCA_KEY="${RCA_DIR}/private/rca.key"
RCA_CRT="${RCA_DIR}/certs/rca.crt"
export SUBJECT="/C=XY/ST=XY/L=XY/O=Acme LTD/OU=Acme LTD/CN=DemoRootCA"
openssl req -nodes -x509 -newkey rsa:4096 -keyout "${RCA_KEY}" -out "${RCA_CRT}" -subj "${SUBJECT}" > /dev/null 2>&1
```

The RootCA's certificate will be located in `/usr/local/openssl/certs/rca.crt`.

The RootCA's private key will be located in `/usr/local/openssl/private/rca.key`.
### Investigating results
```shell
ls -l /usr/local/openssl/certs/rca.crt /usr/local/openssl/private/rca.key
```

Show Root CA certificate info:
```shell
openssl x509 -text -noout -in /usr/local/openssl/certs/rca.crt
```
Note, that subject and issuer are the same, e.g. `C=XY, ST=XY, L=XY, O=Acme LTD, OU=Acme LTD, CN=DemoRootCA`:
1. Country is `XY`
2. State is `XY`
3. Location is `XY`
4. Organisation (AKA `O`) is `Acme LTD`
5. Organisation Unit (AKA `OU`) is `Acme LTD`
6. Common name (AKA `CN` - end entity name) is `DemoRootCA`


Look at `Issuer` and `Subject`.
Also, look at `X509v3 Subject Key Identifier` and `X509v3 Authority Key Identifier`.
The `Subject` means "current certificate" and `Authority`/`Issuer` is who issued/signed the certificate.

The difference between `Subject` and `Subject Key Identifier` is:
1. `Subject` is (generally speaking) just human-readable string identification of certificate
2. While `Subject Key Identifier` is derived from the public key (generally speaking is a hash of public key)

Note, that `Subject Key Identifier` and `Authority Key Identifier` have same values.
This means that this is so-called "self-signed" certificate: certificate that was signed by its own private key.
Self-signed certificate also called RootCA certificate.


## Setting up Intermediate CA (ICA)
Setting up Intermediate CA includes following steps:
1. Generating private key for Intermediate CA (done in ICA side)
2. Create certificate sign request (CSR) signed with ICA private key (done in ICA side)
3. Copying ICA's CSR to RCA host
4. Signing ICA's CSR with RCA private key and producing certificate for ICA (done on RCA side)
5. Copying produced ICA certificate to ICA host
Configuration file is located in `/usr/local/openssl/opnssl-rca.cnf` in `root-ca` container.

### Generate ICA private key
Open `intermediate-ca` container CLI and run following to generate ICA private key 
 
```shell
export ICA_DIR="/usr/local/openssl"
ICA_KEY="${ICA_DIR}/private/ica.key"
openssl genrsa -out "${ICA_KEY}"
```
the resulted ICA private ky will be located in `/usr/local/openssl/private/ica.key`.

### Create ICA certificate sign request
Continue using `intermediate-ca` container CLI and run following to generate ICA certificate sign request:
```shell
export SUBJECT="/C=XY/ST=XY/L=XY/O=Acme LTD/OU=Acme LTD/CN=DemoICA"
openssl req -new -key "${ICA_KEY}" -out /tmp/ica.csr -subj "${SUBJECT}"
```
This will create ICA CSR in `/tmp/ica.csr` file.

The CSR form will contain following info:
1. Country is `XY`
2. State is `XY`
3. Location is `XY`
4. Organisation (AKA `O`) is `Acme LTD`
5. Organisation Unit (AKA `OU`) is `Acme LTD`
6. Common name (AKA `CN` - end entity name) is `DemoICA`

Investigate resulted ICA CSR by running:
```shell
openssl req -text -noout -in /tmp/ica.csr
```
### Copy ICA CSR to RCA
Copy created ICA CSR file (`/tmp/ica.csr`) to `root-ca` container

### Signing ICA's CSR with RCA
On `root-ca` container run following:
```shell
openssl ca -extensions v3_intermediate_ca -out /tmp/ica.crt -infiles /tmp/ica.csr
```
This will sign ICA CSR and create certificate for ICA. The resulted certificate will be saved twice :
1. `/usr/local/openssl/certs/00.pem` file (for further tracking by RCA). 00 is a local certificate serial number. See `/usr/local/openssl/serial` file.
2. `ica.crt` file in current directory of `root-ca` container.

They are the same:
```shell
# md5sum /usr/local/openssl/certs/00.pem /tmp/ica.crt
<some-hash-sum>  /usr/local/openssl/certs/00.pem
<some-hash-sum>  ica.crt
```
Investigate resulted ICA certificate
###
Dump ICA certificate info:
```shell
openssl x509 -text -noout -in /tmp/ica.crt
```
Look at `Issuer` and `Subject`.
Also, look at `X509v3 Subject Key Identifier` and `X509v3 Authority Key Identifier`.
The `Subject` means "current certificate" and `Authority`/`Issuer` is who issued/signed the certificate.

The difference between `Subject` and `Subject Key Identifier` is:
1. `Subject` is (generally speaking) just human-readable string identification of certificate
2. While `Subject Key Identifier` is derived from the public key (generally speaking is a hash of public key)

Same for `Issuer` and `X509v3 Authority Key Identifier`.

### Copying produced ICA certificate to ICA host
Copy produced ICA certificate `ica.crt` from `root-ca` container to `intermediate-ca` and put the certificate
in `/usr/local/openssl/certs/ica.crt` on `intermediate-ca` container.


## Setting up server
### Generate server private key 
Open `server` container CLI and run following to generate server private key

```shell
SRV_KEY="/root/server.key"
openssl genrsa -out "${SRV_KEY}"
```
This will generate server private key and store it in `/root/server.key`.

### Generate server private key 
Open `server` container CLI and run following to generate server CSR
```shell
SUBJECT="/C=XY/ST=XY/L=XY/O=Acme LTD/OU=Acme LTD/CN=server.local"
openssl req -new -key "${SRV_KEY}" -out /tmp/server.csr -subj "${SUBJECT}"
```


### Sign server certificate on ICA
Copy server CSR file (`/tmp/server.csr`) from `server` container to `intermediate-ca` container.
Sign it with ICA by running following on `intermediate-ca` CLI:
```shell
openssl ca -policy policy_strict -extensions server_cert -out /tmp/server.crt -infiles server.csr
```

As in case of issuing/signing ICA certificate above, the server certificate will be written twice in ICAL

Validate they are the same by running following in `intermediate-ca`:
```shell
root@intermediate-ca:~# ls -l /tmp/server.crt /usr/local/openssl/certs/00.pem
-rw-r--r-- 1 root root 5003 Sep 10 15:28 /usr/local/openssl/certs/00.pem
-rw-r--r-- 1 root root 5003 Sep 10 15:28 /tmp/server.crt

root@intermediate-ca:~# md5sum /tmp/server.crt /usr/local/openssl/certs/00.pem
<hash>  /tmp/server.crt
<hash>  /usr/local/openssl/certs/00.pem
```

### Copy server certificate back
Copy server certificate to `server` container to be stored in `/tmp/server.crt`.

Now SSL/TLS server is ready to be run.

### Run simple HTTPS server
On `server` container run simple HTTPS server
```shell
openssl s_server -accept 443 -key "$SRV_KEY" -cert /tmp/server.crt -www
```

## Test HTTPS client
### Create CA certificate bundle
On `root-ca` container, copy RCA certificate to `/tmp` directory.
```shell
cp /usr/local/openssl/certs/rca.crt /tmp
```
Since `/tmp` is shared between containers, switch to `client` container CLI and concatenate two CA certificates (rca.crt and ica.crt) and store them on `client` in `/tmp/ca.crt` file.
```shell
cat /tmp/rca.crt /tmp/ica.crt > /tmp/ca-cundle.crt
```
### Perform https client test
On `client` container CLI, run following:
```shell
openssl s_client -connect server.local:443 -CAfile /tmp/ca-cundle.crt
```

The result should be as following:
```shell
CONNECTED(00000003)
depth=2 C = XY, ST = XY, L = XY, O = Acme LTD, OU = Acme LTD, CN = DemoRootCA
verify return:1
depth=1 C = XY, ST = XY, O = Acme LTD, OU = Acme LTD, CN = DemoICA
verify return:1
depth=0 C = XY, ST = XY, O = Acme LTD, OU = Acme LTD, CN = server.local
verify return:1
---
Certificate chain
 0 s:/C=XY/ST=XY/O=Acme LTD/OU=Acme LTD/CN=server.local
   i:/C=XY/ST=XY/O=Acme LTD/OU=Acme LTD/CN=DemoICA
---
Server certificate
-----BEGIN CERTIFICATE-----
<... snip ...>
-----END CERTIFICATE-----
subject=/C=XY/ST=XY/O=Acme LTD/OU=Acme LTD/CN=server.local
issuer=/C=XY/ST=XY/O=Acme LTD/OU=Acme LTD/CN=DemoICA
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: ECDH, P-256, 256 bits
---
SSL handshake has read 1776 bytes and written 527 bytes
---
New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: zlib compression
Expansion: zlib compression
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 84DE10A39A22CA4AB277EC4E4043EBEC07D3924B5DB1FBD7BBC1C48EC53D826A
    Session-ID-ctx:
    Master-Key: 5AA79E2052D57FB5AA32B5B85703BBB1CD67341D1EA8C42980175DAF52FEAEA70EF7DD02AD0D7BAA7D17E7719972BFFF
    <.... snip ....>
    Compression: 1 (zlib compression)
    Start Time: 1631346230
    Timeout   : 300 (sec)
    Verify return code: 0 (ok)
---
```
The `Verify return code: 0 (ok)` indicates that certificate is valid in terms of:
1. Issuers chain (ICA and RCA) is known (trusted)
2. Certificate is not expired
3. `CN` (a.k.a. common-name) or `SAN`s (Subject Alternative Name) matches server hostname

# Encryption Decryption test
## Encryption
Copy server certificate from `server` to `client` and extract server public key from server certificate by running run following on `client` container:
```shell
# extract public key from certificate
openssl x509 -pubkey -noout -in server.crt > /tmp/server.pub
```

Create "top secret" data to be encrypted on `client` and store it in `/tmp/secret-message`:
```shell
echo "My TOP secret message" > /root/secret-message
```

Encrypt "top secret" data on `client`:
```shell
openssl rsautl -in /root/secret-message -out /tmp/secret-message.enc -pubin -inkey /tmp/server.pub -encrypt
```

The encrypted result will be stored in `/tmp/secret-message.enc` file (it's a binary blob).

Transfer encrypted result (`/tmp/secret-message.enc`) from `client` container to `server` container.

Note: since encrypted data is binary blob, use `base64` tool for ease of transferring between containers by copy-pasting the content.

## Decryption
Decrypt encrypted data on `server` container by running following:
```shell
openssl rsautl -in /tmp/secret-message.enc -out /root/secret-message.dec -inkey /root/server.key -decrypt
```

The decrypted result will be stored in `/root/secret-message.dec` file.

Compare content of `/root/secret-message.dec` on `server` container with original "top-secret" message on `client` container (e.g. `/root/secret-message`).

# Signing and Verification test
In this test we will test singing and verify signature over previously encrypted message `/tmp/secret-message.enc`, though we may use any other test data.

## Singing
To sign file, on `server` container run following:
```shell
openssl dgst -sha256 -sign /root/server.key -out /tmp/secret-message.sign /tmp/secret-message.enc
```
The signature of signed data will be stored in `/tmp/secret-message.sign`.

## Signature verification
To verify the signature with public key, run following on `client` container CLI:
```shell
openssl dgst -sha256 -verify /tmp/server.pub -signature /tmp/secret-message.sign /tmp/secret-message.enc
```
The output will be 
```shell
Verified OK
```

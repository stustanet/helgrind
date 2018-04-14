# Helgrind
Helgrind is an HTTPS Authentication Gateway with strong focus on security.

## Gateway Setup

Make sure Git and Go 1.8+ (on Debian Stretch one can use stretch-backports) are installed on the host system.

```sh
go get gitlab.stusta.de/stustanet/helgrind
```

Helgrind requieres a TLS certificate to offer HTTPS. You can acquire one e.g. via [Let's Encrypt](https://letsencrypt.org/) and [certbot](https://certbot.eff.org/).

### Certificate Authority
Generate a CA certificate and private key:

```sh
openssl genrsa -aes256 -out ca.key 4096
chmod 400 ca.key
openssl req -new -x509 -sha256 -days 3650 -key ca.key -out ca.crt
chmod 444 ca.crt
```

The `ca.key` should be kept private in a secure offline storage. The `ca.crt` has to be copied to the gateway server.

### Helgrind Config
First copy the example file to `/etc/helgrind.json`:

```sh
cp $GOPATH/src/gitlab.stusta.de/stustanet/helgrind/etc/helgrind.json.example /etc/helgrind.json
```

Then adjust the `/etc/helgrind.json` config file.
Each backend service has to be configured in its own block.
User access is granted per service.

### systemd service

First, create a separate user for helgrind:

```sh
useradd --system -s /bin/false -M helgrind
```

Then copy the systemd unit files:

```sh
cp $GOPATH/src/gitlab.stusta.de/stustanet/helgrind/systemd/helgrind.* /etc/systemd/system/
```

Adjust `/etc/systemd/system/helgrind.socket` and `/etc/systemd/system/helgrind.service` if necessary.

Afterwards, run:

```sh
systemctl enable helgrind.socket helgrind.service
systemctl start helgrind.socket helgrind.service
```


## Adding a User
First the **user** has to generate a private key and a signing request for it:

```sh
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
```

Then the `client.csr` (the private key must not be shared) has to be sent to the **gateway admin**, which has to sign the certificate:

```sh
openssl x509 -req -days 730 -sha256 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 1 -out client.crt
```

The SHA256 fingerprint of the certificate is required to grant access to a backend service, which can be configured in the `/etc/helgrind.json` on the helgrind server.

The `client.crt` then has to be sent back to the user, who then creates a PKCS#12 file from the private key and the certificate, which can then imported in the browser (Firefox) or system keychain (Chrome).

```sh
openssl pkcs12 -export -clcerts -in client.crt -inkey client.key -out client.p12
```

### Browser Import
Firefox: Preferences > Advanced > Certificates > View Certificates > Your Certificates

Chrome: Import in the system keychain instead, which is used by Chrome.


## Access Revocation
Access can easily be managed in `/etc/helgrind.json`. Either the user can be removed entirely or the specific user or user device can be set to `Enabled = false`.

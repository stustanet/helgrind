# helgrindctl

Support for common helgrind actions.
Althought helgrind itself is configured using a config file and openssl, it would be nice to have all of that abstracted that it will just work.

# Workflow

To generate a new client certificate for helgrind, some steps need to be taken by both sides of the authentication:

1. *[Helgrind]* Generate a config for the user ([#config])
2. *[User]* Generate the private key and the CSR (following the guidelines in the config). Send the CSR to helgrind.
3. *[Helgrind]* Apply the new csr and generate the cert. (#apply)
4. *[User]* Install the generated cert.

# Actions

## help

List all available actions

## config

Generate a config for a user.

```
helgrindctl -action config -service nuclearreactor.helgrind.example.com -alias jotweh -email nobody@stusta.de -name "Johannes Walcher" -out /tmp/csr.config
```

Whereby the following settings have to be made:

* `-service` has to correspond to a section within the configfile.
* `-alias` the shortname of the user.
* `-email` the email to use - only relevant for the certificate and future extensions sending out the config directly
* `-name` the full given name.
* `-out` (optional) the path where to generate the config. If ommitted, stdout will be used
* `-cfg` (optional) the path to `helgrind.json`

Example config (for the command above):

```
prompt = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
countryName = DE
stateOrProvinceName = München
localityName = StuStaNet e.V.
organizationName = nuclearreactor.helgrind.example.com
organizationalUnitName = Johannes Walcher
commonName = jotweh
emailAddress = jw@stusta.de
## 1. Generate a key
# openssl genrsa -out client.key 2048
## 2. Take this client.conf and generate a Signing request
# openssl req -new -config client.conf -key client.key -out client.csr
## 3. Send the client.csr to your administrator (telling him to helgrindctl --action sign --csr client.csr --out client.cert)
## 4. the file client.key will NEVER EVER leave your device.
## 5. Receive your certificate client.cert
## 6. Install the cert and private key in your firefox: search for "certificate" -> view certificates -> Your Certificates -> [Import]
```

## apply

Apply the things the user has filled out for you.

```
helgrindctl -action apply -csr client.csr -out client.cert
```

The operator has to enter the name of the clients device.

Options:

* `-csr` path to the certificate signing request
* `-out` where to generate the certificate
* `-cfg` (optional) the path to `helgrind.json`

## list

List all services.

```
helgrindctl -action list
```

Options:

* `-service` (optional) limit to only this service
* `-cfg` (optional) the path to `helgrind.json`

## revoke

Revoke access for the user or device by disabling (not removing) his key from the config.

```
helgrindctl -action revoke -service nuclearreactor.helgrind.example.com -alias jotweh -device laptop
```

Options:

* `-service` the service to revoke access to
* `-alias` the user to modify
* `-device` (optional) the device to modify. If omitted, the whole user will be deactivated

## reenable

If the access has been revoked using the revoke command, allow the key (and user) to authenticate again

```
helgrindctl -action reenable -service nuclearreactor.helgrind.example.com -alias jotweh -device laptop
```

Options:

* `-service` the service to grant access to
* `-alias` the user to modify
* `-device` (optional) the device to modify. If omitted, the whole user will be deactivated

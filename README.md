# XBox Authentication

## Install (OSX)
```sh
brew install keystore-explorer
```

## Keystore steps

### Create a keystore for RSA Keys (SSL/TLS connection)
```sh
keytool -importkeystore -srckeystore test.pfx -srcstoretype pkcs12 -destkeystore ssl-keystore.jks -deststoretype jks
```
List keys inside keystore
```sh
keytool -list -v -keystore ssl-keystore.jks
```

Convert .pfx to .pem format
```sh
openssl pkcs12 -in test.pfx -clcerts -nokeys -out test.pem
```
Import RSA x509 keys cert in keystore
```sh
keytool -importcert -keystore ssl-keystore.jks -file test.pem -alias ssl-tls-rsa
```

### Create ECDSA keys

Create private key
```sh
openssl ecparam -name prime256v1 -genkey -noout -out ec_private_key.pem
```

Create a new keystore just for ECKeyPair
```sh
keytool -genkeypair -keystore ec-keystore.jks -keyalg EC -keysize 256 -validity 365 -alias ec-key-pair
```

List keys inside keystore
```sh
keytool -list -v -keystore ec-keystore.jks
```

List pkcs12 keys inside keystore
```sh
keytool -list -keystore keystore.p12 -storetype PKCS12
```







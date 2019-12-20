# gencertchain

A command-line tool for generating Certificate-Chain cbor file.

# Usage

This command generates an Certificate-Chain cbor file.

```bash
$ gencertchain -certificate ./prime256v1.pem > certchain.cbor
```
# Options

- `-help`:                 Show help message.
- `-ocsp` _string_:        Specify a DER-encoded OCSP response file. If omitted, it is automatically fetched from CA.
- `-out` _string_:         Cert chain aoutput file. If value is '-', the output will be written to stdout. If omitted, output will be written 'cert.cbor'.
- `-pem` _string_:         The certificate PEM file for the Certificate Chain.
- `-sctDir` _string_:      A path to the directory which contains *.sct files contains SCT information embedded into the head of Certificate-Chain.

# gencertchain - A command-line tool for generating Certificate-Chain CBOR file

## SYNOPSIS

This command generates an Certificate-Chain CBOR file.

```ShellSession
$ gencertchain -certificate ./prime256v1.pem > certchain.cbor
```

## OPTIONS

`-help`:                 Show help message.

`-ocsp` _string_:        Specify a DER-encoded OCSP response file. If omitted, it is automatically fetched from ther certificate's OCSP responder.

`-out` _string_:         Certificate-Chain output file. If value is '-', the output will be written to stdout. If omitted, output will be written 'cert.cbor'.

`-pem` _string_:         The certificate PEM file for the Certificate-Chain.

`-sctDir` _string_:      A path to the directory which contains \*.sct files for SCT information embedded into the head of Certificate-Chain.

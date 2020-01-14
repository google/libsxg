# gensxg - Generate Signed HTTP Exchange (SXG)

## SYNOPSIS

```ShellSession
$ gensxg -url https://example.com \
         -certUrl https://example.com/cert.cbor \
         -validityUrl https://example.com/validity.msg \
         -certificate ./prime256v1.pem \
         -privateKey ./prime256v1.key \
         -content ./myFile.html \
    > myFile.html.sxg
```

This command generates an SXG file for example.com.

Calculate integrity hash value of some file.

```ShellSession
$ gensxg -integrity \
         -content ./logo.png
         -contentType image/png
    > logo-integrity
```

SXG with subresource integrity.

```ShellSession
$ gensxg -url https://example.com \
         -certUrl https://example.com/cert.cbor \
         -validityUrl https://example.com/validity.msg \
         -certificate ./prime256v1.pem \
         -privateKey ./prime256v1.key \
         -header "link: <https://example.com/logo.png>;rel=\"allowed-alt-sxg\";header-integrity=\"`gensxg -integrity -content ./logo.png -contentType image/png`\"" \
         -header "link: <https://example.com/logo.png>;rel=\"preload\";as=\"image\"" \
         -content ./myFile.html
    > myFile.html.sxg
```

## DESCRIPTION

A command-line tool for generating SXG (Signed HTTP Exchanges).

## OPTIONS

`-help`:                 Show help message.

`-integrity`:            Output integrity hash value only instead of the SXG. Set \<integrity hash only mode\>.

`-content` _string_:     Source file to be used as SXG payload (default `./index.html`).

`-contentType` _string_: Mime type of Source file (default `text/html`).

`-header` _string_:      HTTP response header. You can use this option multiple times.
                           Content-Type should be specified by `-contentType` option above (optional).

`-miRecordSize` _int_:   The record size of Merkle Integrity Content Encoding. (default `4096`)

The options below are not applicable to \<integrity hash only mode\>.

`-url` _string_:         The URI of the resource represented in the SXG file. (required)

`-certUrl` _string_:     The URI of certificate CBOR file published. (required)

`-validityUrl` _string_: The URI of validity information provided. (required)

`-certificate` _string_: The certificate PEM file for the SXG. (mutually exclusive with `-publicKey`)

`-publicKey` _string_:   The Ed25519 PEM file for the SXG. (mutually exclusive with `-certificate`)

`-privateKey` _string_:  The private key PEM file for the SXG. (required)

`-date` _string_:        The datetime for the SXG in RFC3339 format (2006-01-02T15:04:05Z). Use the current time by default.

`-expire` _string_:      The expiration time of the SXG in RFC3339 format (2006-01-02T15:04:05Z). (default \<date\> +7 days)

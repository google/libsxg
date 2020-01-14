# sxg\_signer\_list\_t

SXG supports multiple signers, so generating one SXG file requires a set of
signers. This struct represents a set of signers.
By using multiple signers, you can generate signatures with different parameters.
Using multiple signatures gives you the flexibility of expiration or ways to obtain certificates.

If you want to use `sxg_signer_list_t` API, add

```c
#include <libsxg/sxg_signer_list.h>
```

But in most cases, we recommend to include master header of this project like

```c
#include <libsxg.h>
```

## Fields

### sxg\_signer\_list\_t

Vector of `sxg_signer_t`, you can read all fields, but you should modify them
via dedicated APIs except contents of `sxg_signer_t`.

#### sxg\_signer\_t\* signers

signer_list
Head pointer of signers vector.
Initially `NULL`.

#### size\_t size

Length of `signers` vector.
Initially 0.
Every `sxg_add_*` function will increment this field

#### size\_t capacity

Allocated memory field size of `signers` vector.
Initially 0.
Should be changed only when memory allocation happens.

### sxg\_signer\_t

Represents one signer.
You should change `date` and `expires` members to your own need.
There are undocumented fields (`type`, `private_key` and `public_key`),
which are not intended to be accessed directly by library users.

#### char\* name

Name of the signer. Will be embedded into SXG file.
Always null terminated.

#### time\_t date

Unix time of SXG start time.

#### time\_t expires

Unix time of SXG expiration time.

#### char\* validity\_url

Validity URL embedded into SXG file.
Always null terminated.

## Functions

### sxg\_signer\_list\_t sxg\_empty\_signer\_list()

Creates empty signer list. Never fails.

#### Arguments

Nothing.

#### Returns

Empty `sxg_signer_list_t` structure with zero size and zero capacity.

#### Example

```c
sxg_signer_list_t signers = sxg_empty_signer_list();
```

### void sxg\_signer\_list\_release(sxg\_signer\_list\_t\* target)

Releases memory of the signer list specified as `target`.
Key and cert object's reference count will be decremented.
Never fails.

#### Arguments

- `target`: Target signer list to release memory.

#### Returns

Nothing.

#### Example

```c
sxg_signer_list_t signers = sxg_empty_signer_list();
/* You can call release function even if signer list is empty. */
sxg_signer_list_release(&signers);
```

### bool sxg\_add\_ecdsa\_signer(const char\* name, uint64\_t date, uint64\_t expires, const char\* validity\_url, EVP\_PKEY\* private\_key, X509\* public\_key, const char\* certificate\_url, sxg\_signer\_list\_t\* target)

Appends new ecdsa signer to signer list.
Copies the string parameters and increments the reference count of `private_key` and `public_key`.

#### Arguments

- `name` : Name of the new signer. Must be null terminated. Will be deep copied.
- `date` : Unix time of SXG start time.
- `expires` : Unix time of SXG expiration time.
- `validity_url` : Validity URL to be embedded into SXG. Must be null terminated. Will be deep copied.
- `private_key` : ECDSA private key to be used for generating signature. Reference count will be incremented.
- `public_key` : X509 certificate corresponding to the `private_key`. Reference count will be incremented.
- `certificate_url` : URL for distributing CBOR file of the `public_key`. Will be deep copied.
- `target` : Signer list to be modified.

#### Returns

Returns true on success.
On fail, `target` will not be changed.

#### Example

```c
/* Load private key */
FILE* const keyfile = fopen("/path/to/private_key.pem", "r");
assert(keyfile != NULL);
EVP_PKEY* private_key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
fclose(keyfile);
assert(private_key != NULL);

/* Load certificate */
FILE* certfile = fopen("/path/to/certificate.pem", "r");
assert(certfile != NULL);
char passwd[] = "";
X509* cert = PEM_read_X509(certfile, 0, 0, passwd);
fclose(certfile);
assert(cert != NULL);

sxg_signer_list_t signers = sxg_empty_signer_list();
const time_t now = time(NULL);
bool success = sxg_add_ecdsa_signer(
      "ecdsa256signer", now, now + 60 * 60 * 24,
      "https://original.example.com/resource.validity.msg", private_key, cert,
      "https://yourcdn.veryfast.test/cert.cbor", &signers));

assert(success);
assert(signers.size == 1u);

EVP_PKEY_free(private_key);
X509_free(cert);
sxg_signer_list_release(&signers);
```

### bool sxg\_add\_ed25519\_signer(const char\* name, uint64\_t date, uint64\_t expires, const char\* validity\_url, EVP\_PKEY\* private\_key, EVP\_PKEY\* public\_key, sxg\_signer\_list\_t\* target)

Appends new Ed25519 signer to signer list. Copies the string parameters and
increments the reference counts of `private_key` and `public_key`.
Note: Ed25519 signer does not use certificates, so Ed25519 signer does not
require `certificate_url`.

#### Arguments

- `name` : Name of the new signer. Must be null terminated. Will be deep copied.
- `date` : Unix time of SXG start time.
- `expires` : Unix time of SXG expiration time.
- `validity_url` : Validity URL to be embedded into SXG. Must be null terminated. Will be deep copied.
- `private_key` : Ed25519 private key to be used for generating signature. Reference count will be incremented.
- `public_key` : X509 certificate corresponding to the `private_key`. Reference count will be incremented.
- `target` : signer list to be modified.

#### Returns

Returns true on success.
On fail, `target` will not be changed.

#### Example

```c
/* Load private key */
FILE* const keyfile = fopen("/path/to/private_key.pem", "r");
assert(keyfile != NULL);
EVP_PKEY* private_key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
fclose(keyfile);
assert(private_key != NULL);

/* Load public key */
FILE* publickey_file = fopen("/path/to/public_key.pem", "r");
assert(publickeyA_file != NULL);
EVP_PKEY* public_key = PEM_read_pubkey(publickey_file, 0, 0, &passwd);
fclose(publickey_file);
assert(public_key != NULL);

sxg_signer_list_t signers = sxg_empty_signer_list();
const time_t now = time(NULL);
bool success = sxg_add_ed25519_signer(
      "ed25519signer", now, now + 60 * 60 * 24,
      "https://original.example.com/resource.validity.msg", private_key,
      public_key, &signers));

assert(success);
assert(signers.size == 1u);

EVP_PKEY_free(private_key);
EVP_PKEY_free(public_key);
sxg_signer_list_release(&signers);
```

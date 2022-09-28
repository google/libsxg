// Binary to help us debug the signature verification.
// It works on almost all supported public key types and message digests.
//
// Currently the signature has to be in binary format. If it is in base64
// or other encoding, you can convert it into binary format save it in file and
// run this binary to validate the signature.
//
// TODO(amaltas): Support for base64 encoded signatures.
//
// Compilation:
// $ clang verifysignature.c -std=c2x -lssl -lcrypto -o verifysignature
//
// Usage:
// $ ./verifysignature <digestalgorithm> <publickey> <signature file> <data
// file>
//
// Example:
// $ ./verifysignature sha256 ecpubkey.pem signature.bin data.txt
//
// Output is one of:
// Signature verified OK.
// Signature not verified. Not OK.

#include <fcntl.h>   // for O_RDONLY flag.
#include <stdio.h>   // for open(), printf().
#include <unistd.h>  // for close()

#include "openssl/bio.h"
#include "openssl/ec.h"
#include "openssl/engine.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"

int main(int argc, char** argv) {
  if (argc < 5) {
    printf(
        "Usage: verifysignature sha256 publickey.pem signature.bin "
        "message.txt\n");
    return 0;
  }

  int fd;
  BIO* in = BIO_new(BIO_s_file());
  BIO* bmd = BIO_new(BIO_f_md());
  BIO* inp = BIO_push(bmd, in);

  // Initialize the digest type.
  EVP_MD* md = NULL;
  md = (EVP_MD*)EVP_get_digestbyname(argv[1]);
  if (!md) {
    printf(
        "Unable to open md object for digest type: %s\n."
        "Accepted values: sha1, sha256, sha348, sha512.\n",
        argv[1]);
  }

  // Read the public key.
  fd = open(argv[2], O_RDONLY);
  BIO* bo = BIO_new_fd(fd, 0);
  EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(bo, NULL, NULL, NULL);
  if (!pubkey) {
    printf("Loading public key: %s failed.\n", argv[2]);
  }

  EVP_MD_CTX* mctx;
  if (BIO_get_md_ctx(bmd, &mctx) <= 0) {
    printf("Error initializing message digest context.\n");
    goto err;
  }

  int res;
  res = EVP_DigestVerifyInit(mctx, 0, md, 0, pubkey);
  if (res == 0) {
    printf("Error initializing digest verifier.\n");
    goto err;
  }

  // Read the signature.
  unsigned char* buf = malloc(256);
  unsigned char* sigbuf = NULL;
  BIO* sigbio = BIO_new_file(argv[3], "rb");
  int siglen = EVP_PKEY_get_size(pubkey);
  sigbuf = malloc(siglen);
  siglen = BIO_read(sigbio, sigbuf, siglen);
  BIO_free(sigbio);

  // Read the data file.
  if (BIO_read_filename(in, argv[4]) <= 0) {
    printf("Error reading data file: %s\n", argv[4]);
    goto err;
  }

  (void)BIO_reset(bmd);

  // Verify the signature.
  EVP_MD_CTX* ctx;
  BIO_get_md_ctx(inp, &ctx);

  while (BIO_pending(inp) || !BIO_eof(inp)) {
    if (BIO_read(inp, (char*)buf, 256) == 0) break;
  }

  if (EVP_DigestVerifyFinal(ctx, sigbuf, (unsigned int)siglen) == 1) {
    printf("Signature verified. OK\n");
  } else {
    printf("Signature not verified. Not OK\n");
  }

err:
  close(fd);
  return 0;
}

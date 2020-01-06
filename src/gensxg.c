#define _XOPEN_SOURCE
#include <errno.h>
#include <getopt.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libsxg.h"

static const struct option kOptions[] = {
    {"help", no_argument, NULL, 'h'},
    {"integrity", no_argument, NULL, 'i'},
    {"content", required_argument, NULL, 'c'},
    {"contentType", required_argument, NULL, 't'},
    {"header", required_argument, NULL, 'H'},
    {"output", required_argument, NULL, 'o'},
    {"miRecordSize", required_argument, NULL, 'm'},
    {"uri", required_argument, NULL, 'u'},
    {"certUrl", required_argument, NULL, 'r'},
    {"validityUrl", required_argument, NULL, 'v'},
    {"certificate", required_argument, NULL, 'e'},
    {"publicKey", required_argument, NULL, 'p'},
    {"privateKey", required_argument, NULL, 'k'},
    {"date", required_argument, NULL, 'd'},
    {"expire", required_argument, NULL, 'x'},
    {0, 0, 0, 0},
};

static const char kHelpMessage[] =
    "USAGE: gensxg [OPTIONS]\n"
    "\n"
    "OPTIONS:\n"
    "-help\n"
    "  Show this message.\n"
    "-integrity\n"
    "  Output integrity hash value only instead of the SXG. "
    "Set <integrity hash only mode>.\n"
    "-content string\n"
    "  Source to be used as payload of the SXG (default [./index.html]).\n"
    "-contentType string\n"
    "  Mime type of source (default [text/html]).\n"
    "-header string\n"
    "  Custom inner header of the SXG.\n"
    "  You can use this option multiple times.\n"
    "  Content-Type should be specified by -contentType option above. "
    "(optional)\n"
    "-miRecordSize int\n"
    "  The record size of Merkle Integrity Content Encoding. "
    "(default [4096])\n"
    "\n"
    "The options below are not applicable to <integrity hash only mode>.\n"
    "\n"
    "-o string\n"
    "  Signed exchange output file. If value is '-', sxg is written to stdout. "
    " (default \"out.sxg\")"
    "-uri string\n"
    "  The URI of the resource represented in the SXG file. (required)\n"
    "-certUrl string\n"
    "  The URI of certificate cbor file published. (required)\n"
    "-validityUrl string\n"
    "  The URI of validity information provided. (required)\n"
    "-certificate string\n"
    "  The certificate PEM file for the SXG. (mutually exclusive with "
    "-publicKey)\n"
    "-publicKey string\n"
    "  The Ed25519 PEM file for the SXG. (mutually exclusive with "
    "-certificate)\n"
    "-private_key string\n"
    "  The private key PEM file for the SXG. (required)\n"
    "-date string\n"
    "  The datetime for the SXG in RFC3339 format (2006-01-02T15:04:05Z)."
    " Use the current time by default.\n"
    "-expire string\n"
    "  The expire time of the SXG in RFC3339 format (2006-01-02T15:04:05Z)."
    " (default <date> +7 days)\n";

typedef struct {
  bool help;
  bool integrity_mode;
  const char* content;
  const char* content_type;
  sxg_header_t header;
  uint64_t mi_record_size;
  const char* output;
  const char* url;
  const char* cert_url;
  const char* validity_url;
  const char* certificate;
  const char* public_key;
  const char* private_key;
  time_t date;
  int64_t duration; /* Seconds from date. */
} Options;

FILE* safe_fopen(const char* filepath, const char* mode) {
  FILE* const file = fopen(filepath, mode);
  if (file == NULL) {
    fprintf(stderr, "fopen %s: %s\n", filepath, strerror(errno));
    exit(EXIT_FAILURE);
  }
  return file;
}

void safe_fwrite(const uint8_t* data, uint64_t size, FILE* out) {
  const size_t written = fwrite(data, sizeof(uint8_t), size, out);
  if (written != size) {
    perror("fwrite");
    exit(EXIT_FAILURE);
  }
}

static EVP_PKEY* load_private_key(const char* filepath) {
  FILE* const keyfile = safe_fopen(filepath, "r");
  EVP_PKEY* const private_key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
  if (private_key == NULL) {
    fprintf(stderr, "Failed to read private key: %s\n", filepath);
    exit(EXIT_FAILURE);
  }
  fclose(keyfile);
  return private_key;
}

static X509* load_x509_cert(const char* filepath) {
  FILE* const certfile = safe_fopen(filepath, "r");
  X509* const cert = PEM_read_X509(certfile, NULL, NULL, NULL);
  if (cert == NULL) {
    fprintf(stderr, "Failed to read certificate: %s\n", filepath);
    exit(EXIT_FAILURE);
  }
  fclose(certfile);
  return cert;
}

static EVP_PKEY* load_ed25519_pubkey(const char* filepath) {
  FILE* const keyfile = safe_fopen(filepath, "r");
  EVP_PKEY* const public_key = PEM_read_PUBKEY(keyfile, NULL, NULL, NULL);
  if (public_key == NULL) {
    fprintf(stderr, "Failed to read public key: %s\n", filepath);
    exit(EXIT_FAILURE);
  }
  fclose(keyfile);
  return public_key;
}

static time_t parse_time(const char* datestring) {
  struct tm date;
  char* const finished = strptime(datestring, "%Y-%m-%dT%H:%M:%SZ", &date);
  if (finished == NULL) {
    fprintf(stderr, "Failed to parse date: %s\n", datestring);
    exit(EXIT_FAILURE);
  } else if (*finished != '\0') {
    fprintf(stderr, "Failed to parse at: %s\n", finished);
    exit(EXIT_FAILURE);
  }
  return mktime(&date);
}

static Options init_default_options() {
  Options result;
  memset(&result, 0, sizeof(result));
  result.content = "index.html";
  result.content_type = "text/html";
  result.header = sxg_empty_header();
  result.date = time(NULL);
  result.duration = 60 * 60 * 24 * 7; /* = 7 Days in seconds. */
  result.mi_record_size = 4096;
  result.output = "out.sxg";
  return result;
}

static void header_append_string(const char* data, sxg_header_t* header) {
  const size_t delimiter = strcspn(data, ": ");
  if (delimiter == strlen(data)) {
    fprintf(stderr, "Colon not found in header: %s\n", data);
    exit(EXIT_FAILURE);
  }
  const size_t value_start = strspn(data + delimiter + 1, " ") + delimiter + 1;
  if (value_start == strlen(data)) {
    fprintf(stderr, "Value not found in header: %s\n", data);
    exit(EXIT_FAILURE);
  }
  const size_t value_finish = strcspn(data + value_start, " ");
  char* const key = OPENSSL_strndup(data, delimiter);
  char* const value = OPENSSL_strndup(data + value_start, value_finish);

  sxg_header_append_string(key, value, header);

  OPENSSL_free(key);
  OPENSSL_free(value);
}

static Options parse_options(int argc, char* const argv[]) {
  Options result = init_default_options();
  int opt;
  int longindex;
  time_t expires = 0;
  bool is_expire_specified = false;
  while ((opt = getopt_long_only(argc, argv, "h:i:c:t:H:m:u:r:v:e:p:k:d:x",
                                 kOptions, &longindex)) != -1) {
    switch (opt) {
      case 'h':
        result.help = true;
        return result;
      case 'i':
        result.integrity_mode = true;
        break;
      case 'c':
        result.content = optarg;
        break;
      case 't':
        result.content_type = optarg;
        break;
      case 'H':
        header_append_string(optarg, &result.header);
        break;
      case 'm':
        result.mi_record_size = strtoull(optarg, NULL, 0);
        break;
      case 'o':
        result.output = optarg;
        break;
      case 'u':
        result.url = optarg;
        break;
      case 'r':
        result.cert_url = optarg;
        break;
      case 'v':
        result.validity_url = optarg;
        break;
      case 'e':
        result.certificate = optarg;
        break;
      case 'p':
        result.public_key = optarg;
        break;
      case 'k':
        result.private_key = optarg;
        break;
      case 'd':
        result.date = parse_time(optarg);
        break;
      case 'x':
        is_expire_specified = true;
        expires = parse_time(optarg);
        break;
      default:
        exit(EXIT_FAILURE);
    }
  }

  if (is_expire_specified) {
    result.duration = expires - result.date;
  }
  return result;
}

static bool is_empty(const char* str) { return str == NULL || *str == '\0'; }

static bool validate_common_options(const Options* opt) {
  bool valid = true;
  if (opt->content == NULL) {
    fputs("error: -content must be specified.\n", stderr);
    valid = false;
  } else if (access(opt->content, F_OK)) {
    fprintf(stderr, "error: Cannot access content: %s\n", opt->content);
    valid = false;
  }
  if (opt->mi_record_size == 0) {
    fputs("error: -miRecordSize must be greater than 0.\n", stderr);
    valid = false;
  }
  return valid;
}

static bool validate_generator_options(const Options* opt) {
  bool valid = true;
  if (is_empty(opt->url)) {
    fputs("error: -url must not be empty.\n", stderr);
    valid = false;
  }
  if (is_empty(opt->cert_url)) {
    fputs("error: -certUrl must not be empty.\n", stderr);
    valid = false;
  }
  if (is_empty(opt->validity_url)) {
    fputs("error: -validityUrl must not be empty.\n", stderr);
    valid = false;
  }
  if (is_empty(opt->certificate)) {
    if (is_empty(opt->public_key)) {
      fprintf(stderr, "error: -certificate or -publicKey must be specified.\n");
      valid = false;
    } else if (access(opt->public_key, F_OK)) {
      fprintf(stderr, "error: Cannot access publicKey: %s\n", opt->public_key);
      valid = false;
    }
  } else {
    if (opt->public_key != NULL) {
      fprintf(stderr,
              "error: -certificate and -publicKey cannot be "
              "specified at the same time.\n");
      valid = false;
    } else if (access(opt->certificate, F_OK)) {
      fprintf(stderr, "error: Cannot access certificate: %s\n",
              opt->certificate);
      valid = false;
    }
  }
  if (is_empty(opt->private_key)) {
    fputs("error: -privateKey must be specified.\n", stderr);
    valid = false;
  } else if (access(opt->private_key, F_OK)) {
    fprintf(stderr, "error: Cannot access privateKey: %s\n", opt->private_key);
    valid = false;
  }
  if (opt->duration <= 0) {
    fputs("error: SXG lifespan must be a positive number.\n", stderr);
    valid = false;
  }
  if (opt->duration > 60 * 60 * 24 * 7) {
    fputs("error: SXG lifespan must not exceed 7 days.\n", stderr);
    valid = false;
  }
  return valid;
}

static bool validate(const Options* opt) {
  bool valid = validate_common_options(opt);
  if (!opt->integrity_mode) {
    valid = valid & validate_generator_options(opt);
  }
  return valid;
}

static void load_signer(const Options* opt, sxg_signer_list_t* signers) {
  uint64_t date = (uint64_t)opt->date;
  uint64_t expire = (uint64_t)opt->date + (uint64_t)opt->duration;

  if (opt->certificate != NULL) {
    X509* cert = load_x509_cert(opt->certificate);
    EVP_PKEY* pri_key = load_private_key(opt->private_key);
    if (!sxg_add_ecdsa_signer(opt->url, date, expire, opt->validity_url,
                              pri_key, cert, opt->cert_url, signers)) {
      fprintf(stderr, "Failed to generate SXG signer with certificate\n");
      exit(EXIT_FAILURE);
    }
    X509_free(cert);
    EVP_PKEY_free(pri_key);
  } else {
    EVP_PKEY* pub_key = load_ed25519_pubkey(opt->public_key);
    EVP_PKEY* pri_key = load_private_key(opt->private_key);
    if (!sxg_add_ed25519_signer(opt->url, date, expire, opt->validity_url,
                                pri_key, pub_key, signers)) {
      fprintf(stderr, "Failed to generate SXG signer with Ed25519 key\n");
      exit(EXIT_FAILURE);
    }
    EVP_PKEY_free(pub_key);
    EVP_PKEY_free(pri_key);
  }
}

static void load_content(const char* filepath, sxg_buffer_t* buf) {
  FILE* const file = safe_fopen(filepath, "rb");
  if (fseek(file, 0, SEEK_END) != 0) {
    fprintf(stderr, "fseek %s: %s\n", filepath, strerror(errno));
    exit(EXIT_FAILURE);
  }
  const long filesize = ftell(file);
  if (filesize == -1) {
    fprintf(stderr, "ftell %s: %s\n", filepath, strerror(errno));
    exit(EXIT_FAILURE);
  }
  rewind(file);
  sxg_buffer_resize(filesize, buf);
  int64_t nread = fread(buf->data, sizeof(uint8_t), filesize, file);
  if (nread != filesize) {
    fprintf(stderr, "fread %s: %s\n", filepath, strerror(errno));
    exit(EXIT_FAILURE);
  }
  fclose(file);
}

static void print_help() { fputs(kHelpMessage, stderr); }

static void dump_options(const Options* opt) {
  fprintf(stderr, "Input arguments:\n");
  fprintf(stderr, " integrity: %s\n", opt->integrity_mode ? "true" : "false");
  fprintf(stderr, " content: %s\n", opt->content);
  fprintf(stderr, " contentType: %s\n", opt->content_type);
  fprintf(stderr, " miRecordSize: %ld\n", opt->mi_record_size);
  for (size_t i = 0; i < opt->header.size; ++i) {
    if (i == 0) {
      fprintf(stderr, " header: ");
    } else {
      fprintf(stderr, "         ");
    }
    fprintf(stderr, "%s: ", opt->header.entries[i].key);
    sxg_buffer_t value = sxg_empty_buffer();
    sxg_buffer_copy(&opt->header.entries[i].value, &value);
    sxg_write_byte('\0', &value);
    fprintf(stderr, "%s\n", value.data);
  }
  fprintf(stderr, " url: %s\n", opt->url);
  fprintf(stderr, " certUrl: %s\n", opt->cert_url);
  fprintf(stderr, " validityUrl: %s\n", opt->validity_url);
  fprintf(stderr, " certificate: %s\n", opt->certificate);
  fprintf(stderr, " publicKey: %s\n", opt->public_key);
  fprintf(stderr, " privateKey: %s\n", opt->private_key);
  fprintf(stderr, " date: %ld\n", opt->date);
  fprintf(stderr, " expire: %ld\n", opt->date + opt->duration);
}

sxg_encoded_response_t get_encoded_response(const Options* opt) {
  sxg_raw_response_t raw = sxg_empty_raw_response();
  sxg_header_copy(&opt->header, &raw.header);
  load_content(opt->content, &raw.payload);
  if (!sxg_header_append_string("content-type", opt->content_type,
                                &raw.header)) {
    fputs("Failed to append content-type header.\n", stderr);
    exit(EXIT_FAILURE);
  }
  sxg_encoded_response_t encoded = sxg_empty_encoded_response();
  if (!sxg_encode_response(opt->mi_record_size, &raw, &encoded)) {
    fputs("Failed to encode content.\n", stderr);
    exit(EXIT_FAILURE);
  }
  sxg_raw_response_release(&raw);
  return encoded;
}

static void print_integrity_hash(const sxg_encoded_response_t* encoded) {
  sxg_buffer_t integrity = sxg_empty_buffer();
  if (!sxg_write_header_integrity(encoded, &integrity)) {
    fputs("Failed to calculate integrity hash.\n", stderr);
    exit(EXIT_FAILURE);
  }
  safe_fwrite(integrity.data, integrity.size, stdout);
}

void write_sxg(const sxg_signer_list_t* signers, const char* url,
               sxg_encoded_response_t* encoded, const char* output) {
  sxg_buffer_t result = sxg_empty_buffer();
  if (!sxg_generate(url, signers, encoded, &result)) {
    fputs("Failed to generate SXG.\n", stderr);
    exit(EXIT_FAILURE);
  }

  FILE* out;
  if (strcmp(output, "-") == 0) {
    // In Linux, stdout is binary mode by default.
    // But we freopen it for portability.
    out = freopen(NULL, "wb", stdout);
    if (out == NULL) {
      perror("reopen stdout");
      exit(EXIT_FAILURE);
    }
  } else {
    out = safe_fopen(output, "wb");
  }

  safe_fwrite(result.data, result.size, out);

  if (out != stdout && fclose(out) != 0) {
    perror("fclose");
    exit(EXIT_FAILURE);
  }

  sxg_buffer_release(&result);
}

int main(int argc, char* const argv[]) {
  Options opt = parse_options(argc, argv);
  if (opt.help) {
    print_help();
    return 0;
  }

  if (!validate(&opt)) {
    dump_options(&opt);
    return 1;
  }

  sxg_encoded_response_t encoded = get_encoded_response(&opt);

  if (opt.integrity_mode) {
    print_integrity_hash(&encoded);
  } else {
    sxg_signer_list_t signers = sxg_empty_signer_list();
    load_signer(&opt, &signers);
    write_sxg(&signers, opt.url, &encoded, opt.output);
    sxg_signer_list_release(&signers);
  }

  sxg_header_release(&opt.header);
  sxg_encoded_response_release(&encoded);
  return 0;
}

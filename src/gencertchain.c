#define _XOPEN_SOURCE
#include <errno.h>
#include <getopt.h>
#include <glob.h>
#include <openssl/crypto.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libsxg.h"
#include "libsxg/internal/sxg_buffer.h"

static const struct option kOptions[] = {
    {"help", no_argument, NULL, 'h'},
    {"ocsp", required_argument, NULL, 'p'},
    {"out", required_argument, NULL, 'o'},
    {"pem", required_argument, NULL, 'c'},
    {"sctDir", required_argument, NULL, 's'},
    {0, 0, 0, 0},
};

static const char kHelpMessage[] =
    "USAGE: gencertchain [OPTIONS]\n"
    "\n"
    "OPTIONS:\n"
    "-help\n"
    "  Show this message.\n"
    "-ocsp string\n"
    "  DER-encoded OCSP response file. If omitted, it fetches from network.\n"
    "-out string\n"
    "  Cert chain output file."
    " If value is '-', the cert chain is written to stdout."
    " (default \"cert.cbor\")\n"
    "-pem string\n"
    "  The certificate PEM file for the cert chain. (required)\n"
    "-sctDir string\n"
    "  Directory containing .sct files.\n";

typedef struct {
  bool help;
  const char* ocsp;
  const char* output;
  const char* pem;
  const char* sct;
} Options;

static Options init_default_options() {
  Options result;
  memset(&result, 0, sizeof(result));
  result.output = "cert.cbor";
  return result;
}

static Options parse_options(int argc, char* const argv[]) {
  Options result = init_default_options();
  int opt;
  int longindex;
  while ((opt = getopt_long_only(argc, argv, "h:p:o:c:s", kOptions,
                                 &longindex)) != -1) {
    switch (opt) {
      case 'h':
        result.help = true;
        return result;
      case 'p':
        result.ocsp = optarg;
        break;
      case 'o':
        result.output = optarg;
        break;
      case 'c':
        result.pem = optarg;
        break;
      case 's':
        result.sct = optarg;
        break;
      default:
        exit(EXIT_FAILURE);
    }
  }

  return result;
}

static bool is_empty(const char* str) { return str == NULL || *str == '\0'; }

static bool validate(const Options* opt) {
  bool valid = true;
  if (is_empty(opt->pem)) {
    fprintf(stderr, "error: -pem must be specified.\n");
    valid = false;
  }
  return valid;
}

static void print_help() { fputs(kHelpMessage, stderr); }

static void load_file(const char* filepath, sxg_buffer_t* dst) {
  FILE* file = fopen(filepath, "rb");
  if (file == NULL) {
    fprintf(stderr, "fopen %s: %s\n", filepath, strerror(errno));
    exit(EXIT_FAILURE);
  }
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
  sxg_buffer_resize(filesize, dst);
  int read_size = fread(dst->data, sizeof(uint8_t), filesize, file);
  if (read_size != filesize) {
    fprintf(stderr, "fread %s: %s\n", filepath, strerror(errno));
    exit(EXIT_FAILURE);
  }
  fclose(file);
}

static void parse_ocsp_file(const char* ocsp_path, OCSP_RESPONSE** dst) {
  sxg_buffer_t ocsp_content = sxg_empty_buffer();
  load_file(ocsp_path, &ocsp_content);
  const uint8_t* ocsp_ptr = ocsp_content.data;
  d2i_OCSP_RESPONSE(dst, &ocsp_ptr, ocsp_content.size);
  if (dst == NULL) {
    fprintf(stderr, "Failed to parse OCSP response: %s\n", ocsp_path);
    exit(EXIT_FAILURE);
  }
}

static void make_glob_pattern(const char* base_path, sxg_buffer_t* dst) {
  sxg_buffer_release(dst);
  if (!sxg_write_string(base_path, dst) || !sxg_write_string("/*.sct", dst) ||
      !sxg_write_byte('\0', dst)) {
    fprintf(stderr, "Failed to make glob pattern.\n");
    exit(EXIT_FAILURE);
  }
}

static void parse_sct_files(const char* sct_path, sxg_buffer_t* sct_list) {
  glob_t glob_result;

  // Load all sct files at sct_path into sxg_buffer_t array.
  sxg_buffer_t glob_pattern = sxg_empty_buffer();
  make_glob_pattern(sct_path, &glob_pattern);
  if (glob((const char*)glob_pattern.data, GLOB_ERR | GLOB_NOESCAPE, NULL,
           &glob_result) != 0) {
    globfree(&glob_result);
    fprintf(stderr, "Failed to glob at: %s\n", sct_path);
    exit(EXIT_FAILURE);
  }
  sxg_buffer_release(&glob_pattern);
  const size_t files = glob_result.gl_pathc;
  sxg_buffer_t* buffers =
      OPENSSL_malloc(sizeof(sxg_buffer_t) * glob_result.gl_pathc);
  for (size_t i = 0; i < files; ++i) {
    buffers[i] = sxg_empty_buffer();
    load_file(glob_result.gl_pathv[i], &buffers[i]);
    if (buffers[i].size > USHRT_MAX) {
      fprintf(stderr, "Too long sct file: %s\n", glob_result.gl_pathv[i]);
      exit(EXIT_FAILURE);
    }
  }

  // Accumulate total size.
  size_t total_size = 0;
  for (size_t i = 0; i < files; ++i) {
    total_size += buffers[i].size;
    if (total_size > USHRT_MAX) {
      fprintf(stderr, "Too long total length of *.sct files: %s\n", sct_path);
      exit(EXIT_FAILURE);
    }
  }
  total_size += files * 2;  // 16-bits length prefix on each sct.

  // Parse sct payloads.
  bool success = sxg_write_int(total_size, 2, sct_list);
  for (size_t i = 0; i < files && success; ++i) {
    success = sxg_write_int(buffers[i].size, 2, sct_list) &&
              sxg_write_buffer(&buffers[i], sct_list);
  }

  // Release sct payloads.
  for (size_t i = 0; i < files; ++i) {
    sxg_buffer_release(&buffers[i]);
  }
  OPENSSL_free(buffers);
  globfree(&glob_result);
  if (!success) {
    fprintf(stderr, "Failed to parse sct files: %s\n", sct_path);
    exit(EXIT_FAILURE);
  }
}

static void load_x509_certs(const char* filepath, const char* ocsp_path,
                            const char* sct_path, sxg_cert_chain_t* chain) {
  FILE* const certfile = fopen(filepath, "r");
  if (certfile == NULL) {
    fprintf(stderr, "fopen %s: %s\n", filepath, strerror(errno));
    exit(EXIT_FAILURE);
  }
  X509* cert = PEM_read_X509(certfile, NULL, NULL, NULL);
  X509* issuer = PEM_read_X509(certfile, NULL, NULL, NULL);
  OCSP_RESPONSE* ocsp;

  // Load specified OCSP response.
  if (ocsp_path != NULL) {
    parse_ocsp_file(ocsp_path, &ocsp);
  } else if (!sxg_fetch_ocsp_response(cert, issuer, &ocsp)) {
    fprintf(stderr, "Failed to fetch OCSP response: %s\n", filepath);
    exit(EXIT_FAILURE);
  }

  // Load specified SCT List.
  sxg_buffer_t sct_list = sxg_empty_buffer();
  if (sct_path != NULL) {
    parse_sct_files(sct_path, &sct_list);
    sxg_buffer_dump(&sct_list);
  }

  // Start to load certificate.
  if (!sxg_cert_chain_append_cert(cert, ocsp, &sct_list, chain)) {
    fprintf(stderr, "Failed to append first certificate: %s\n", filepath);
    exit(EXIT_FAILURE);
  }
  cert = issuer;
  const sxg_buffer_t empty_buffer = sxg_empty_buffer();
  while (cert != NULL) {
    if (!sxg_cert_chain_append_cert(cert, NULL, &empty_buffer, chain)) {
      fprintf(stderr, "Failed to append certificate: %s\n", filepath);
      exit(EXIT_FAILURE);
    }
    cert = PEM_read_X509(certfile, NULL, NULL, NULL);
  }
  fclose(certfile);
}

static void dump_options(const Options* opt) {
  fprintf(stderr, "Input arguments:\n");
  fprintf(stderr, " ocsp: %s\n", opt->ocsp);
  fprintf(stderr, " pem: %s\n", opt->pem);
  fprintf(stderr, " out: %s\n", opt->output);
  fprintf(stderr, " sctDir: %s\n", opt->sct);
}

void write_cert_chain(const sxg_cert_chain_t* chain, const char* output) {
  sxg_buffer_t result = sxg_empty_buffer();
  if (!sxg_write_cert_chain_cbor(chain, &result)) {
    fprintf(stderr, "Failed to write cert chain\n");
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
    out = fopen(output, "wb");
    if (out == NULL) {
      perror("open file");
      exit(EXIT_FAILURE);
    }
  }

  const size_t written = fwrite(result.data, sizeof(uint8_t), result.size, out);
  if (written != result.size) {
    perror("fwrite");
    exit(EXIT_FAILURE);
  }

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

  sxg_cert_chain_t chain = sxg_empty_cert_chain();
  load_x509_certs(opt.pem, opt.ocsp, opt.sct, &chain);
  write_cert_chain(&chain, opt.output);

  sxg_cert_chain_release(&chain);
  return 0;
}

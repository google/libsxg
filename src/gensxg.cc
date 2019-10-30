#include <openssl/pem.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <string>

#include "libsxg.h"

struct Options {
 private:
  static EVP_PKEY* LoadPrivateKey(const std::string& filepath) {
    FILE* const keyfile = fopen(filepath.c_str(), "r");
    if (keyfile == nullptr) {
      return nullptr;
    }
    EVP_PKEY* private_key =
        PEM_read_PrivateKey(keyfile, nullptr, nullptr, nullptr);
    fclose(keyfile);
    return private_key;
  }

  static X509* LoadX509Cert(const std::string& filepath) {
    FILE* certfile = fopen(filepath.c_str(), "r");
    if (certfile == nullptr) {
      return nullptr;
    }
    char passwd[] = "";
    X509* cert = PEM_read_X509(certfile, 0, 0, passwd);
    fclose(certfile);
    return cert;
  }

  static EVP_PKEY* LoadEd25519Pubkey(const std::string& filepath) {
    FILE* keyfile = fopen(filepath.c_str(), "r");
    if (!keyfile) {
      return nullptr;
    }
    EVP_PKEY* public_key = PEM_read_PUBKEY(keyfile, nullptr, nullptr, nullptr);
    fclose(keyfile);
    return public_key;
  }

 public:
  Options(int argc, const char** argv)
      : help(false),
        content_type("text/html"),
        date(0),
        expire(0),
        mi_record_size(4096),
        output("out.sxg") {
    if (argc <= 2) {
      help = true;
      return;
    }
    for (int i = 1; i < argc; i += 2) {
      std::string key(argv[i]);
      std::string value(argv[i + 1]);
      if (key == "-help") {
        help = true;
        return;
      } else if (key == "-url") {
        url = value;
      } else if (key == "-certUrl") {
        cert_url = value;
      } else if (key == "-validityUrl") {
        validity_url = value;
      } else if (key == "-certificate") {
        certificate = value;
      } else if (key == "-privateKey") {
        private_key = value;
      } else if (key == "-content") {
        content = value;
      } else if (key == "-contentType") {
        content_type = value;
      } else if (key == "-date") {
        date = std::stoul(value);
      } else if (key == "-expire") {
        expire = std::stoul(value);
      } else if (key == "-miRecordSize") {
        mi_record_size = std::stoul(value);
      } else {
        throw std::runtime_error("Unknown option [" + key + "]");
      }
    }

    // Set default values.
    if (date == 0) {
      time_t now = time(nullptr);
      date = static_cast<size_t>(now);
    }
    if (expire == 0) {
      expire = date + 60 * 60 * 24 * 7;  // 7 days.
    }
    if (mi_record_size == 0) {
      mi_record_size = 4096;
    }
  }

  std::string Validate() const {
    std::string ans = "";
    if (url.empty()) {
      ans += " -url must not be empty.\n";
    }
    if (cert_url.empty()) {
      ans += " -certUrl must not be empty.\n";
    }
    if (validity_url.empty()) {
      ans += " -validityUrl must not be empty.\n";
    }
    if (content.empty()) {
      ans += " -content file must be specified.\n";
    } else {
      if (::access(content.c_str(), F_OK)) {
        ans += " Cannot access content file: " + content + "\n";
      }
    }
    if (certificate.empty()) {
      if (public_key.empty()) {
        ans += " -certificate file or -publicKey file must be specified.\n";
      } else if (::access(public_key.c_str(), F_OK)) {
        ans += " Cannot access public_key file: " + public_key + "\n";
      }
    } else {
      if (!public_key.empty()) {
        ans +=
            " -certificate and -publicKey cannot be specified "
            "at the same time.\n";
      } else if (::access(certificate.c_str(), F_OK)) {
        ans += " Cannot access certificate file: " + certificate + "\n";
      }
    }
    if (private_key.empty()) {
      ans += " -privateKey file must be specified.\n";
    } else {
      if (::access(private_key.c_str(), F_OK)) {
        ans += " Cannot access privateKey file: " + private_key + "\n";
      }
    }
    return ans;
  }

  void LoadSigner(sxg_signer_list_t* signers) const {
    if (!certificate.empty()) {
      X509* cert = LoadX509Cert(certificate);
      EVP_PKEY* pri_key = LoadPrivateKey(private_key);
      if (!sxg_add_ecdsa_signer(url.c_str(), date, expire, validity_url.c_str(),
                                pri_key, cert, cert_url.c_str(), signers)) {
        throw std::runtime_error(
            "Failed to generate SXG signer with certificate");
      }
      X509_free(cert);
      EVP_PKEY_free(pri_key);
    } else {
      EVP_PKEY* pub_key = LoadEd25519Pubkey(public_key);
      EVP_PKEY* pri_key = LoadPrivateKey(private_key);
      if (!sxg_add_ed25519_signer(url.c_str(), date, expire,
                                  validity_url.c_str(), pri_key, pub_key,
                                  signers)) {
        throw std::runtime_error(
            "Failed to generate SXG signer with Ed25519 key");
      }
      EVP_PKEY_free(pub_key);
      EVP_PKEY_free(pri_key);
    }
  }

  void LoadContents(sxg_buffer_t* buf) {
    FILE* file = fopen(content.c_str(), "rb");
    if (file == nullptr) {
      throw std::runtime_error("Failed to load content: " + content);
    }
    fseek(file, 0, SEEK_END);
    size_t filesize = ftell(file);
    rewind(file);
    sxg_buffer_resize(filesize, buf);
    fread(buf->data, sizeof(char), filesize, file);
    fclose(file);
  }

  void Output(const sxg_buffer_t* payload) {
    FILE* file = fopen(output.c_str(), "wb");
    if (file == nullptr) {
      throw std::runtime_error("Failed to open file: " + output);
    }
    fwrite(payload->data, sizeof(char), payload->size, file);
    fclose(file);
  }

  static void Help(std::ostream& o) {
    o << "-help\n"
         "  Show this message.\n"
         "-url string\n"
         "  The URI of the resource represented in the SXG file. (required)\n"
         "-certUrl string\n"
         "  The URI of certificate cbor file published. (required)\n"
         "-validityUrl string\n"
         "  The URI of validity information provided. (required)\n"
         "-certificate string\n"
         "  The certificate PEM file for the SXG. (mutual exclusive with "
         "-publicKey)\n"
         "-publicKey string\n"
         "  The Ed25519 PEM file for the SXG. (mutual exclusive with "
         "-certificate)\n"
         "-private_key string\n"
         "  The private key PEM file for the SXG. (required)\n"
         "-content string\n"
         "  Source file to be used as SXG payload (default [index.html]).\n"
         "-contentType string\n"
         "  Mime type of Source file (default [text/html]).\n"
         "-date int\n"
         "  The datetime for the SXG in unixtime. Use now by default.\n"
         "-expire int\n"
         "  The expire time of the SXG in unixtime. (default <date> +7 days)\n"
         "-miRecordSize int\n"
         "  The record size of Merkle Integrity Content Encoding. "
         "(default [4096])\n"
         "-output string\n"
         "  Filename of output sxg file (default [out.sxg])\n";
  }

  friend std::ostream& operator<<(std::ostream& o, const Options& opt) {
    o << "url: " << opt.url << "\n"
      << "certUrl: " << opt.cert_url << "\n"
      << "validityUrl: " << opt.validity_url << "\n";
    if (!opt.certificate.empty()) {
      o << "certificate: " << opt.certificate << "\n";
    }
    if (!opt.public_key.empty()) {
      o << "publicKey: " << opt.public_key << "\n";
    }
    o << "privateKey: " << opt.private_key << "\n"
      << "content: " << opt.content << "\n"
      << "contentType: " << opt.content_type << "\n"
      << "date: " << opt.date << "\n"
      << "expire: " << opt.expire << "\n"
      << "miRecordSize: " << opt.mi_record_size << "\n"
      << "output: " << opt.output << "\n";
    return o;
  }

  bool help;
  std::string url;
  std::string cert_url;
  std::string validity_url;
  std::string certificate;
  std::string public_key;
  std::string private_key;
  std::string content;
  std::string content_type;
  size_t date;
  size_t expire;
  size_t mi_record_size;
  std::string output;
};

int main(int argc, const char** argv) {
  try {
    Options opt(argc, argv);
    if (opt.help) {
      Options::Help(std::cout);
      return 0;
    }
    std::string error = opt.Validate();
    if (!error.empty()) {
      std::cerr << "Invalid option error:\n" << error;
      return 1;
    }

    sxg_signer_list_t signers = sxg_empty_signer_list();
    ;
    opt.LoadSigner(&signers);

    sxg_raw_response_t content = sxg_empty_raw_response();
    ;
    opt.LoadContents(&content.payload);
    if (!sxg_header_append_string("content-type", opt.content_type.c_str(),
                                  &content.header)) {
      throw std::runtime_error("Failed to append content-type header.\n");
    }

    sxg_encoded_response_t encoded = sxg_empty_encoded_response();
    if (!sxg_encode_response(opt.mi_record_size, &content, &encoded)) {
      throw std::runtime_error("Failed to encode contents.");
    }

    sxg_buffer_t result = sxg_empty_buffer();
    if (!sxg_generate(opt.url.c_str(), &signers, &encoded, &result)) {
      throw std::runtime_error("Failed to generate SXG.");
    }

    opt.Output(&result);

    sxg_signer_list_release(&signers);
    sxg_raw_response_release(&content);
    sxg_encoded_response_release(&encoded);
    sxg_buffer_release(&result);

    std::cout << "Wrote SXG file successfully: " << opt.output << "\n";
  } catch (const std::exception& e) {
    std::cerr << e.what() << "\n";
    Options::Help(std::cerr);
  }
}

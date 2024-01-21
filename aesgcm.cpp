#include <CLI11.hpp>
#include <random>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <sys/random.h>
#define VERSION "0.0.1"
using namespace std;
constexpr size_t BATCH_SIZE = 1 << 20;
#define FASSERT(x) \
	if (!(x)) throw std::runtime_error { \
			#x \
		}
using UC = unsigned char;
const string_view MAGIC{"AEG\0", 4};

struct AES256GCM {
	EVP_CIPHER_CTX *ctx;
	EVP_CIPHER *cipher;
	UC iv[12], key[32], tag[16], in_buf[BATCH_SIZE], out_buf[BATCH_SIZE];
	int out_len;

	AES256GCM(string_view k) {
		FASSERT(k.size() == 32);
		copy(k.begin(), k.end(), key);
		FASSERT(ctx = EVP_CIPHER_CTX_new());
		FASSERT(cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL));
	}
	void encrypt(istream &in, ostream &o) {
		getrandom(iv, 12, 0);
		OSSL_PARAM params[2] = {
			OSSL_PARAM_END, OSSL_PARAM_END};
		FASSERT(EVP_EncryptInit_ex2(ctx, cipher, key, iv, params));
		o << MAGIC;
		o.write((char *)iv, 12);
		int gc;
		while (in.read((char *)in_buf, BATCH_SIZE), gc = in.gcount()) {
			FASSERT(EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, gc));
			o.write((char *)out_buf, gc);
		}
		FASSERT(in.eof());
		int _;
		FASSERT(EVP_EncryptFinal_ex(ctx, out_buf, &_));
		params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
													  tag, 16);

		FASSERT(EVP_CIPHER_CTX_get_params(ctx, params));
		o.write((char *)tag, 16);
		o.flush();
	}
	bool decrypt(istream &in, const auto &callback) {
		OSSL_PARAM params[2] = {
			OSSL_PARAM_END, OSSL_PARAM_END};
		in.read((char *)tag, 16);
		FASSERT(in.gcount() == 16);
		string_view magic{(char *)tag, (char *)tag + 4};
		FASSERT(magic == MAGIC);
		FASSERT(EVP_DecryptInit_ex2(ctx, cipher, key, tag + 4, params));
		// tag is used to store a preview of data
		int residual = 0, gc;
		while (in.read((char *)in_buf + residual, BATCH_SIZE - residual), gc = in.gcount()) {
			if (auto in_len = gc + residual; in_len == BATCH_SIZE) {
				in.read((char *)tag, 16);
				if ((residual = in.gcount()) < 16) {
					// approaching to end
					in_len += residual - 16;
					memmove(tag + 16 - residual, tag, residual);
					memmove(tag, in_buf + in_len, 16 - residual);
				}
				FASSERT(EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len));
				memcpy(in_buf, tag, residual);
			} else {
				FASSERT(in_len >= 16);
				memcpy(tag, in_buf + in_len - 16, 16);
				in_len -= 16;
				FASSERT(EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len));
			}
			callback(out_buf, out_len);
		}
		// expected tag
		params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
													  (void *)tag, 16);
		FASSERT(EVP_CIPHER_CTX_set_params(ctx, params));
		return EVP_DecryptFinal_ex(ctx, out_buf, &out_len) > 0;
	}
	~AES256GCM() {
		EVP_CIPHER_free(cipher);
		EVP_CIPHER_CTX_free(ctx);
	}
};
void unit_test(bool quick) {
	string key;
	key.resize(32);
	getrandom(key.data(), 32, 0);
	auto aes = make_unique<AES256GCM>(key);
	string input;
	mt19937 mt(random_device{}());
	auto validate = [&](int len) {
		while (input.size() < len)
			input.push_back(mt());
		stringstream ss{input}, cipher;
		aes->encrypt(ss, cipher);
		int decrypted = 0;
		aes->decrypt(cipher, [&](UC *c, int len) {
			if (!equal(c, c + len, (UC *)input.data() + decrypted)) {
				cerr << "Error when testing len" << input.size() << "\n";
				exit(1);
			}
			decrypted += len;
		});
		FASSERT(decrypted == input.size());
	};
	for (int i = 0; i < (quick ? 512 : 2048); ++i)
		validate(i);
	const int width = quick ? 10 : 1024;
	for (int i = BATCH_SIZE - width; i < BATCH_SIZE + width; ++i)
		validate(i);
	for (int i = 2 * BATCH_SIZE - width; i < 2 * BATCH_SIZE + width; ++i)
		validate(i);
}
int main(int argc, char **argv) {
	CLI::App app("AES256-GCM encryption/decryption " VERSION);
	CLI::App *enc = app.add_subcommand("enc", "encryption");
	CLI::App *dec = app.add_subcommand("dec", "decryption");
	CLI::App *test = app.add_subcommand("test", "test");
	app.require_subcommand(1, 1);
	string key, input, output;
	for (auto x : {enc, dec})
		x->add_option("key", key, "Encryption/Decryption key in hex, 64 or less chars")->required();
	for (auto x : {enc, dec})
		x->add_option("input", input, "Input file path")->required();
	for (auto x : {enc, dec})
		x->add_option("output", output, "Output file path")->required();
	CLI11_PARSE(app, argc, argv);
	if (*test) {
		unit_test(0);
		return 0;
	}
	if (key.size() > 64) {
		cerr << "Warning: key more than 64 chars, the end will be ignored\n";
	}
	key.resize(64);
	auto to_int = [](char c) {
		if (isdigit(c)) return c - '0';
		if (c >= 'A' && c <= 'F') return c - 'A' + 10;
		if (c >= 'a' && c <= 'f') return c - 'a' + 10;
		throw invalid_argument{"got invalid key"};
	};
	for (int i = 0; i < 32; ++i) {
		key[i] = to_int(key[i * 2]) << 4 | to_int(key[i * 2 + 1]);
	}
	key.resize(32);

	auto aes = make_unique<AES256GCM>(key);
	ifstream i(input, ios::in | ios::binary);
	ofstream o(output, ios::out | ios::binary);
	if (*enc) {
		aes->encrypt(i, o);
	} else if (*dec) {
		auto v = aes->decrypt(i, [&](UC *c, int len) { o.write((char *)c, len); });
		FASSERT(v);
	}
}

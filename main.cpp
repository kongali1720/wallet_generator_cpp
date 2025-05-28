#include <iostream>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <iomanip>
#include <sstream>
#include <vector>
#include <cstring>
#include <openssl/bn.h>

using namespace std;

// Convert binary to hex string
string toHex(const unsigned char* data, size_t len) {
    stringstream ss;
    for (size_t i = 0; i < len; i++)
        ss << hex << setw(2) << setfill('0') << (int)data[i];
    return ss.str();
}

// SHA-256
void sha256(const unsigned char* data, size_t len, unsigned char* out) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

// RIPEMD-160
void ripemd160(const unsigned char* data, size_t len, unsigned char* out) {
    RIPEMD160_CTX ctx;
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, data, len);
    RIPEMD160_Final(out, &ctx);
}

// Base58 encode (simple)
const char* BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
string base58(const unsigned char* data, size_t len) {
    BIGNUM* bn = BN_new();
    BN_bin2bn(data, len, bn);

    BIGNUM* div = BN_new();
    BIGNUM* rem = BN_new();
    BN_CTX* ctx = BN_CTX_new();
    string result;

    while (!BN_is_zero(bn)) {
        BN_div(div, rem, bn, BN_value_one(), ctx);
        BN_div(bn, rem, bn, BN_new(), ctx);
        result = BASE58[BN_get_word(rem)] + result;
    }

    BN_free(bn);
    BN_free(div);
    BN_free(rem);
    BN_CTX_free(ctx);
    return result;
}

int main() {
    // Generate EC key
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(key);
    const BIGNUM* priv = EC_KEY_get0_private_key(key);
    const EC_POINT* pub = EC_KEY_get0_public_key(key);
    const EC_GROUP* group = EC_KEY_get0_group(key);

    unsigned char pub_key[65];
    size_t pub_len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, pub_key, sizeof(pub_key), NULL);

    unsigned char sha_pub[32];
    sha256(pub_key, pub_len, sha_pub);

    unsigned char ripe[20];
    ripemd160(sha_pub, 32, ripe);

    // Bitcoin address
    unsigned char btc_address[25];
    btc_address[0] = 0x00; // Mainnet prefix
    memcpy(btc_address + 1, ripe, 20);

    unsigned char hash1[32];
    sha256(btc_address, 21, hash1);
    unsigned char hash2[32];
    sha256(hash1, 32, hash2);
    memcpy(btc_address + 21, hash2, 4);

    string priv_hex = BN_bn2hex(priv);
    string btc_addr_base58 = base58(btc_address, 25);

    // Ethereum address
    string eth_pub_hex = toHex(pub_key + 1, 64);
    unsigned char eth_hash[32];
    sha256(pub_key + 1, 64, eth_hash);
    string eth_addr = "0x" + toHex(eth_hash + 12, 20); // last 20 bytes

    // Output
    cout << "🔑 Private Key (HEX): " << priv_hex << endl;
    cout << "₿ BTC Address: " << btc_addr_base58 << endl;
    cout << "Ξ ETH Address: " << eth_addr << endl;

    EC_KEY_free(key);
    return 0;
}

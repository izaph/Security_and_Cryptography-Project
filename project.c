#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define TEA_BLOCK_SIZE 8
#define CHACHA_BLOCK_SIZE 64
#define RSA_BIGINT_WORDS 32
#define RSA_CHUNK_SIZE 116
#define RSA_BLOCK_SIZE 128

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

typedef struct {
    uint32_t words[RSA_BIGINT_WORDS];
} BigInt;

void bigint_init(BigInt *n, uint64_t val) {
    memset(n->words, 0, sizeof(n->words));
    n->words[0] = (uint32_t)(val & 0xFFFFFFFF);
    n->words[1] = (uint32_t)((val >> 32) & 0xFFFFFFFF);
}

int bigint_is_zero(const BigInt *n) {
    for (int i = 0; i < RSA_BIGINT_WORDS; i++) {
        if (n->words[i] != 0) return 0;
    }
    return 1;
}

int bigint_compare(const BigInt *a, const BigInt *b) {
    for (int i = RSA_BIGINT_WORDS - 1; i >= 0; i--) {
        if (a->words[i] > b->words[i]) return 1;
        if (a->words[i] < b->words[i]) return -1;
    }
    return 0;
}

void bigint_add(BigInt *r, const BigInt *a, const BigInt *b) {
    uint64_t carry = 0;
    for (int i = 0; i < RSA_BIGINT_WORDS; i++) {
        uint64_t sum = (uint64_t)a->words[i] + b->words[i] + carry;
        r->words[i] = (uint32_t)(sum & 0xFFFFFFFF);
        carry = sum >> 32;
    }
}

void bigint_sub(BigInt *r, const BigInt *a, const BigInt *b) {
    int64_t borrow = 0;
    for (int i = 0; i < RSA_BIGINT_WORDS; i++) {
        int64_t diff = (int64_t)a->words[i] - b->words[i] - borrow;
        if (diff < 0) {
            r->words[i] = (uint32_t)(diff + 0x100000000ULL);
            borrow = 1;
        } else {
            r->words[i] = (uint32_t)diff;
            borrow = 0;
        }
    }
}

void bigint_shift_left_1(BigInt *n) {
    uint32_t carry = 0;
    for (int i = 0; i < RSA_BIGINT_WORDS; i++) {
        uint32_t next_carry = n->words[i] >> 31;
        n->words[i] = (n->words[i] << 1) | carry;
        carry = next_carry;
    }
}

void bigint_divmod(const BigInt *num, const BigInt *den, BigInt *rem, BigInt *quo) {
    BigInt q, r;
    bigint_init(&q, 0);
    bigint_init(&r, 0);
    if (bigint_is_zero(den)) return;
    for (int i = RSA_BIGINT_WORDS - 1; i >= 0; i--) {
        for (int j = 31; j >= 0; j--) {
            bigint_shift_left_1(&r);
            r.words[0] |= (num->words[i] >> j) & 1;
            bigint_shift_left_1(&q);
            if (bigint_compare(&r, den) >= 0) {
                bigint_sub(&r, &r, den);
                q.words[0] |= 1;
            }
        }
    }
    if (rem) *rem = r;
    if (quo) *quo = q;
}

void bigint_mul(BigInt *r, const BigInt *a, const BigInt *b) {
    BigInt res;
    bigint_init(&res, 0);
    for (int i = 0; i < RSA_BIGINT_WORDS; i++) {
        uint64_t carry = 0;
        BigInt temp;
        memset(&temp, 0, sizeof(temp));
        for (int j = 0; j + i < RSA_BIGINT_WORDS; j++) {
            uint64_t prod = (uint64_t)a->words[j] * b->words[i] + carry;
            temp.words[j + i] = (uint32_t)(prod & 0xFFFFFFFF);
            carry = prod >> 32;
        }
        bigint_add(&res, &res, &temp);
    }
    *r = res;
}

void bigint_mod_exp(BigInt *r, const BigInt *base, const BigInt *exp, const BigInt *mod) {
    BigInt res, b, e;
    bigint_init(&res, 1);
    b = *base;
    e = *exp;
    while (!bigint_is_zero(&e)) {
        if (e.words[0] & 1) {
            BigInt t;
            bigint_mul(&t, &res, &b);
            bigint_divmod(&t, mod, &res, NULL);
        }
        BigInt t2;
        bigint_mul(&t2, &b, &b);
        bigint_divmod(&t2, mod, &b, NULL);
        BigInt two;
        bigint_init(&two, 2);
        bigint_divmod(&e, &two, &e, NULL);
    }
    *r = res;
}

void to_bytes(const BigInt *n, uint8_t *bytes) {
    for (int i = 0; i < RSA_BLOCK_SIZE; i++) {
        int word_idx = (RSA_BLOCK_SIZE - 1 - i) / 4;
        int byte_idx = (RSA_BLOCK_SIZE - 1 - i) % 4;
        bytes[i] = (uint8_t)((n->words[word_idx] >> (byte_idx * 8)) & 0xFF);
    }
}

void from_bytes(BigInt *n, const uint8_t *bytes, int len) {
    bigint_init(n, 0);
    for (int i = 0; i < len; i++) {
        int target_byte = len - 1 - i;
        int word_idx = target_byte / 4;
        int byte_idx = target_byte % 4;
        if (word_idx < RSA_BIGINT_WORDS) {
            n->words[word_idx] |= ((uint32_t)bytes[i]) << (byte_idx * 8);
        }
    }
}

void tea_encrypt_block(uint32_t *v, const uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    uint32_t delta = 0x9E3779B9;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    for (i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }
    v[0] = v0; v[1] = v1;
}

void chacha_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

void chacha20_block(uint32_t output[16], const uint32_t input[16]) {
    int i;
    memcpy(output, input, 64);
    for (i = 0; i < 10; i++) {
        chacha_quarter_round(&output[0], &output[4], &output[8], &output[12]);
        chacha_quarter_round(&output[1], &output[5], &output[9], &output[13]);
        chacha_quarter_round(&output[2], &output[6], &output[10], &output[14]);
        chacha_quarter_round(&output[3], &output[7], &output[11], &output[15]);
        chacha_quarter_round(&output[0], &output[5], &output[10], &output[15]);
        chacha_quarter_round(&output[1], &output[6], &output[11], &output[12]);
        chacha_quarter_round(&output[2], &output[7], &output[8], &output[13]);
        chacha_quarter_round(&output[3], &output[4], &output[9], &output[14]);
    }
    for (i = 0; i < 16; i++) {
        output[i] += input[i];
    }
}

int run_tea_ctr(const char *in_path, const char *out_path, const uint8_t key[16], const uint8_t nonce[8]) {
    FILE *fin = fopen(in_path, "rb");
    FILE *fout = fopen(out_path, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return 0;
    }
    uint32_t k[4];
    memcpy(k, key, 16);
    uint64_t ctr_val = 0;
    uint8_t block_counter[8];
    memcpy(block_counter, nonce, 8);
    uint8_t buf[65536];
    size_t bytes_read;
    while ((bytes_read = fread(buf, 1, sizeof(buf), fin)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            size_t rem = i % TEA_BLOCK_SIZE;
            static uint32_t encrypted_counter[2];
            if (rem == 0) {
                uint64_t current_nonce_ctr;
                memcpy(&current_nonce_ctr, block_counter, 8);
                current_nonce_ctr += ctr_val++;
                memcpy(encrypted_counter, &current_nonce_ctr, 8);
                tea_encrypt_block(encrypted_counter, k);
            }
            uint8_t *keystream = (uint8_t *)encrypted_counter;
            buf[i] ^= keystream[rem];
        }
        fwrite(buf, 1, bytes_read, fout);
    }
    fclose(fin);
    fclose(fout);
    return 1;
}

int run_chacha20(const char *in_path, const char *out_path, const uint8_t key[32], const uint8_t nonce[12]) {
    FILE *fin = fopen(in_path, "rb");
    FILE *fout = fopen(out_path, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return 0;
    }
    uint32_t state[16];
    state[0] = 0x61736578; state[1] = 0x3120646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    memcpy(&state[4], key, 32);
    state[12] = 0;
    memcpy(&state[13], nonce, 12);
    uint8_t buf[65536];
    size_t bytes_read;
    uint32_t output_block[16];
    uint8_t *keystream = (uint8_t *)output_block;
    size_t keystream_pos = 64;
    while ((bytes_read = fread(buf, 1, sizeof(buf), fin)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            if (keystream_pos >= 64) {
                chacha20_block(output_block, state);
                state[12]++;
                keystream_pos = 0;
            }
            buf[i] ^= keystream[keystream_pos++];
        }
        fwrite(buf, 1, bytes_read, fout);
    }
    fclose(fin);
    fclose(fout);
    return 1;
}

int run_rsa(const char *in_path, const char *out_path, const BigInt *key, const BigInt *mod, int mode) {
    FILE *fin = fopen(in_path, "rb");
    FILE *fout = fopen(out_path, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return 0;
    }
    if (mode == 0) {
        uint8_t in_buf[RSA_CHUNK_SIZE];
        uint8_t out_buf[RSA_BLOCK_SIZE];
        size_t bytes_read;
        while ((bytes_read = fread(in_buf, 1, RSA_CHUNK_SIZE, fin)) > 0) {
            BigInt m, c;
            from_bytes(&m, in_buf, (int)bytes_read);
            bigint_mod_exp(&c, &m, key, mod);
            to_bytes(&c, out_buf);
            fwrite(out_buf, 1, RSA_BLOCK_SIZE, fout);
        }
    } else {
        uint8_t in_buf[RSA_BLOCK_SIZE];
        uint8_t out_buf[RSA_CHUNK_SIZE];
        size_t bytes_read;
        while ((bytes_read = fread(in_buf, 1, RSA_BLOCK_SIZE, fin)) > 0) {
            if (bytes_read < RSA_BLOCK_SIZE) break;
            BigInt c, m;
            from_bytes(&c, in_buf, RSA_BLOCK_SIZE);
            bigint_mod_exp(&m, &c, key, mod);
            to_bytes(&m, out_buf);
            int write_len = RSA_CHUNK_SIZE;
            while (write_len > 0 && out_buf[RSA_CHUNK_SIZE - write_len] == 0) {
                write_len--;
            }
            if (write_len > 0) {
                fwrite(out_buf + (RSA_CHUNK_SIZE - write_len), 1, write_len, fout);
            }
        }
    }
    fclose(fin);
    fclose(fout);
    return 1;
}

int read_key_file(const char *path, uint8_t *buffer, size_t max_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t read_bytes = fread(buffer, 1, max_len, f);
    fclose(f);
    return (read_bytes > 0);
}

int main(int argc, char *argv[]) {
    char *algo = NULL;
    char *mode = NULL;
    char *infile = NULL;
    char *keyfile = NULL;
    char *outfile = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-algo") == 0 && i + 1 < argc) algo = argv[++i];
        else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) { mode = "enc"; infile = argv[++i]; }
        else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) { mode = "dec"; infile = argv[++i]; }
        else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) keyfile = argv[++i];
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) outfile = argv[++i];
    }

    if (!algo || !mode || !infile || !keyfile || !outfile) {
        printf("Usage: %s -algo <tea|chacha|rsa> <-e|-d> <file> -k <keyfile> -o <output>\n", argv[0]);
        return 1;
    }

    uint8_t key_buffer[512];
    memset(key_buffer, 0, sizeof(key_buffer));
    if (!read_key_file(keyfile, key_buffer, sizeof(key_buffer))) {
        printf("Error reading key file: %s\n", keyfile);
        return 1;
    }

    uint8_t tea_nonce[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t chacha_nonce[12] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};

    int success = 0;
    clock_t start_time = clock();

    if (strcmp(algo, "tea") == 0) {
        success = run_tea_ctr(infile, outfile, key_buffer, tea_nonce);
    } else if (strcmp(algo, "chacha") == 0) {
        success = run_chacha20(infile, outfile, key_buffer, chacha_nonce);
    } else if (strcmp(algo, "rsa") == 0) {
        BigInt rsa_mod, rsa_key;
        bigint_init(&rsa_mod, 0);
        rsa_mod.words[0] = 0xE140810D; rsa_mod.words[1] = 0xB167E4A1; rsa_mod.words[2] = 0x933092A5; rsa_mod.words[3] = 0x6E4A810B;

        if (strcmp(mode, "enc") == 0) {
            bigint_init(&rsa_key, 65537);
            success = run_rsa(infile, outfile, &rsa_key, &rsa_mod, 0);
        } else {
            bigint_init(&rsa_key, 0);
            rsa_key.words[0] = 0x47B78001; rsa_key.words[1] = 0x1E14B4A9; rsa_key.words[2] = 0x2A1549B1; rsa_key.words[3] = 0x3C49A005;
            success = run_rsa(infile, outfile, &rsa_key, &rsa_mod, 1);
        }
    }

    clock_t end_time = clock();
    double total_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    if (success) {
        printf("Operation completed successfully.\n");
        printf("Execution Time: %.4f seconds\n", total_time);
        return 0;
    } else {
        printf("Operation failed.\n");
        return 1;
    }
}
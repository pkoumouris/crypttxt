/*
Compile:
gcc -o pkcrypt pkcrypt.c -L/usr/local/opt/openssl@1.1/lib -I/usr/local/opt/openssl@1.1/include -lssl -lcrypto -lgmp

Encrypt:
./pkcrypt enc <filename>

Decrypt:
./pkcrypt dec <filename>
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "crypttxt.h"

static const unsigned char base64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int main(int argc, char *argv[]){
  if (argc != 3){
    printf("Must have 2 arguments (received %d)\n", argc-1);
    return 0;
  }

  char password[MAX_PASSWORD_LEN + 1];

  if (!strcmp(argv[1], "enc")){
    printf("Type your password (max %d characters): ", MAX_PASSWORD_LEN);
    scanf("%s", password);
    if (encrypt_file(argv[2], password)){
      printf("Encryption failed.\n");
    } else {
      printf("Successfully encrypted.\n");
    }
  } else if (!strcmp(argv[1], "dec")){
    printf("Type your password: ");
    scanf("%s", password);
    if (decrypt_file(argv[2], password)){
      printf("Decryption failed.\n");
    } else {
      printf("Successfully decrypted.\n");
    }
  } else {
    printf("First argument is either enc or dec.\n");
  }
  return 0;
}

int decrypt_file(char *filename, char *password){
  FILE *fr = fopen(filename, "r");
  unsigned long int len;
  char *buf;
  if (fr != NULL){
    fseek(fr, 0, SEEK_END);
    len = ftell(fr);
    fseek(fr, 0, SEEK_SET);
    buf = malloc(len + 1);
    if (buf != NULL){
      fread(buf, 1, len, fr);
    }
    fclose(fr);
  } else {
    printf("Couldn't read file.\n");
    return 1;
  }

  size_t b64declen;
  char *b64dec = (char *)base64_decode((unsigned char *)buf, len, &b64declen);

  unsigned char key[HASHBYTE_LEN];
  hash(key, password, strlen(password), HASH_FUNCTION);

  char str[b64declen + 9];
  int slen = decrypt((unsigned char *)b64dec, (int)b64declen, key, (unsigned char *)"0123456789abcdef", (unsigned char *)str);
  if (slen < 0){
    printf("Couldn't decrypt, possibly wrong password.\n");
    return 1;
  }
  str[slen] = '\0';

  FILE *f = fopen(filename, "w");
  if (f != NULL){
    fwrite(str, 1, b64declen, f);
    fclose(f);
  } else {
    return 1;
  }
  return 0;
}

int encrypt_file(char *filename, char *password){
  FILE *fr = fopen(filename, "r");
  unsigned long int len;
  char *buf;
  if (fr != NULL){
    fseek(fr, 0, SEEK_END);
    len = ftell(fr);
    fseek(fr, 0, SEEK_SET);
    buf = malloc(len + 1);
    if (buf != NULL){
      fread(buf, 1, len, fr);
    }
    fclose(fr);
  } else {
    printf("Couldn't read file.\n");
    return 1;
  }
  //printf("Your string (len = %lu) is:\n%s\n", len, buf);

  unsigned char key[HASHBYTE_LEN];
  hash(key, password, strlen(password), HASH_FUNCTION);

  unsigned char ct[len + 9];
  int ctlen = encrypt((unsigned char *)buf, len, key, (unsigned char *)"0123456789abcdef", ct);

  size_t b64enclen;
  char *b64enc = (char *)base64_encode(ct, ctlen, &b64enclen);

  FILE *f = fopen(filename, "w");
  if (f != NULL){
    //printf("The base 64 str is:\n%s\n", b64enc);
    fwrite(b64enc, 1, b64enclen, f);
    fclose(f);
  } else {
    return 1;
  }
  return 0;
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        return -1;

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return -1;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

unsigned char * base64_encode(const unsigned char *src, size_t len,
  size_t *out_len){
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 72; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = malloc(olen);
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 72) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}

unsigned char * base64_decode(const unsigned char *src, size_t len,
  size_t *out_len){
	unsigned char dtable[256], *out, *pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char) i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}

unsigned int hash(unsigned char *output, char *input, int input_len, char *hashtype){
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned int md_len;
  md = EVP_get_digestbyname(hashtype);

  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, input, input_len);
  EVP_DigestFinal_ex(mdctx, output, &md_len);
  EVP_MD_CTX_free(mdctx);
  return md_len;
}

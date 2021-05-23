
#define HASHBYTE_LEN 32
#define HASH_FUNCTION "SHA256"
#define MAX_PASSWORD_LEN 64

int encrypt_file(char *filename, char *password);
int decrypt_file(char *filename, char *password);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);
unsigned char * base64_encode(const unsigned char *src, size_t len,
    size_t *out_len);
unsigned char * base64_decode(const unsigned char *src, size_t len,
    size_t *out_len);
unsigned int hash(unsigned char *output, char *input, int input_len, char *hashtype);

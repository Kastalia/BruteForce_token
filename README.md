BruteForce impementation for token decryption (result is PIN).

Salt = most popular default salts, custom salts.
Key = PBKDF2(HMAC-SHA1, PIN, array of Salts, 1024 iterations, custom keylen)
Ciphers = AES, Blowfish, DES, DES3, CAST in CBC/ECB mode, Gamma
Criterion for plain text: Keywords, padding PKCS#7

May be used for bruteforce any types of cipher texts.

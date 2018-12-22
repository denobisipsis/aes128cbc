# aes128cbc

WHY A NEW RIJNDAEL CLASS?

I WANTED TO MAKE A PURE CLASS WITHOUT HELP-TABLES, ONLY THE PURE COMPUTING ON DATA AS IS RIJNDAEL ENCRYPTION. THIS IS A BIT MORE COMPLICATED AS THE ROW SHIFTING AND MIXING COLUMNS GALOIS ARE NOT EASY TO IMPLEMENT, AND I HAVE NOT FOUND ON THE WEB ANYTHING SIMILAR.

Pure PHP Rijndael/AES code for 128 bits block CBC

This is PURE RIJNDAEL IMPLEMENTATION with each step explained

- PRETTY SHORT

- WITHOUT TABLES

- SBOX IS GENERATED

- FIXED TO 16 BYTE BLOCK SIZE (AES STANDARD) AND CBC

- KEY CAN BE 128,192 OR 256 BITS, either hexadecimal or ascii. If aes128, aes192 or aes256 is determined by the key length

- IV always 128

USAGE:

$AES=new aes128cbc;

$AES->init($key,$iv);

$AES->decrypt($AES->encrypt($plaintext));

# RIJNDAEL

### BYTE ORIENTED

YOU CAN ENCRYPT/DECRYPT IN 16,20,24,28 AND 32 BYTES BLOCK SIZE

KEY CAN BE 128,160,192,224 OR 256 BITS, either hexadecimal or ascii. In theory is possible to use keys >256 with this class.

IV SHOULD MATCH BLOCK SIZE (CBC MODE)

TO IMPLEMENT

Padding Oracle Attack
Also, you normally don't want to use a (rather short) password directly as a key, but instead use a longer passphrase, and hash it with a salt (included with in the message) to derive the key. If you do this, you can also derive the initialization vector from the same two pieces of data (but in a way that they'll be different, using a key derivation function). To avoid brute-forcing your password from the encrypted file, use a slow hash function here (PBKDF-2 or bcrypt).

CTR & other modes

USAGE:

$RIJNDAEL_CBC=new RIJNDAEL_CBC;

$RIJNDAEL_CBC->init($key,$iv,$block_size);

$RIJNDAEL_CBC->decrypt($RIJNDAEL_CBC->encrypt($plaintext));

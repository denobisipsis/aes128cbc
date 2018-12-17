# aes128cbc
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

YOU CAN ENCRYPT IN 16, 20,24,28 AND 32 BYTES BLOCK SIZE

KEY CAN BE 128,192 OR 256 BITS, either hexadecimal or ascii. 

IV SOULD MATCH BLOCK SIZE (CBC MODE)

USAGE:

$RIJNDAEL_CBC=new RIJNDAEL_CBC;
$RIJNDAEL_CBC->init($key,$iv,$block_size);
$RIJNDAEL_CBC->decrypt($RIJNDAEL_CBC->encrypt($plaintext));

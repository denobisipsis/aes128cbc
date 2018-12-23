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
```php
$AES=new aes128cbc;

$AES->init($key,$iv);

$AES->decrypt($AES->encrypt($plaintext));
```
# RIJNDAEL

Pure PHP Rijndael/AES code for 128 to 256 bits block ECB,CBC,CTR,CFB,OFB & GCM

This is PURE RIJNDAEL IMPLEMENTATION with each step explained

PRETTY SHORT
WITHOUT TABLES
SBOX IS GENERATED
BY DEFAULT 16 BYTE BLOCK SIZE (AES STANDARD) AND CBC, BUT YOU CAN ENCRYPT IN 20,24,28 AND 32 BYTES BLOCK SIZE
KEY CAN BE 128,160,192,224 OR 256 BITS, either hexadecimal or ascii. 
IV SHOULD MATCH BLOCK SIZE (CBC MODE)
GCM MODE INCORPORATED


```php
	GCM MODE
	
	Recommendation for Block
	Cipher Modes of Operation:
	Galois/Counter Mode (GCM)
	and GMAC
	
	https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	
	Freely adopted & modified in part the script https://github.com/Spomky-Labs/php-aes-gcm
	
	Specially, the GMUL function.
	
	Also, the ECB is computed internally
```
USAGE:
```php
$RIJNDAEL_CBC=new RIJNDAEL_CBC;
$RIJNDAEL_CBC->init($mode,$key,$iv,$block_size);
$RIJNDAEL_CBC->decrypt($RIJNDAEL_CBC->encrypt($plaintext));
```
USAGE for AES-GCM
```php
	$x=new RIJNDAEL_CBC; 
	
	$K = 'feffe9928665731c6d6a8f9467308308feffe9928665731cfeffe9928665731c6d6a8f9467308308feffe9928665731c';

	// The data to encrypt (can be null for authentication)
	$P = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39';

	// Additional Authenticated Data
	$A = 'feedfacedeadbeeffeedfacedeadbeefabaddad2';

	// Initialization Vector
	$IV = 'cafebabefacedbaddecaf888';

	$x->init("gcm",$K,$IV,16);
	
	// $C is the encrypted data ($C is null if $P is null)
	// $T is the associated tag

	list($C, $T) = $x->encrypt($P, $A, "",128);

	list($P, $T) = $x->decrypt($C, $A, $T,128);
```
# THERE IS A TEST to validate THIS AES-GCM, SIMPLY RUN THIS SCRIPT

AES GCM test vectors from http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf

# Supported key lengths:

128 bits

160 bits

192 bits

224 bits

256 bits

# Support block modes:

ECB: Electronic Code Book

CBC: Cipher Block Chaining

CTR: Counter mode

CFB: Cipher Feedback

OFB: Output Feedback

GCM: Galois Counter Mode


# TO IMPLEMENT

Padding Oracle Attack
Also, you normally don't want to use a (rather short) password directly as a key, but instead use a longer passphrase, and hash it with a salt (included with in the message) to derive the key. If you do this, you can also derive the initialization vector from the same two pieces of data (but in a way that they'll be different, using a key derivation function). To avoid brute-forcing your password from the encrypted file, use a slow hash function here (PBKDF-2 or bcrypt).

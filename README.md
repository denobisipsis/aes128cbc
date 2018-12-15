# aes128cbc
Pure PHP Rijndael/AES code for 128 bits block CBC

/* Copyright 2018 denobisipsis
*
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License as
*  published by the Free Software Foundation; either version 2 of the
*  License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*  General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
*  02111-1307 USA
*/

This is PURE RIJNDAEL IMPLEMENTATION with each step explained

- PRETTY SHORT

- WITHOUT TABLES

- SBOX IS GENERATED

- FIXED TO 16 BYTE BLOCK SIZE (AES STANDARD) AND CBC

- KEY CAN BE 128,192 OR 256 BITS, either hexadecimal or ascii. If one or another is determined by the key length

- IV always 128

USAGE:

$AES=new aes128cbc;
$AES->init($key,$iv);
$AES->decrypt($AES->encrypt($plaintext));

<?
/**
*  Copyright XII-2018 denobisipsis
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
*
Pure PHP Rijndael/AES code for 128 to 256 bits block ECB,CBC,CTR,CFB,OFB & GCM

This is PURE RIJNDAEL IMPLEMENTATION with each step explained

PRETTY SHORT
WITHOUT TABLES
SBOX IS GENERATED
BY DEFAULT 16 BYTE BLOCK SIZE (AES STANDARD) AND CBC, BUT YOU CAN ENCRYPT IN 20,24,28 AND 32 BYTES BLOCK SIZE
KEY CAN BE 128,160,192,224 OR 256 BITS, either hexadecimal or ascii. 
IV SHOULD MATCH BLOCK SIZE (CBC MODE)
GCM MODE INCORPORATED

USAGE:

$RIJNDAEL_CBC=new RIJNDAEL_CBC;
$RIJNDAEL_CBC->init($mode,$key,$iv,$block_size);
$RIJNDAEL_CBC->decrypt($RIJNDAEL_CBC->encrypt($plaintext));

USAGE for AES-GCM

	$x=new RIJNDAEL_CBC; 
	
	$K = ('feffe9928665731c6d6a8f9467308308feffe9928665731cfeffe9928665731c6d6a8f9467308308feffe9928665731c');

	// The data to encrypt (can be null for authentication)
	$P = ('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');

	// Additional Authenticated Data
	$A = ('feedfacedeadbeeffeedfacedeadbeefabaddad2');

	// Initialization Vector
	$IV = ('cafebabefacedbaddecaf888');

	$x->init("gcm",$K,$IV,16);
	
	// $C is the encrypted data ($C is null if $P is null)
	// $T is the associated tag

	list($C, $T) = $x->encrypt($P, $A, "",128);

	list($P, $T) = $x->decrypt($C, $A, $T,128);

Supported key lengths:

128 bits
160 bits
192 bits
224 bits
256 bits

Support block modes:

ECB: Electronic Code Book
CBC: Cipher Block Chaining
CTR: Counter mode
CFB: Cipher Feedback
OFB: Output Feedback
GCM: Galois Counter Mode


TO IMPLEMENT

Padding Oracle Attack
Also, you normally don't want to use a (rather short) password directly as a key, but instead use a longer passphrase, and hash it with a salt (included with in the message) to derive the key. If you do this, you can also derive the initialization vector from the same two pieces of data (but in a way that they'll be different, using a key derivation function). To avoid brute-forcing your password from the encrypted file, use a slow hash function here (PBKDF-2 or bcrypt).

*/
class RIJNDAEL_CBC
	{	
	var $sbox;
	var $Nr;
	var $Nk;
	var $keys;
	var $iv;
	var $iv_ctr;
	var $iv_gcm;
	var $Nb;
	var $c;
	var $block_size;
	var $mode;
	var $gcm_tag_length;
	var $K;
	
	function init($mode='cbc',$key,$iv="",$block_size=16)
		{
		$mode=strtolower($mode);
		
		/**
		Valid modes are ecb,cbc,ctr,cfb,ofb,gcm		
		*/
				
		if (!ctype_xdigit($key) and $mode!="gcm") $key=bin2hex($key);
		if (!ctype_xdigit($iv) and $mode!="gcm")  $iv=bin2hex($iv);
		
		if ((strlen($key)%4)!=0)
			die("Key length should be 16,20,24,28 or 32 bytes");
		elseif (strlen($key)<64 or strlen($key)>128)
			die("Key length should be 16,20,24,28 or 32 bytes");
		
		$this->block_size = $block_size;
		$this->mode=$mode;
		$this->iv_gcm = $iv;				
		
		/**
		Iv is padded to block_size except for GCM mode	
		*/
				
		if ($iv!="")
			if (strlen($iv)!=$block_size*2 and $mode!="gcm")				
				$iv=str_pad(substr($iv, 0, $this->block_size*2), $this->block_size*2, "00"); 
		
		$this->iv = $iv;

		if ($mode=="gcm") 
			{
			$this->K  = hex2bin($key);
			$this->iv = hex2bin($iv);			
			return;
			}
									
		$this->generatesbox();	
		
		$this->Nb = $block_size/4;
		$this->Nk = strlen($key)/8;
		$this->Nr = max($this->Nk, $this->Nb) + 6;
						
		$this->key_expansion($key);	
				
		// COLUMNS SHIFTING 
		
	        switch ($this->Nb) {
	            case 4:
	            case 5:
	            case 6:
	                $this->c = 4; // 128,160,192 BITS
	                break;
	            case 7:
	                $this->c = 2; // 224
	                break;
	            case 8:
	                $this->c = 1; // 256
	        }		
		
		if ($this->gcm_tag_length) $mode="gcm";
		
		echo "\nRIJNDAEL BLOCK ".($block_size*8)." KEY ".(strlen($key)*2)." MODE $mode\n";	
		}
		
	function rOTL8($x,$shift) 
		{
		// FOR AFFINE TRANSFORMATION
		return ($x << $shift) | ($x >> (8 - $shift));}
	
	function generatesbox() 
		{		
		$p = $q = 1;
		
		/** LOOP INVARIANT: p * q == 1 IN THE GALOIS FIELD */
		
		do {
			/** MULTIPLY p BY 3 */
			
			$p ^= $this->multiply($p);
	
			/** DIVIDE q BY 3 = * 0xf6) */
			
			$q^= $q << 1;
			$q^= $q << 2;
			$q^= $q << 4;
			$q^= $q & 0x80 ? 0x09 : 0;
			
			$q %=256;
			
			/** AFFINE TRANSFORMATION */
			
			$xformed = ($q ^ $this->rOTL8($q, 1) ^ $this->rOTL8($q, 2) ^ $this->rOTL8($q, 3) ^ $this->rOTL8($q, 4)) % 256;
	
			$sbox[$p] = $xformed ^ 0x63;
			
		} while ($p != 1);
	
		/** 0 HAS NO INVERSE */
		
		$sbox[0] = 0x63;
		
		$this->sbox=$sbox;
		}

	function multiply($a)
		{
		$hi_bit_set = $a & 0x80;
		$a <<= 1;
		if($hi_bit_set == 0x80) $a ^= 0x1b;
		return $a % 256;	
		}
						
	function sub_byte($byte,$xor="")
		{
		// PERFORM SBOX SUBSTITUTION
		return @($this->sbox[$byte]^$xor);}

	function sub_word($word)
	    	{   
	        for( $i=0; $i<4; $i++ ){$word[$i] = $this->sbox[$word[$i]];}
	        return $word;
	    	}

	function key_expansion($key)
	    	{
		// COMPUTE ALL ROUND KEYS
		    	
	        $key_schedule=array();		
		$key=array_values(unpack("C*",pack("H*",$key)));		
	        for($i=0;  $i < $this->Nk; $i++)
			{$key_schedule[$i] = array(($key[4*$i]),($key[4*$i+1]),($key[4*$i+2]),($key[4*$i+3]));}	
	        $i = $this->Nk;	
		
		// RCON IS CALCULATED ON THE FLY
			
		$rcon=0x8d;		
	        while ($i < $this->Nb * ($this->Nr+1) )
			{
		            $word = $key_schedule[$i-1];			    	    
		            if ($i % $this->Nk == 0)
				    {  
				        array_push($word,@array_shift($word));	// ROT WORD						      
			                $word = $this->sub_word($word);	// SBOX SUBSTITUTION
					$word[0]^=($rcon=$this->multiply($rcon));// XOR WITH RCON					
			            }
			    elseif ($this->Nk > 6 && $i % $this->Nk == 4)				    			    	
			                $word = $this->sub_word($word);	
			    
			    // XORING REMAINING WORDS WITH PREVIOUS
		            for($j=0; $j<4; $j++) {$word[$j]^= $key_schedule[$i-$this->Nk][$j];}	
		            $key_schedule[$i] = $word;
		            $i++;
	        	}
		    // REGROUP WORDS TO RETURN KEYS	    
		    $key_expansion=Array();		    
		    for ($k=0;$k<sizeof($key_schedule)-1;$k+=$this->Nb)
		    	{
			    $v2=array();			    
			    for ($j1=$k;$j1<$this->Nb+$k;$j1++)
			    	{for ($j2=0;$j2<4;$j2++) {$v2[]=$key_schedule[$j1][$j2];}}				
			    $key_expansion[]=$v2;	
			}			
		$this->keys=$key_expansion;
		}			
		
	function galois_multiplication($a,$b="") 
		{
		// FOR COLUMNS MIXING
		
		// reference https://www.samiam.org/galois.html
		
		$p = 0;
		for($c = 0; $c < 8; $c++) 
			{
			if(($b & 1) == 1) $p ^= $a;
			$a=$this->multiply($a);			
			$b >>= 1;
			}		
		return ($p % 256);
		}
    
	function block_encrypt($block,$xor="")
		{
		$keys = $this->keys;
		
		// COLUMN MULTIPLIERS FOR MIXING GALOIS
		
		$mul = array(2,3,1,1);
		
		$state=$block;
		
		// XOR IV IF PRESENT OR IV=LAST ENCRYPTED BLOCK
							
		if ($xor)
			{$temp=array();for ($g=0;$g<$this->Nb*4;$g++) {$temp[]=$state[$g] ^ $xor[$g];}$state=$temp;}

		/**
		https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
		
		Table 1: Number of rounds (Nr) as a function of the block and key length.
		
				   Nb = 4 Nb = 6 Nb = 8
				Nk = 4  10     12    14
				Nk = 6  12     12    14
				Nk = 8  14     14    14			
		*/
							
		FOR ($ROUND=1;$ROUND<$this->Nr;$ROUND++)
			{
			// SBOX SUBSTITUTION & ROWS SHIFTING & XOR WITH ROUND KEY
				
			/**
			Table 2: Shift offsets for different block lengths.
			
					4 1 2 3
					6 1 2 3
					8 1 3 4	
					
			I HAVE IMPLEMENTED THIS THROUGH C VARIABLE. BY DEFAULT SHIFTING IS STANDARD 0,1,2,3				
			*/
							
			$temp0=array();								
			for ($g=0;$g<$this->Nb;$g++)
				{						
				for ($k1=0;$k1<4;$k1++)
					{						
					$c = $k1>$this->c ? 1 : 0;$index=($g-$c+$k1*($this->Nb-1))%$this->Nb;
					$temp0[$k1][$index]=$this->sub_byte($keys[$ROUND-1][$g*4+$k1]^$state[$g*4+$k1]);
					}
				}
			// MIX COLUMNS WITH GALOIS MULTIPLICATION				
			$temp1=array();				
			for ($k1=0;$k1<4;$k1++)
				{
				for ($k3=0;$k3<$this->Nb;$k3++)
					{								
					$t="";		
					for ($k2=0;$k2<4;$k2++){$t^=$this->galois_multiplication($temp0[$k2][$k3],$mul[($k2+$k1*3)%4]);}					
					$temp1[$k3*4+$k1]=$t;
					}
				}
			// TEMP1 IS THE MIX-STATE MATRIX
			$state=$temp1;
			}
		// FINAL ROUND NO MIXING. FIRST XORING AND SUBSBOX, SECOND ROUNDKEY				
		for ($g=0;$g<$this->Nb;$g++)
			{			
			for ($k1=0;$k1<4;$k1++)
				{
				$c = $k1>$this->c ? 1 : 0;$index=($g-$c+$k1*($this->Nb-1))%$this->Nb;					
				$k0[$k1][$index]=$this->sub_byte($keys[$ROUND-1][$k1+$g*4]^$state[$k1+$g*4]);
				}
			}
			
		return $this->xor_block_key($k0,$keys[$ROUND]);		
		}
	
	function xor_block_key($block,$key)
		{
		$xor="";						
		for ($k2=0;$k2<$this->Nb;$k2++)
			{for ($k1=0;$k1<4;$k1++){$xor.=sprintf("%02x",$block[$k1][$k2]^$key[$k2*4+$k1]);}}
		return $xor;		
		}
				
	function block_decrypt($todecrypt,$i,$ecb)
		{
		// SAME SBOX, NO INVERSE TABLE
		
		// COLUMN MULTIPLIERS FOR INVERSE MIXING
		
		$mul=array(14,11,13,9);				
		$keys=$this->keys;					
		$state=array_values(unpack("C*",pack("H*",$todecrypt[$i])));
		
		// ROUNDKEY & UNSUBS-SBOX & UNXORING WITH NEXT KEY
			
		$temp=array();			
		for ($k1=0;$k1<$this->Nb*4;$k1++)
			{										
			$c = ($k1%4)>$this->c ? 1 : 0;				
			$index=($k1+4*($k1%4+$c))%$this->block_size;				
			$temp[$index]=array_Search($keys[$this->Nr][$k1]^$state[$k1],$this->sbox)^$keys[$this->Nr-1][$index];
			}			
		$state=$temp;			
		FOR ($ROUND=$this->Nr-2;$ROUND>=0;$ROUND--)
			{
			// UNMIX COLUMNS & UNSHIFT & UNSBOX & UNXORING WITH KEY				
			$ky=$keys[$ROUND];					
			for ($k1=0;$k1<4;$k1++)
				{
				$c = $k1>$this->c ? 1 : 0;					
				for ($k3=0;$k3<$this->Nb;$k3++)
					{								
					$galoism="";
					$index=($k1+($k3+$c+$k1)*4)%$this->block_size;
					for ($k2=0;$k2<4;$k2++)
						{$galoism^=$this->galois_multiplication($state[$k2+$k3*4],$mul[($k2+$k1*3)%4]) % 256;}	
					$temp[$index]=array_Search($galoism,$this->sbox)^$ky[$index];				
					}					
				}
			$state=$temp;														
			}
		// FINAL BLOCK DECRYPTING 																		
		if ($i>0)          	$ky=array_values(unpack("C*",pack("H*",$todecrypt[$i-1])));	// UNXOR WITH PREVIOUS BLOCK				  	
		else if ($this->iv)  	$ky=array_values(unpack("C*",pack("H*",$this->iv)));		// UNXOR WITH IV				
		else               	$ky=str_split(str_repeat("0",$this->Nb*4));	
								
		$decrypted_block="";
					
		for ($k1=0;$k1<$this->Nb*4;$k1++)
			{
			if (!$ecb)
				$decrypted_block.=sprintf("%02x",$state[$k1]^$ky[$k1]);
			else 	$decrypted_block.=sprintf("%02x",$state[$k1]);
			}
																					
		return $decrypted_block;
		}

	function encrypt_ecb($tocrypt)		
		{								
		$this->iv="";			    
		return $this->encrypt_cbc($tocrypt,1);
		}		    
				
	function decrypt_ecb($todecrypt)
		{
		$this->iv="";			    
		return $this->decrypt_cbc($todecrypt,1);		    
		}
										         				
	function encrypt_cbc($tocrypt,$ecb=0)
		{							
		$tocrypt=bin2hex($this->pad($tocrypt));	
		
		$iv = array_values(unpack("C*",pack("H*",$this->iv)));						
		$ENCRYPTED = "";		
		$it=$this->block_size*2;		
		$tocrypt=str_Split($tocrypt,$it);					
		for ($i = 0; $i < sizeof($tocrypt); $i++)
			{					
			$enc=$this->block_encrypt(array_values(unpack("C*",pack("H*",$tocrypt[$i]))),$iv);	
			$ENCRYPTED.=$enc;
			if (!$ecb)			
			$iv=array_values(unpack("C*",pack("H*",$enc)));
			}			
		return $ENCRYPTED;
		}

	function decrypt_cbc($todecrypt,$ecb=0)
		{		
		$DECRYPTED=array();	
		$it=$this->block_size*2;
		$todecrypt=str_Split($todecrypt,$it);						
		for ($i = sizeof($todecrypt)-1; $i >=0 ; $i--)
			{					
			$dec=$this->block_decrypt($todecrypt,$i,$ecb);	
			$DECRYPTED[]=$dec;			
			}			
		return $this->unpad(pack("H*",implode(array_reverse($DECRYPTED))));
		}
				
	function encrypt_ctr($tocrypt)
		{							
		$tocrypt=bin2hex($tocrypt);	
		$this->iv_ctr = $this->iv;						
		$ENCRYPTED = "";		
		$it=$this->block_size*2;		
		$tocrypt=str_Split($tocrypt,$it);		

                for ($i = 0; $i < sizeof($tocrypt); $i++) 
		 	{
                        $block = pack("H*",$tocrypt[$i]);
                        $key = pack("H*",$this->block_encrypt($this->xor_ctr_gen($this->block_size, $this->iv_ctr)));
                        $ENCRYPTED.= bin2hex($block^$key);
                    	}
									
		return $ENCRYPTED;
		}

	function decrypt_ctr($todecrypt)
		{											
		return pack("H*",$this->encrypt_ctr($todecrypt));
		}

	function xor_ctr_gen($length, $iv)
	    	{	   	        	
	        $block_size = $this->block_size;
	        $xor = $iv;
							
	        for ($j = 8; $j <= $block_size*2; $j+=8) 
			{
		        $temp = substr($iv, -$j, 8);

	                extract(unpack('Ncount', pack("H*",$temp)));
	                $long=bin2hex(pack('N', $count+1));
			$iv = substr_replace($iv, $long, -$j, 8);
			
			if ($temp!="FFFFFFFF" and $temp!="7FFFFFFF") break;					
		        }

		$this->iv_ctr=$iv;	
	        return array_values(unpack("C*",pack("H*",$xor)));
	    	}
		    		
	function encrypt_cfb($tocrypt)
		{
		$iv = array_values(unpack("C*",pack("H*",$this->iv)));		
                $block_size = $this->block_size;		
                $len = strlen($tocrypt);
                $i = 0;
		$ENCRYPTED="";
				
                while ($len >= $block_size) 
			{ 
		    	$iv = pack("H*",$this->block_encrypt($iv)) ^ substr($tocrypt, $i, $block_size);
                    	$ENCRYPTED.= $iv;
		    	$iv = array_values(unpack("C*",$iv));
                    	$len-= $block_size;
                    	$i+= $block_size;
                	}
                if ($len) 
			{
                    	$iv = pack("H*",$this->block_encrypt($iv));
                    	$block = $iv ^ substr($tocrypt, $i);
                    	$iv = substr_replace($iv, $block, 0, $len);
                    	$ENCRYPTED.= $block;
                	}
			
		return bin2hex($ENCRYPTED);
		}
		
	function decrypt_cfb($todecrypt)
		{
		$iv = array_values(unpack("C*",pack("H*",$this->iv)));		
                $block_size = $this->block_size;		
                $len = strlen($todecrypt);
                $i = 0;
		$DECRYPTED="";
				
                while ($len >= $block_size) 
			{ 
		    	$iv = pack("H*",$this->block_encrypt($iv));
			$cb = substr($todecrypt, $i, $block_size);
                    	$DECRYPTED.= $iv ^ $cb;
		    	$iv = array_values(unpack("C*",$cb));
                    	$len-= $block_size;
                    	$i+= $block_size;
                	}
                if ($len) 
			{
                    	$iv = pack("H*",$this->block_encrypt($iv));
			$DECRYPTED.= $iv ^ substr($todecrypt, $i);                    	
                    	$iv = substr_replace($iv, substr($todecrypt, $i), 0, $len);
                	}
			
		return $DECRYPTED;
		}
		
	function encrypt_ofb($tocrypt)
		{
                $xor = array_values(unpack("C*",pack("H*",$this->iv)));
 		$block_size = $this->block_size;
		$ENCRYPTED="";
		 
                for ($i = 0; $i < strlen($tocrypt); $i+=$block_size) 
		    	{
                        $xor = pack("H*",$this->block_encrypt($xor));
                        $ENCRYPTED.= substr($tocrypt, $i, $block_size) ^ $xor;
			$xor = array_values(unpack("C*",$xor));
                    	}
			    
		return bin2hex($ENCRYPTED);		    
		}

	/**
	GCM MODE
	
	Recommendation for Block
	Cipher Modes of Operation:
	Galois/Counter Mode (GCM)
	and GMAC
	
	https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	
	Freely adopted & modified in part the script https://github.com/Spomky-Labs/php-aes-gcm
	
	Specially, the GMUL function.
	
	Also, the ECB is computed internally	
	*/
			
	function encrypt_gcm($P = null, $A = null, $T = null, $tag_length = 128)
	    	{
		/**
		Same for decrypting with the T value
		*/
		$this->gcm_tag_length=$tag_length;
		
		if (ctype_xdigit($P)) $P=hex2bin($P);
		if (ctype_xdigit($A)) $A=hex2bin($A);
		
		$K=$this->K;$T1=$C2="";
		
		$key_length=mb_strlen($K, '8bit') * 8;
		
			
		if (!in_Array($tag_length, [128, 120, 112, 104, 96])) print_r('Invalid tag length. Supported values are: 128, 120, 112, 104 and 96.');	
		/**
		
		To check, but it works with 160 & 224 too
		
		if (!in_Array($key_length, [128, 192, 256])) print_r('Bad key encryption key length. Supported values are: 128, 192 and 256.');	
	
		*/
						
		if ($T!=null) {$T=hex2bin($T);$T1=$T;$C2=$P;}

	        list($J0, $v, $a_len_padding, $H) = $this->GCMSETUP($K, $key_length, $this->iv, $A);
	
	        $C = $C3 = $this->GCTR($K, $key_length, $this->Inc(32, $J0), $P);
		
		if ($T!=null) {$C=$P;}
		
	        $u = $this->calcVector($C);
		
	        $c_len_padding = $this->addPadding($C);
	
	        $S = $this->Hash($H, $A.str_pad('', $v / 8, "\0").$C.str_pad('', $u / 8, "\0").$a_len_padding.$c_len_padding);
		
		if ($T==null) $C=bin2hex($C); else $C=bin2hex($C2);
		
	        $T = $this->SB($tag_length, $this->GCTR($K, $key_length, $J0, $S));
		
		if ($T1!=$T and $C2) print_r('Unable to decrypt or to verify the tag.');		
		
		$T=bin2hex($T);
		
		$this->init("gcm",bin2hex($this->K),$this->iv_gcm);
		
		if ($C2) $C = $C3;
		
	        return [$C, $T];
	    	}
			        
	function GCMSETUP($K, $key_length, $IV, $A)
		{	
		$this->init('ecb',bin2hex($K),bin2hex($IV),$this->block_size); 	
		$H=pack("H*",$this->encrypt_ecb(str_repeat("\0", $this->block_size)));
	        $iv_len = $this->gLength($IV);
	
	        if (96 === $iv_len) 
	            	$J0 = $IV.pack('H*', '00000001');
	        else 
			{
			$s = $this->calcVector($IV);
			if (($s + 64) % 8!=0) print_r('Unable to decrypt or to verify the tag.');
			
			$packed_iv_len = pack('N', $iv_len);
			$iv_len_padding = str_pad($packed_iv_len, 8, "\0", STR_PAD_LEFT);
			$hash_X = $IV.str_pad('', ($s + 64) / 8, "\0").$iv_len_padding;
			$J0 = $this->Hash($H, $hash_X);
	        	}
			
	        $v = $this->calcVector($A);
	        $a_len_padding = $this->addPadding($A);
	
	        return [$J0, $v, $a_len_padding, $H];
		}
		    
	function calcVector($value)
	    	{return (128 * ceil($this->gLength($value) / 128)) - $this->gLength($value);}
    
	function addPadding($value)
	    	{return str_pad(pack('N', $this->gLength($value)), 8, "\0", STR_PAD_LEFT);}
	
	function gLength($x)
	    	{return mb_strlen($x, '8bit') * 8;}
	    
	function SB($s, $X, $init=0)
	    	{
		/** 
		if $s!=null
			bit string consisting of the s LEFT-most bits of the bit string X
		else
			bit string consisting of the s RIGHT-most bits of the bit string X		
		*/
		
		if ($s!=null) $s=$s/8; else $init=$init/8;
			
	        return mb_substr($X, $init, $s, '8bit');
	    	}
	
	function Inc($s_bits, $x)
	    	{
		/**
		output of incrementing the right-most s bits of the bit string X,
		regarded as the binary representation of an integer, by 1 modulo 2s
		
		initial counter block ICB
		*/
	        $lsb = $this->SB(null,$x,-$s_bits);
	        $X = hexdec(bin2hex($lsb)&0xFFFFFFFF)+1;
	        $res = $this->SB($this->gLength($x) - $s_bits, $x).pack('N', $X);
	
	        return $res;
	    	}

	function GMUL($X, $Y)
	    	{
		/**
		6.3 Multiplication Operation on Blocks 
		
		https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf#11-12
		
		Algorithm 1: X Y
		Input:
		blocks X, Y.
		Output:
		block X Y.
		
		Steps:
		1. Let x0x1...x127 denote the sequence of bits in X.
		2. Let Z0 = 0128 and V0 = Y.
		3. For i = 0 to 127, calculate blocks Zi+1 and Vi+1 as follows:
	
			Zi+1 =
		 		if xi = 0;
					Zi
		 		if xi =1.
				 	Zi ^ Vi
	
			Vi+1 = 
				Vi >>1 		if LSB1(Vi) = 0;
		 		Vi >>1 ^ R 	if LSB1(Vi) = 1.
	
		
		4. Return Z128.
		
		As you see is better
		
			Vi+1 = 
				Vi >>1 		
		 		Vi ^ R 		if LSB1(Vi) = 1
		*/
		
		$parts = str_split($X, 4);	
		$V=$Y=array_values(unpack("C*",$Y));
		
		// CONVERT X TO BINARY
		
	  	$c=0;$X="";
	    	while ($c < sizeof($parts)) 
	    		{
	    		$d=unpack("n*",$parts[$c]);
	    		$X.=sprintf("%032b",($d[2]+($d[1] * 0x010000)));
	    		$c++;
	    		}  
	    	
	    	$R      = 0xE1;  //  constant within the algorithm for the block multiplication operation   
	    	$mask   = 0x80;        
	    	$Ztemp=str_split(str_repeat("0",16));     
	          
	    	for($i=0;$i<128;$i++)
		    	{ 
		        if ($X[$i])	          		    
		          	for($j=0;$j<16;$j++) $Ztemp[$j]^=$V[$j]; 	          	
			
			$LSB=$V[15];
			
			// RIGHTSHIFT V
			
			$V[15]>>=1;
			
		        for($j=1;$j<16;$j++)
		            {			
		            if ($V[15-$j] & 1)
		                $V[16-$j] |= 0x80;
				
		            $V[15-$j]>>=1;          
		            }
			
			// CHECK IF LSB TO XOR
				    		
		        if ($LSB & 1)
			        $V[0]^=$R;  
				
		        if(($mask >>=1)==0) $mask=0x80;
		    	}
	
		$Z="";foreach ($Ztemp as $z) $Z.=sprintf("%02x",$z);
		    		    		
	        return pack("H*",$Z);
	    	}
	    	           				
	function GCTR($K, $key_length, $ICB, $X)
	    	{
		/**
		output of the GCTR function for a given block cipher with key K
		applied to the bit string X with an initial counter block ICB		
		*/
		if (empty($X)) return '';
	        $n = (int) ceil($this->gLength($X) / 128);
	        $CB = $Y = [];
	        $CB[1] = $ICB;
	        for ($i = 2; $i <= $n; $i++)		
	            	$CB[$i] = $this->Inc(32, $CB[$i - 1]);
	        	
	        for ($i = 1; $i < $n; $i++) 
			{
			$C = pack("H*",$this->encrypt_ecb($CB[$i]));
			$Y[$i] = $this->SB(128, $X, ($i - 1) * 16) ^ $C;
	        	}
	
	        $Xn = $this->SB(null, $X, ($n - 1) * 128);
		$C = pack("H*",$this->encrypt_ecb($CB[$n]));
	        $Y[$n] = $Xn ^ $this->SB($this->gLength($Xn), $C);
	
	        return implode($Y);
	    	}
	
	function Hash($H, $X)
	    	{
		/**
		output of the GHASH function under the hash subkey H applied to
		the bit string X
		
		$H is the hash subkey
		$X bit string such that len(X) = 128m for some positive integer m
		*/
	        $Y = [];
	        $Y[0] = str_pad('', 16, "\0");
	        $nblocks = (int) (mb_strlen($X, '8bit') / 16);
	        for ($i = 1; $i <= $nblocks; $i++) 
	            $Y[$i] = $this->GMUL($Y[$i - 1] ^ $this->SB(128, $X, ($i - 1) * 16), $H);	        
	
	        return $Y[$nblocks];
	    	} 		    
				
	function encrypt($tocrypt,$A="",$T=null,$taglength=128)
		{
		switch ($this->mode)
			{
			case "ecb": return $this->encrypt_ecb($tocrypt);
			case "cbc": return $this->encrypt_cbc($tocrypt);
			case "ctr": return $this->encrypt_ctr($tocrypt);
			case "cfb": return $this->encrypt_cfb($tocrypt);
			case "ofb": return $this->encrypt_ofb($tocrypt);
			case "gcm": return $this->encrypt_gcm($tocrypt,$A,$T,$taglength);
			}		
		}

	function decrypt($todecrypt,$A="",$T=null,$taglength=128)
		{
		switch ($this->mode)
			{
			case "ecb": return $this->decrypt_ecb($todecrypt);
			case "cbc": return $this->decrypt_cbc($todecrypt);
			case "ctr": return $this->decrypt_ctr(pack("H*",$todecrypt));
			case "cfb": return $this->decrypt_cfb(pack("H*",$todecrypt));
			case "ofb": return pack("H*",$this->encrypt_ofb(pack("H*",$todecrypt)));
			case "gcm": return $this->encrypt_gcm($todecrypt,$A,$T,$taglength);
			}		
		}
										
	function pad($text='')
		{
		$length = strlen($text);
		$padding =  $this->block_size - ($length  % $this->block_size );
		$text = str_pad($text,  $length + $padding, chr($padding) );
		return $text;
		}
		
     	function unpad($text='')
		{			
		$padded = (int) ord($text[strlen($text)-1]);
		$padded = ($padded > $this->block_size ? $this->block_size : $padded);
		$text = substr($text,0,strlen($text)-$padded);
		return rtrim($text, "\0"); // TO AVOID BAD MCRYPT PADDING		
		}		 
	}

<?
/*
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

Pure PHP Rijndael/AES code for 128 to 256 bits block CBC

This is PURE RIJNDAEL IMPLEMENTATION with each step explained

PRETTY SHORT

WITHOUT TABLES

SBOX IS GENERATED

BY DEFAULT 16 BYTE BLOCK SIZE (AES STANDARD) AND CBC, BUT YOU CAN ENCRYPT IN 20,24,28 AND 32 BYTES BLOCK SIZE

KEY CAN BE 128,160,192,224 OR 256 BITS, either hexadecimal or ascii. 

IV SHOULD MATCH BLOCK SIZE (CBC MODE)

USAGE:

$RIJNDAEL_CBC=new RIJNDAEL_CBC;
$RIJNDAEL_CBC->init($key,$iv,$block_size);
$RIJNDAEL_CBC->decrypt($RIJNDAEL_CBC->encrypt($plaintext));

TO IMPLEMENT

Padding Oracle Attack

Also, you normally don't want to use a (rather short) password directly as a key, but instead use a longer passphrase, and hash it with a salt (included with in the message) to derive the key. If you do this, you can also derive the initialization vector from the same two pieces of data (but in a way that they'll be different, using a key derivation function). To avoid brute-forcing your password from the encrypted file, use a slow hash function here (PBKDF-2 or bcrypt).

CTR & other modes

*/

class RIJNDAEL_CBC
	{	
	var $sbox;
	var $Nr;
	var $Nk;
	var $keys;
	var $iv;
	var $Nb;
	var $c;
	var $block_size;
	
	function init($key,$iv="",$block_size=16)
		{		
		if (!ctype_xdigit($key)) $key=bin2hex($key);
		if (!ctype_xdigit($iv))  $iv=bin2hex($iv);
		
		if ((strlen($key)%4)!=0 or (strlen($key)<32 or strlen($key)>64))
			die("Key length should be 16,20,24,28 or 32 bytes");

		if ($iv!="")
			if (strlen($iv)!=$block_size*2) 
				die("Iv length should be $block_size bytes to match CBC block size");
						
		$this->generatesbox();	
		
		$this->Nb = $block_size/4;
		$this->Nk = strlen($key)/8;

		$this->Nr = max($this->Nk, $this->Nb) + 6;
		$this->block_size = $block_size;	
		
		$this->key_expansion($key);
	
		$this->iv = $iv;
		
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
		
		echo "\nRIJNDAEL BLOCK ".($block_size*8)." KEY ".(strlen($key)*4)." ";	
		}
		
	function rOTL8($x,$shift) 
		{		
		// FOR AFFINE TRANSFORMATION
		
		return ($x << $shift) | ($x >> (8 - $shift));	
		}
	
	function generatesbox() 
		{		
		$p = $q = 1;
		
		/* LOOP INVARIANT: p * q == 1 IN THE GALOIS FIELD */
		
		do {
			/* MULTIPLY p BY 3 */
			
			$p ^= $this->multiply($p);
	
			/* DIVIDE q BY 3 = * 0xf6) */
			
			$q^= $q << 1;
			$q^= $q << 2;
			$q^= $q << 4;
			$q^= $q & 0x80 ? 0x09 : 0;
			
			$q %=256;
			
			/* AFFINE TRANSFORMATION */
			
			$xformed = ($q ^ $this->rOTL8($q, 1) ^ $this->rOTL8($q, 2) ^ $this->rOTL8($q, 3) ^ $this->rOTL8($q, 4)) % 256;
	
			$sbox[$p] = $xformed ^ 0x63;
			
		} while ($p != 1);
	
		/* 0 HAS NO INVERSE */
		
		$sbox[0] = 0x63;
		
		$this->sbox=$sbox;
		}

	function multiply($a)
		{
		$hi_bit_set = $a & 0x80;
		$a <<= 1;
		if($hi_bit_set == 0x80) 
			$a ^= 0x1b;
		return $a % 256;	
		}
						
	function sub_byte($byte,$xor="")
		{		
		// PERFORM SBOX SUBSTITUTION
		
		return $this->sbox[$byte]^$xor;
		}

	function sub_word($word)
	    	{   
	        for( $i=0; $i<4; $i++ ){
	            $word[$i] = $this->sbox[$word[$i]];
	        }
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
				        // ROT WORD
					
				        array_push($word,@array_shift($word));	
					
					// SBOX SUBSTITUTION
							      
			                $word = $this->sub_word($word);
					
					// XOR WITH RCON
			
			                $word[0]^=($rcon=$this->multiply($rcon));	
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
			if(($b & 1) == 1) 
				$p ^= $a;
			$a=$this->multiply($a);			
			$b >>= 1;
			}
		
		return ($p % 256);
		}
		
	function decrypt($todecrypt)
		{
		// SAME SBOX, NO INVERSE TABLE
		
		$keys=$this->keys;		
		$DECRYPTED=array();	
		$it=$this->block_size*2;		
		$fiv=$this->iv;	
		
		// COLUMN MULTIPLIERS FOR INVERSE MIXING
		
		$mul=array(14,11,13,9);			
		$todecrypt=str_Split($todecrypt,$it);	
		
		// INVERSE BLOCK DECRYPTING, FIRST IS LAST
						
		for ($i = sizeof($todecrypt)-1; $i >=0 ; $i--)
			{					
			$state=array_values(unpack("C*",pack("H*",$todecrypt[$i])));
			
			// KEY IS LAST FROM ROTKEY
			
			$ky =$keys[$this->Nr];
			$ky2=$keys[$this->Nr-1];	
					
			// ROUNDKEY & UNSUBS-SBOX & UNXORING WITH NEXT KEY
	
			$temp=array();
			
			for ($k1=0;$k1<$this->Nb*4;$k1++)
				{										
				$c = ($k1%4)>$this->c ? 1 : 0;				
				$index=($k1+4*($k1%4+$c))%$this->block_size;				
				$temp[$index]=array_Search($ky[$k1]^$state[$k1],$this->sbox)^$ky2[$index];						
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
							
						$temp[$index]=array_Search($galoism,$this->sbox)^
										$ky[$index];				
						}					
					}
				
				$state=$temp;														
				}
					
			// FINAL BLOCK DECRYPTING 
																			
			if ($i>0)          $ky=array_values(unpack("C*",pack("H*",$todecrypt[$i-1])));	// UNXOR WITH PREVIOUS BLOCK				  	
			else if ($fiv!="") $ky=array_values(unpack("C*",pack("H*",$fiv)));		// UNXOR WITH IV				
			else               $ky=str_split(str_repeat("\0",$this->Nb));
							
			$decrypted_block="";
			
			for ($k1=0;$k1<$this->Nb*4;$k1++)
				{$decrypted_block.=sprintf("%02x",$state[$k1]^$ky[$k1]);}
												
			$DECRYPTED[]=$decrypted_block;
			}
			
		return $this->unpad(pack("H*",implode(array_reverse($DECRYPTED))));
		}
				         				
	function encrypt($tocrypt)
		{		
		$keys = $this->keys;		
		$iv   = $this->iv;					
		$tocrypt=bin2hex($this->pad($tocrypt));	
		$iv = array_values(unpack("C*",pack("H*",$iv)));	

		// COLUMN MULTIPLIERS FOR MIXING GALOIS
		
		$mul = array(2,3,1,1);		
		$ENCRYPTED = "";		
		$it=$this->block_size*2;		
		$tocrypt=str_Split($tocrypt,$it);
					
		for ($i = 0; $i < sizeof($tocrypt); $i++)
			{
			// 16 BYTES BLOCK ENCRYPTING FOR AES, RIJNDAEL SUPPORT 24 OR 32 INDEPENDENT OF KEY LENGTH
					
			$state=array_values(unpack("C*",pack("H*",$tocrypt[$i])));

			// XOR IV IF PRESENT OR IV=LAST ENCRYPTED BLOCK 
					
			if ($iv)
				{
				$temp=array();
				for ($g=0;$g<$this->Nb*4;$g++) {$temp[]=$state[$g] ^ $iv[$g];}	
				$state=$temp;
				}			
			
			/*
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
					
				/*
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
						$c = $k1>$this->c ? 1 : 0;
						$index=($g-$c+$k1*($this->Nb-1))%$this->Nb;
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
						for ($k2=0;$k2<4;$k2++)
							{$t^=$this->galois_multiplication($temp0[$k2][$k3],$mul[($k2+$k1*3)%4]);}
						
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
					$c = $k1>$this->c ? 1 : 0;
					$index=($g-$c+$k1*($this->Nb-1))%$this->Nb;					
					$k0[$k1][$index]=$this->sub_byte($keys[$ROUND-1][$k1+$g*4]^$state[$k1+$g*4]);
					}
				}
			
			// ROUNDKEY TO GET FINAL BLOCK ENCRYPTING
			
			$enc="";
						
			for ($k2=0;$k2<$this->Nb;$k2++)
				{
				for ($k1=0;$k1<4;$k1++)
					{$enc.=sprintf("%02x",$k0[$k1][$k2]^$keys[$ROUND][$k2*4+$k1]);}
				}
			
			// ENC IS ENCRYPTION OF CURRENT BLOCK
				
			$ENCRYPTED.=$enc;
						
			// XOR NEXT BLOCK WITH THIS ENCRYPTED BLOCK
			
			$iv=array_values(unpack("C*",pack("H*",$enc)));
			}
			
		return $ENCRYPTED;
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

function check()
	{
	$text="En un lugar de la Mancha, de cuyo nombre no quiero acordarme...";
	$key32="4f6bdaa39e2f8cb07f5e722d9edef314";
	$key40=$key32.substr($key32,24);
	$key48=$key32.substr($key32,16);
	$key56=$key32.substr($key32,8);
	$key64=$key32.$key32;
	
	$keys=array("k32"=>$key32,"k40"=>$key40,"k48"=>$key48,"k56"=>$key56,"k64"=>$key64);
	$x=new RIJNDAEL_CBC;
	
	foreach ($keys as $nkey=>$key)
		{
		for($k=16;$k<=32;$k+=4)
			{
			$iv=substr($key64,0,$k*2);
			$x->init($key,$iv,$k); 
			echo ($r=$x->encrypt($text))."\n";
			echo $x->decrypt($r)."\n";
			}
		}
	}
	
check();			
			

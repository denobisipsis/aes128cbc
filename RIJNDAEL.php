<?
/*
*  Copyright 2018 denobisipsis
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

BY DEFAULT 16 BYTE BLOCK SIZE (AES STANDARD) AND CBC, BUT YOU CAN ENCRYPT/DECRYPT IN 20,24,28 AND 32 BYTES BLOCK SIZE

KEY CAN BE 128,192 OR 256 BITS, either hexadecimal or ascii. 

IV SHOULD MATCH BLOCK SIZE (CBC MODE)

USAGE:

$RIJNDAEL_CBC=new RIJNDAEL_CBC;
$RIJNDAEL_CBC->init($key,$iv,$block_size);
$RIJNDAEL_CBC->decrypt($RIJNDAEL_CBC->encrypt($plaintext));
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
		
		if (strlen($key)!=32 and strlen($key)!=48 and strlen($key)!=64)
			die("Key length should be 16,24 or 32 bytes");

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
		$hi_bit_set = ($a & 0x80);
		$a <<= 1;
		if($hi_bit_set == 0x80) 
			$a ^= 0x1b;
		return $a % 256;	
		}
						
	function sub_byte($byte,$xor="")
		{		
		// PERFORM SBOX SUBSTITUTION
		
		return sprintf("%02x",$this->sbox[16*hexdec($byte[0])+hexdec($byte[1])]^$xor);
		}

	function sub_word($word)
	    	{   
	        for( $i=0; $i<4; $i++ ){
	            $word[$i] = hexdec($this->sub_byte($word[$i]));
	        }
	        return $word;
	    	}

	function key_expansion($key)
	    	{
		// COMPUTE ALL ROUND KEYS
			
	        $key_schedule=array();
		$key=str_split($key,2);
		
	        for($i=0;  $i < $this->Nk; $i++)
			{$key_schedule[$i] = array(($key[4*$i]),($key[4*$i+1]),($key[4*$i+2]),($key[4*$i+3]));}
	
	        $i = $this->Nk;
		
		// RCON IS CALCULATED ON THE FLY
		
		$rcon=array(0x8d,0,0,0);
		
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
					
			                $rcon = array(($rcon[0]<<1) ^ (hexdec("11b") & -($rcon[0]>>7)),0,0,0);
			
			                for($j=0; $j<4; $j++)
						{$word[$j] = sprintf("%02x",$word[$j]^$rcon[$j]);}	
			            }
			    elseif ($this->Nk > 6 && $i % $this->Nk == 4)
				    {			    	
			                $word = $this->sub_word($word);
			                for($j=0; $j<4; $j++)
						{$word[$j] = sprintf("%02x",$word[$j]);}
			            }
				    
			    // XORING REMAINING WORDS WITH PREVIOUS
			    
		            for($j=0; $j<4; $j++)
			    	{$word[$j] = sprintf("%02x",hexdec($word[$j])^hexdec($key_schedule[$i-$this->Nk][$j]));}
	
		            $key_schedule[$i] = $word;
		            $i++;
	        	}
		    
		    // REGROUP WORDS TO RETURN KEYS
		    
		    $key_expansion=Array();
		    
		    for ($k=0;$k<sizeof($key_schedule)-1;$k+=$this->Nb)
		    	{
			    $v2="";
			    for ($j=$k;$j<($this->Nb+$k);$j++)
				    {$v2.=implode($key_schedule[$j]);}
			    $key_expansion[]=$v2;	
			}
			
		$this->keys=$key_expansion;
		}			
		
	function galois_multiplication($a,$b="") 
		{
		// FOR COLUMNS MIXING
		
		// reference https://www.samiam.org/galois.html
		
		$p = 0;$a=hexdec($a);

		for($c = 0; $c < 8; $c++) 
			{
			if(($b & 1) == 1) 
				$p ^= $a;
			$a=$this->multiply($a);			
			$b >>= 1;
			}
		
		return ($p % 256);
		}

	function reord($arr)
		{
		foreach ($arr as $k) ksort($k);
		
		$k=array();
		for ($k1=0;$k1<$this->Nb;$k1++)
			{	
			for ($k2=0;$k2<4;$k2++)
				{$k[$k1][$k2]=$arr[$k2][$k1];}		
			}
		return $k;
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
			$state=str_split($todecrypt[$i],8);
			
			// KEY IS LAST FROM ROTKEY
			
			$ky=str_split($keys[$this->Nr],8);
						
			// ROUNDKEY
			
			$enc=array();
				
			for ($k2=0;$k2<$this->Nb;$k2++)
				{
				$v=str_split($state[$k2],2);
				
				for ($k1=0;$k1<4;$k1++)
					{					
					$c = $k1>$this->c ? 1 : 0;
		
					$enc[$k1][($k2+$c+$k1) % $this->Nb]=sprintf("%02x",hexdec(substr($ky[$k2],2*$k1,2))^hexdec($v[$k1]));					
					}			
				}
			
			$k=$this->reord($enc);
			
			// UNSUBS-SBOX & UNXORING WITH NEXT KEY
			
			$ky=str_split($keys[$this->Nr-1],8);
																
			for ($k2=0;$k2<$this->Nb;$k2++)
				{
				for ($k1=0;$k1<4;$k1++)
					{$enc[$k1][$k2]=sprintf("%02x",array_Search(hexdec($k[$k2][$k1]),$this->sbox)^hexdec(substr($ky[$k2],2*$k1,2)));}
				}
				
			$v2=$this->reord($enc);
			
			FOR ($ROUND=$this->Nr-2;$ROUND>=0;$ROUND--)
				{
				// FIRST UNMIX COLUMNS & UNSHIFT & UNSBOX
				
				$state=Array();	
						
				for ($k1=0;$k1<4;$k1++)
					{
					for ($k3=0;$k3<$this->Nb;$k3++)
						{								
						$temp="";					
			
						for ($k2=0;$k2<4;$k2++)
							{$temp^=$this->galois_multiplication($v2[$k3][$k2],$mul[($k2+$k1*3)%4]) % 256;}
						
						$c = $k1>$this->c ? 1 : 0;
						$state[$k1][($k3+$c+$k1) % $this->Nb]=sprintf("%02x",array_Search($temp,$this->sbox));
						}
					}				
				
				$v2=$this->reord($state);
				
				// SECOND UNXORING WITH KEY
				
				$ky=str_split($keys[$ROUND],8);	
				
				for ($k1=0;$k1<$this->Nb;$k1++)
					{	
					for ($k2=0;$k2<4;$k2++)
						{$v2[$k1][$k2]=sprintf("%02x",hexdec($v2[$k1][$k2])^hexdec(substr($ky[$k1],2*$k2,2)));}		
					}											
				}
					
			// FINAL BLOCK DECRYPTING 
																			
			if ($i>0) $ky=str_split($todecrypt[$i-1],8);	// UNXOR WITH PREVIOUS BLOCK
				
			else if ($fiv!="") $ky=str_split($fiv,8);	// UNXOR WITH IV
				
			else    $ky=str_split(str_repeat("\0",$this->Nb));
							
			$decrypted_block="";
			
			for ($k1=0;$k1<$this->Nb;$k1++)
				{	
				for ($k2=0;$k2<4;$k2++)
					{$decrypted_block.=sprintf("%02x",hexdec($v2[$k1][$k2])^hexdec(substr($ky[$k1],2*$k2,2)));}		
				}
												
			$DECRYPTED[]=$decrypted_block;
			}
			
		return $this->unpad(pack("H*",implode(array_reverse($DECRYPTED))));
		}
				         				
	function encrypt($tocrypt)
		{		
		$keys = $this->keys;
		$iv   = $this->iv;
					
		$tocrypt=bin2hex($this->pad($tocrypt));		

		// COLUMN MULTIPLIERS FOR MIXING GALOIS
		
		$mul = array(2,3,1,1);
		
		$ENCRYPTED = "";
		
		$it=$this->block_size*2;
					
		for ($i = 0; $i < strlen($tocrypt); $i+= $it)
			{
			// 16 BYTES BLOCK ENCRYPTING FOR AES, RIJNDAEL SUPPORT 24 OR 32 INDEPENDENT OF KEY LENGTH
					
			$state=str_split(substr($tocrypt,$i,$it),8);

			// XOR IV IF PRESENT OR IV=LAST ENCRYPTED BLOCK 
					
			if ($iv)
				{
				$iv = str_split($iv,8);$v="";
				for ($g=0;$g<$this->Nb;$g++)
					{
					if (@($state[$g])) $v.=sprintf("%08x",hexdec($state[$g]) ^ hexdec($iv[$g]));
					else		   $v.=$iv[$g];							
					}	
				$state=str_split($v,8);
				}
													
			$ky=str_split($keys[0],8);
			
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
				for ($g=0;$g<$this->Nb;$g++)
					{
					// XOR WITH ROUND KEY
					
					$v=str_split(sprintf("%08x",hexdec($state[$g]) ^ hexdec($ky[$g])),2);	
									
					// SBOX SUBSTITUTION AND ROWS SHIFTING
					
					/*
					Table 2: Shift offsets for different block lengths.
					
							4 1 2 3
							6 1 2 3
							8 1 3 4	
							
					I HAVE IMPLEMENTED THIS THROUGH C VARIABLE. BY DEFAULT SHIFTING IS STANDARD 0,1,2,3				
					*/
					
					for ($k1=0;$k1<4;$k1++)
						{						
						$c = $k1>$this->c ? 1 : 0;						
	
						$k0[$k1][($g-$c+$k1*($this->Nb-1))%$this->Nb]=$this->sub_byte($v[$k1]);
						}
					}
					
				// REORD ARRAY
				
				$st="";foreach ($k0 as $k) {ksort($k);$st.=implode($k);} $st=str_split($st,2);				
				
				// MIX COLUMNS WITH GALOIS MULTIPLICATION 	
				
				for ($k1=0;$k1<4;$k1++)
					{
					for ($k3=0;$k3<$this->Nb;$k3++)
						{								
						$temp="";		
						for ($k2=0;$k2<4;$k2++)
							{$temp^=$this->galois_multiplication($st[$k3+$this->Nb*$k2],$mul[($k2+$k1*3)%4]);}
						
						$k4[$k3][$k1]=sprintf("%02x",$temp);
						}
					}			
				
				// K4 IS THE MIX-STATE MATRIX
				
				$state=array();foreach ($k4 as $k) $state[]=implode($k);				
				
				// ROT KEY WITH SBOX
				
				$ky=str_split($keys[$ROUND],8);
				}
			
			// FINAL ROUND NO MIXING. FIRST XORING AND SUBSBOX, SECOND ROUNDKEY	
				
			for ($g=0;$g<$this->Nb;$g++)
				{						
				$v=str_split(sprintf("%08x",hexdec($state[$g]) ^ hexdec($ky[$g])),2);
			
				for ($k1=0;$k1<4;$k1++)
					{
					$c = $k1>$this->c ? 1 : 0;
					
					$k0[$k1][($g-$c+$k1*($this->Nb-1))%$this->Nb]=$this->sub_byte($v[$k1]);
					}
				}
			
			$ky=str_split($keys[$ROUND],8);
			
			// ROUNDKEY TO GET FINAL BLOCK ENCRYPTING
			
			$enc="";
						
			for ($k2=0;$k2<$this->Nb;$k2++)
				{
				for ($k1=0;$k1<4;$k1++)
					{$enc.=sprintf("%02x",hexdec($k0[$k1][$k2])^hexdec(substr($ky[$k2],2*$k1,2)));}
				}
			
			// ENC IS ENCRYPTION OF CURRENT BLOCK
				
			$ENCRYPTED.=$enc;
						
			// XOR NEXT BLOCK WITH THIS ENCRYPTED BLOCK
			
			$iv=$enc;
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
	$key48=$key32.substr($key32,16);
	$key64=$key32.$key32;
	
	$keys=array("k32"=>$key32,"k48"=>$key48,"k64"=>$key64);
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
			

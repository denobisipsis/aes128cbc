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

Pure PHP Rijndael/AES code for 128 bits block CBC

This is PURE RIJNDAEL IMPLEMENTATION with each step explained

PRETTY SHORT

WITHOUT TABLES

SBOX IS GENERATED

FIXED TO 16 BYTE BLOCK SIZE (AES STANDARD) AND CBC

KEY CAN BE 128,192 OR 256 BITS, either hexadecimal or ascii. If one or another is determined by the key length

IV always 128

USAGE:

$AES=new aes128cbc;
$AES->init($key,$iv);
$AES->decrypt($AES->encrypt($plaintext));
*/

class aes128cbc
	{	
	var $sbox;
	var $Nr;
	var $Nk;
	var $keys;
	var $iv;
	
	function init($key,$iv="")
		{
		if (!ctype_xdigit($key)) $key=bin2hex($key);
		if (!ctype_xdigit($iv))  $iv=bin2hex($iv);
		
		if (strlen($key)!=32 and strlen($key)!=48 and strlen($key)!=64)
			die("Key length should be 16,24 or 32 bytes");

		if ($iv!="")
			if (strlen($iv)!=32) // for block size 128
				die("Iv length should be 16 bytes");
						
		$this->generatesbox();	
		
		$this->Nk = strlen($key)/8;
		$this->Nr = $this->Nk+6;
			
		$this->key_expansion($key);
		$this->iv = $iv;
		
		echo "\nRIJNDAEL BLOCK 128 KEY ".(strlen($key)*4)."\n";	
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
		
		return sprintf("%02x",$this->sbox[hexdec($byte)]^$xor);
		}

	function sub_word($word)
	    	{   
	        for( $i=0; $i<4; $i++ ){
	            $word[$i] = $this->sbox[hexdec($word[$i])];
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
		
	        while ($i < 4 * ($this->Nr+1) )
			{
		            $word = $key_schedule[$i-1];
			    	    
		            if ($i % $this->Nk == 0)
				    {  	
				        // ROT WORD
					
				        array_push($word,@array_shift($word));	
					
					// SBOX SUBSTITUTION
							      
			                $word = $this->sub_word($word);
					
					// XOR WITH RCON
					
			                $rcon = array($this->multiply($rcon[0]),0,0,0);
			
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
		    
		    for ($k=0;$k<sizeof($key_schedule)-1;$k+=4)
		    	{
			    $v2="";
			    for ($j=$k;$j<(4+$k);$j++)
				    {
				    $v2.=implode($key_schedule[$j]);				    
				    }
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

	function decrypt($todecrypt)
		{
		// SAME SBOX, NO INVERSE TABLE
		
		$keys=$this->keys;
		
		// COLUMN MULTIPLIERS FOR INVERSE MIXING
		
		$mul=array(14,11,13,9);
		
		$DECRYPTED=array();
	
		$todecrypt=str_Split($todecrypt,32);
		
		$fiv=$this->iv;;						
		
		// INVERSE BLOCK DECRYPTING, FIRST IS LAST
						
		for ($i = sizeof($todecrypt)-1; $i >=0 ; $i--)
			{
			// 16 BYTES BLOCK DECRYPTING
					
			$state=str_split($todecrypt[$i],8);
			
			// KEY IS LAST FROM ROTKEY
			
			$ky=str_split($keys[$this->Nr],8);
			
			$v="";$enc=array();
			
			// ROUNDKEY
				
			for ($k2=0;$k2<4;$k2++)
				{
				$v=str_split($state[$k2],2);
				
				for ($k1=0;$k1<4;$k1++)
					{$enc[]=sprintf("%02x",hexdec(substr($ky[$k2],2*$k1,2))^hexdec($v[$k1]));}
				}
			
			// REORD ARRAY
			
			$v=$this->reordarray($enc);
	
			$ky=str_split($keys[$this->Nr-1],8);
			
			// UNSUBS-SBOX
			
			$v2="";						
			for ($k2=0;$k2<4;$k2++)
				{
				$w=str_split($v[$k2],2);
				
				$temp="";
				for ($k1=0;$k1<4;$k1++)
					{$temp.=sprintf("%02x",array_Search(hexdec($w[$k1]),$this->sbox));}						
				
				// UNXORING
				
				$v2.=sprintf("%08x",hexdec($ky[$k2]) ^ hexdec($temp));
				}
	
			$st=str_split($v2,2);
			
			FOR ($ROUND=$this->Nr-2;$ROUND>=0;$ROUND--)
				{
				// FIRST UNMIX COLUMNS 
	
				for ($k1=0;$k1<4;$k1++)
					{
					for ($k3=0;$k3<4;$k3++)
						{								
						$temp="";					
			
						for ($k2=0;$k2<4;$k2++)
							{$temp^=$this->galois_multiplication($st[$k3*4+$k2],$mul[($k2+$k1*3)%4]) % 256;}
						
						$k4[$k3][$k1]=sprintf("%02x",$temp);
						}
					}			
				
				$state=array();foreach ($k4 as $k) $state[]=implode($k);
										
				// SECOND UNSUBS-SBOX
				
				$temp=Array();				
				for ($g=0;$g<4;$g++)
					{
					$v=str_split($state[$g],2);
				
					for ($k1=0;$k1<4;$k1++)
						{$temp[]=sprintf("%02x",array_Search(hexdec($v[$k1]),$this->sbox));}
					}
					
				$v=$this->reordarray($temp);
				
				// THIRD UNXORING WITH KEY
				
				$ky=str_split($keys[$ROUND],8);
				
				$v2="";	
				for ($k=0;$k<4;$k++)
					{$v2.=sprintf("%08x",hexdec($v[$k])^hexdec($ky[$k]));}
	
				$st=str_split($v2,2);
				}
				
			// FINAL BLOCK DECRYPTING 
																			
			if ($i>0)	   // UNXOR WITH PREVIOUS BLOCK
						
				$ky=str_split($todecrypt[$i-1],8);
				
			else if ($fiv!="") // UNXOR WITH IV
					
				$ky=str_split($fiv,8);
				
			else    $ky=array(0,0,0,0);
				
			$v=str_split($v2,8);$v2="";
			
			for ($k=0;$k<4;$k++)
				{$v2.=sprintf("%08x",hexdec($v[$k])^hexdec($ky[$k]));}
							
			$DECRYPTED[]=$v2;
			}
			
		return $this->unpad(pack("H*",implode(array_reverse($DECRYPTED))));
		}
				         				
	function encrypt($tocrypt)
		{		
		$keys=$this->keys;
		$iv=$this->iv;
					
		$tocrypt=bin2hex($this->pad($tocrypt));		
		
		// COLUMN MULTIPLIERS FOR MIXING GALOIS
		
		$mul=array(2,3,1,1);
		
		$ENCRYPTED="";
		
		$it=32;
					
		for ($i = 0; $i < strlen($tocrypt); $i+= $it)
			{
			// 16 BYTES BLOCK ENCRYPTING FOR AES, RIJNDAEL SUPPORT 24 OR 32 INDEPENDENT OF KEY LENGTH
					
			$state=str_split(substr($tocrypt,$i,$it),8);
			
			// XOR IV IF PRESENT OR IV=LAST ENCRYPTED BLOCK 
					
			if ($iv)
				{
				$iv=str_split($iv,8);$v="";
				for ($g=0;$g<4;$g++)
					{
					$v.=sprintf("%08x",hexdec($state[$g]) ^ hexdec($iv[$g]));						
					}	
				$state=str_split($v,8);
				}
													
			$ky=str_split($keys[0],8);									    			
				
			FOR ($ROUND=1;$ROUND<$this->Nr;$ROUND++)
				{								
				for ($g=0;$g<4;$g++)
					{
					// XOR WITH ROUND KEY
					
					$v=str_split(sprintf("%08x",hexdec($state[$g]) ^ hexdec($ky[$g])),2);
									
					// SBOX SUBSTITUTION AND ROWS SHIFTING
					
					for ($k1=0;$k1<4;$k1++)
						{$k0[$k1][($g+$k1*3)%4]=$this->sub_byte($v[$k1]);}	
					}				
				
				// REORD ARRAY
				
				$st="";foreach ($k0 as $k) {ksort($k);$st.=implode($k);} $st=str_split($st,2);				
				
				// MIX COLUMNS WITH GALOIS MULTIPLICATION 	
				
				for ($k1=0;$k1<4;$k1++)
					{
					for ($k3=0;$k3<4;$k3++)
						{								
						$temp="";		
						for ($k2=0;$k2<4;$k2++)
							{
							$temp^=$this->galois_multiplication($st[$k3+4*$k2],$mul[($k2+$k1*3)%4]);
							}
						
						$k4[$k3][$k1]=sprintf("%02x",$temp);
						}
					}			
				
				// K4 IS THE MIX-STATE MATRIX
				
				$state=array();foreach ($k4 as $k) $state[]=implode($k);
				
				// ROT KEY WITH SBOX
				
				$ky=str_split($keys[$ROUND],8);
				}
				
			// FINAL ROUND NO MIXING. FIRST XORING AND SUBSBOX, SECOND ROUNDKEY	
				
			for ($g=0;$g<4;$g++)
				{						
				$v=str_split(sprintf("%08x",hexdec($state[$g]) ^ hexdec($ky[$g])),2);
			
				for ($k1=0;$k1<4;$k1++)
					{
					$k0[$k1][($g+$k1*3)%4]=$this->sub_byte($v[$k1]);
					}
				}
			
			$ky=str_split($keys[$ROUND],8);
			
			// ROUNDKEY TO GET FINAL BLOCK ENCRYPTING
			
			$enc="";			
			for ($k2=0;$k2<4;$k2++)
				{
				for ($k1=0;$k1<4;$k1++)
					{
					$enc.=sprintf("%02x",hexdec($k0[$k1][$k2])^hexdec(substr($ky[$k2],2*$k1,2)));
					}
				}
			
			// ENC IS ENCRYPTION OF CURRENT BLOCK
				
			$ENCRYPTED.=$enc;
						
			// XOR NEXT BLOCK WITH THIS ENCRYPTED BLOCK
			
			$iv=$enc;
			}
			
		return $ENCRYPTED;
		}
	
	function reordarray($temp)
		{
		$v=$temp[0];
		for ($k=0;$k<15;$k++)
			{$v.=$temp[(-(3*($k+1)%16)+16) % 16];}
		return str_split($v,8);	
		}

	function pad($text='')
		{
		$length = strlen($text);
		$padding =  16 - ($length  % 16 );
		$text = str_pad($text,  $length + $padding, chr($padding) );
		return $text;
		}
		
     	function unpad($text='')
		{			
		$padded = (int) ord($text[strlen($text)-1]);
		$padded = ($padded > 16 ? 16 : $padded);
		$text = substr($text,0,strlen($text)-$padded);
		return rtrim($text, "\0");		
		}
	}
	
$x=new aes128cbc;
	
$text="En un lugar de la Mancha, de cuyo nombre no quiero acordarme...";
$key="4f6bdaa39e2f8cb07f5e722d9edef314";
	
$x->init($key,$key); 
echo ($r=$x->encrypt($text))."\n";
echo $x->decrypt($r)."\n";
?>
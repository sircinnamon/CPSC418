import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.math.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.math.BigInteger;
import java.util.Random;

public class CryptoUtil
{
	public static final int KEYSIZE = 1024;
	public static final int CERTAINTY = 1; //1 = 50%, 2 = 75%
	public static final int BLOCKSIZE = 108; //+20 = 128 encrypts evenly
	public static final boolean FAST = false;

	public static byte[] wrapMsg(byte[] msg, SecretKey key) throws Exception
	{
		//adds hash and encrypts
		byte[] hash = hmac_sha1(msg, key);
		msg = concatMsgHash(msg, hash);
		return aes_encrypt(msg, key);
	}

	public static String unwrapMsg(byte[] bytes, SecretKey key) throws Exception
	{
		//decrypts, removes and verifies hash, returns as a string
		return new String(unwrapMsgBytes(bytes, key));
	}
	public static byte[] unwrapMsgBytes(byte[] bytes, SecretKey key) throws Exception
	{
		//decrypts, removes and verifies hash, returns the bytes
		bytes = aes_decrypt(bytes, key);
		byte[] msg = new byte[bytes.length - 20];
		byte[] hash = new byte[20];
		System.arraycopy(bytes, 0, msg, 0, msg.length);
		System.arraycopy(bytes, msg.length, hash, 0, 20);
		if(!(Arrays.equals(hash, hmac_sha1(msg, key))))
		{
			throw new Exception("Invalid hash");
		}
		return msg;
	}

	public static SecretKey genSeededKey(byte[] seed) throws Exception
	{
		SecureRandom secRan = SecureRandom.getInstance("SHA1PRNG");
		secRan.setSeed(seed);
		KeyGenerator key_gen = KeyGenerator.getInstance("AES");
		key_gen.init(128, secRan);
		SecretKey sec_key = key_gen.generateKey();
		return sec_key;

		//get key material in raw form
		//raw = sec_key.getEncoded();
		//return sec_key_spec = new SecretKeySpec(raw, "AES");
	}

	public static BigInteger genSophieGermain()
	{
		//generate 1023 bit random prime q
		//check if p = 2q + 1 is prime
		//repeat until true
		//return p
		BigInteger q;
		BigInteger p;
		Random r = new Random();
		do
		{
			q = new BigInteger(KEYSIZE-1, CERTAINTY ,r);
			p = (q.shiftLeft(1)).add(q.ONE);
			if(FAST)
			{
				p = new BigInteger("953");
			}
			//p = (q.add(q)).add(q.ONE);n
			//System.out.println(p.toByteArray()[0]);
			//System.out.println("\np "+p.bitLength());
			//System.out.println("\n~q" + p.subtract(p.ONE).shiftRight(1));
			//System.out.println("\nq "+q.toByteArray().length);

		}while(!p.isProbablePrime(CERTAINTY));
		return p;
	}

	public static BigInteger findPrimitiveRoot(BigInteger p)
	{
		//find primitive root g mod p
		BigInteger g;
		BigInteger q = p.subtract(p.ONE).shiftRight(1);
		Random r = new Random();

		do
		{
			do
			{
				g = new BigInteger(KEYSIZE, r);
				if(FAST)
				{
					g = new BigInteger("257");
				}
				//System.out.println("\ng " + g.bitLength() + " -> " +  g.toByteArray().length);
				//System.out.println("\n+-" + g.compareTo(p.subtract(p.ONE)));
				//System.out.println(g.compareTo(p.subtract(p.ONE)) != -1);
			}while(g.compareTo(p.subtract(p.ONE)) != -1);
			//g^q != 1 (mod p)
			//q = p-1/2
			//System.out.println("\n%" + modExponent(g,q,p));
		}while((p.ONE).equals(modExponent(g,q,p)));
		return g;
	}

	public static BigInteger genRandomExponent(BigInteger p)
	{
		//get random exponent x such that 0 <= x <= p-2
		Random r = new Random();
		BigInteger x;
		do
		{
			x = new BigInteger(KEYSIZE, r);
			if(FAST)
			{
				x = new BigInteger("7");
			}
		}while(x.compareTo(p.subtract(p.ONE)) != -1);
		return x;
	}

	public static BigInteger modExponent(BigInteger g, BigInteger x, BigInteger p)
	{
		//get g^x mod p
		return g.modPow(x, p);
	}

	public static SecretKey genSessionKey() throws Exception
	{
		//generates a fully random 128 bit session key
		SecureRandom secRan = SecureRandom.getInstance("SHA1PRNG");
		//secRan.setSeed(seed);
		KeyGenerator key_gen = KeyGenerator.getInstance("AES");
		key_gen.init(128, secRan);
		SecretKey sec_key = key_gen.generateKey();
		return sec_key;
	}

	public static SecretKey buildSessionKey(byte[] keyBytes) throws Exception
	{
		//take the encoded bits of one key and reconstitute it
		SecretKey sec_key = new SecretKeySpec(keyBytes, "AES");
		return sec_key;
	}

	public static byte[] hmac_sha1(byte[] in_data, SecretKey key) throws Exception{
		byte[] result = null;

		try{
			Mac theMac = Mac.getInstance("HMACSHA1");
			theMac.init(key);
			//create the hash
			result = theMac.doFinal(in_data);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return result;
	}

	public static byte[] aes_encrypt(byte[] data_in, SecretKey sec_key) throws Exception{
		byte[] out_bytes = null;
		Cipher sec_cipher = null;
		SecretKeySpec sec_key_spec = new SecretKeySpec(sec_key.getEncoded(), "AES");
		try{
			//set cipher object to encrypt mode
			sec_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");	
			sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec, new IvParameterSpec(new byte[16]));
			//create ciphertext
			out_bytes = sec_cipher.doFinal(data_in);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return out_bytes;
	}

	public static byte[] aes_decrypt(byte[] data_in, SecretKey sec_key) throws Exception{
		byte[] decrypted = null;
		String dec_str = null;
		Cipher sec_cipher = null;
		SecretKeySpec sec_key_spec = new SecretKeySpec(sec_key.getEncoded(), "AES");
		try{
			sec_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");	
			//set cipher to decrypt mode
			sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec, new IvParameterSpec(new byte[16]));

			//do decryption
			decrypted = sec_cipher.doFinal(data_in);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return decrypted;
	}

	public static byte[] concatMsgHash(byte[] msg, byte[] hash)
	{
		//concatenate a byte arrays with another
		int totalLen = msg.length + hash.length;
		byte[] total = new byte[totalLen];
		System.arraycopy(msg, 0, total, 0, msg.length);
		System.arraycopy(hash, 0, total, msg.length, hash.length);

		return total;
	}

		/*
     * Converts a byte array to hex string
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        } 
        return buf.toString();
    }
    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     * this code from http://java.sun.com/j2se/1.4.2/docs/guide/security/jce/JCERefGuide.html#HmacEx
     */
    public static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    public static byte[] formatByteArr(byte[] bytes)
    {
    	byte[] ret = new byte[KEYSIZE/8 + 1];
    	System.arraycopy(bytes, 0, ret, ret.length-bytes.length, bytes.length);
    	{
    		for(int i = 0; i < ret.length-bytes.length; i++)
    		{
    			ret[i] = 0;
    		}
    	}
    	return ret;
    }
}

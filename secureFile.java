import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
/*
Created using code from demo code in CryptoDemo.java
secureFile.java
Riley Lahd
10110725

This code will:
take in a file and a seed
create and ouput file named "Secure" + source file name
compute a SHA1 hash of the input - not HMAC?
Use seed to generate a key
AES-128 CBC encrypt input and store in output
AES-128 CBC encrypt hash and append to output
*/
public class secureFile{
	private static KeyGenerator key_gen = null;
	private static SecretKey sec_key = null;
	private static byte[] raw = null;
	private static SecretKeySpec sec_key_spec = null;
	private static Cipher sec_cipher = null;

	private static SecureRandom secRan = null;

	public static void main(String args[]) throws Exception{
		FileInputStream in_file = null;
		FileOutputStream out_file = null;
		byte[] sha_hash = null;
		byte[] aes_ciphertext = null;
		byte[] seedByte = null;
		String decrypted_str = new String();
		int read_bytes = 0;
		String seed = null;

		try{
			//store seed, open file and create output file
			seed = args[1];
			seedByte = seed.getBytes();
			File file = new File("Secure" + args[0]);
			file.createNewFile();
			in_file = new FileInputStream(args[0]);
			out_file = new FileOutputStream("Secure" + args[0]);

			//read file into a byte array
			byte[] msg = new byte[in_file.available()];
			read_bytes = in_file.read(msg);
			//System.out.println("input: " + new String(msg));

			//SHA-1 Hash
			sha_hash = sha1_hash(msg);

			//create a full array of things to be encrypted out of msg and hash
			byte[] fullMsg = concatMsgHash(msg, sha_hash);
			//print out hash in hex
			//System.out.println("SHA-1 Hash: " + toHexString(sha_hash));

			//convert seed to byte array
			//create SecureRandom w/ a seed byte array
			//generate 128 bit key using SecureRandom PRNG
			secRan = SecureRandom.getInstance("SHA1PRNG");
			secRan.setSeed(seedByte);
			key_gen = KeyGenerator.getInstance("AES");
			key_gen.init(128, secRan);
			sec_key = key_gen.generateKey();

			//get key material in raw form
			raw = sec_key.getEncoded();
			sec_key_spec = new SecretKeySpec(raw, "AES");

			//create the cipher object that uses AES as the algorithm
			//Use AES/CBC/PKCS5PADDING 
			sec_cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			//do AES encryption
			//System.out.println("Full Msg Length " + fullMsg.length);
			//System.out.println("Full Msg: " + new String(fullMsg));
			aes_ciphertext = aes_encrypt(fullMsg);
			//System.out.println("Ciphertext Length " + aes_ciphertext.length);
			//System.out.println("Ciphertext Bytes: " + toHexString(aes_ciphertext));
			out_file.write(aes_ciphertext);
			out_file.close();
		}
		catch(Exception e){
			System.out.println(e);
		}
		finally{
			if (in_file != null){
				in_file.close();
			}
			if(out_file != null){
				out_file.close();
			}
		}
	}

	public static byte[] sha1_hash(byte[] input_data) throws Exception{
		byte[] hashval = null;
		try{
			//create message digest object
			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			
			//make message digest
			hashval = sha1.digest(input_data);
		}
		catch(NoSuchAlgorithmException nsae){
			System.out.println(nsae);
		}
		return hashval;
	}

	public static byte[] aes_encrypt(byte[] data_in) throws Exception{
		byte[] out_bytes = null;
		try{
			//set cipher object to encrypt mode
			sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec, new IvParameterSpec(new byte[16]));

			//create ciphertext
			out_bytes = sec_cipher.doFinal(data_in);
		}
		catch(Exception e){
			System.out.println(e);
		}
		return out_bytes;
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
}
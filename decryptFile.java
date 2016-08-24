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
decryptFile.java
Riley Lahd
10110725

This code will:
take in a file and a seed
create and ouput file named "Decrypted" + source file name
Use seed to generate a key
AES-128 CBC decrypt input and store in output
Compute SHA1 hash of decrypted data without hash append
compare generated Hash to Hash appended on file
*/
public class decryptFile{
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
			File file = new File("Decrypted" + args[0]);
			file.createNewFile();
			in_file = new FileInputStream(args[0]);
			out_file = new FileOutputStream("Decrypted" + args[0]);

			//read file into a byte array
			byte[] msg = new byte[in_file.available()];
			read_bytes = in_file.read(msg);

			secRan = SecureRandom.getInstance("SHA1PRNG");
			secRan.setSeed(seedByte);
			key_gen = KeyGenerator.getInstance("AES");
			key_gen.init(128, secRan);
			sec_key = key_gen.generateKey();

			//get key material in raw form
			raw = sec_key.getEncoded();
			sec_key_spec = new SecretKeySpec(raw, "AES");

			//create the cipher object that uses AES as the algorithm
			// use AES/CBC/PKCS5PADDING 
			sec_cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

			byte[] decrypted = aes_decrypt(msg);
			decrypted_str = new String(decrypted);
			//split hash off the end - last 160 bits - 20 bytes
			byte[] decryptedHash = new byte[20];
			byte[] decryptedMsg = new byte[decrypted.length-20];
			//move message to one array and decrypted hash to another
			System.arraycopy(decrypted, 0, decryptedMsg, 0, decryptedMsg.length);
			System.arraycopy(decrypted, (decrypted.length-20), decryptedHash, 0, 20);

			//debug messages
			//System.out.println("Decrypted Message: " + new String(decryptedMsg));
			//System.out.println("Full Msg Length " + decrypted.length);
			//System.out.println("Msg Length " + decryptedMsg.length);
			//System.out.println("SHA-1 Hash: " + toHexString(decryptedHash));
			//System.out.println("SHA-1 Hash string: " + new String(decryptedHash));
			//System.out.println("SHA-1 Hash size: " + decryptedHash.length);

			//create a hash of the original message
			byte[] newHash = sha1_hash(decryptedMsg);

			//see if new hash matches old one
			if(toHexString(newHash).equals(toHexString(decryptedHash)))
			{
				//Silent if nothing is wrong
				//System.out.println("The hashes match.");
			}
			else
			{
				throw new Exception("Error: This file does not match the given hash."); 
			}

			//write message to new file
			out_file.write(decryptedMsg);
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

	public static byte[] aes_decrypt(byte[] data_in) throws Exception{
		byte[] decrypted = null;
		String dec_str = null;
		try{
			//set cipher to decrypt mode
			sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec, new IvParameterSpec(new byte[16]));

			//do decryption
			decrypted = sec_cipher.doFinal(data_in);

			//Modified to return byte array, conversion to string was problematic
			//convert to string
			//dec_str = new String(decrypted);
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
}
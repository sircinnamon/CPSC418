import java.io.*;
import java.net.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.math.*;
import java.security.SecureRandom;
import java.util.Scanner;
import java.math.BigInteger;


public class Client 
{
    private Socket sock;  //Socket to communicate with.
	
    public static void main (String [] args)
    {
    boolean debug = false;
	if (args.length != 2 && args.length != 3) {
	    System.out.println ("Usage: java Client hostname port# (optional: debug)");
	    System.out.println ("hostname is a string identifying your server");
	    System.out.println ("port is a positive integer identifying the port to connect to the server");
	    return;
	}

	try {
		if(args.length == 3 && args[2].toLowerCase().equals("debug"))
		{
			debug = true;
		}
		else if (args.length == 3)
		{
			throw new IllegalArgumentException("Invalid Argument Format");
		}
	    Client c = new Client (args[0], Integer.parseInt(args[1]), debug);
	}
	catch (NumberFormatException e) {
	    System.out.println ("Usage: java Client hostname port# (optional: debug)");
	    System.out.println ("Second argument was not a port number");
	    return;
	}
	catch (IllegalArgumentException e) {
    System.out.println (e);
    return;
	}
    }
	
    public Client (String ipaddress, int port, boolean debug)
    {

		//STEPS TO RUN
		//1: recieve session key encrypted and hashed with seeded key
		//2: Send FIlename wait for ack (Decrypt and verify)
		//3: Send filesize wait for ack (Decrypt and verify)
		//4: Send data and wait for ack (Decrypt and verify)
		//6: Await final Ack and shutdown
		
		InputStream in;
		OutputStream out;
		byte[] incoming = null;
		byte[] outgoing;
		File file;
		String destination;
		SecretKey sessionKey;
		String msg;
		BigInteger p;
		BigInteger g;
		BigInteger secret;
		BigInteger intKey;
		FileInputStream fis;
		int filesize;

		try 
		{
			//Get seed, source filename and destination filename
			//seed = getInput("Enter a seed: ").getBytes();
			//seededKey = CryptoUtil.genSeededKey(seed);
			//if(debug){System.out.println("SEEDEDKEY: " + CryptoUtil.toHexString(seededKey.getEncoded()));}
			file = new File(getInput("Enter filename to send: "));
			if(!file.exists() || !file.isFile())
			{
				throw new Exception("Entered file does not exist locally");
			}
			filesize = (int)file.length();
			destination = getInput("Enter destination file name: ");
			
		/* Try to connect to the specified host on the specified port. */
		    sock = new Socket (InetAddress.getByName(ipaddress), port);
		    in = sock.getInputStream();
		    out = sock.getOutputStream();

			/* Status info */
			if(debug){System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);}

			/*Step 1: recieve session key
			while(in.available() < 48)
			{
				//System.out.print((in.available()!=0)?in.available()+"\n":"");
			}
		    incoming = new byte[in.available()];
		    in.read(incoming);
		    if(debug){System.out.println("SERVER: " + CryptoUtil.toHexString(incoming));}
			sessionKey = CryptoUtil.buildSessionKey(CryptoUtil.unwrapMsgBytes(incoming, seededKey));
			if(debug){System.out.println("SERVER: " + CryptoUtil.toHexString(sessionKey.getEncoded()));}*/


			//Step 1: recieve p and ack
			p = new BigInteger(readBlock(in, CryptoUtil.KEYSIZE/8 + 1));
			if(debug){System.out.println("p = " + CryptoUtil.toHexString(p.toByteArray()));}
			out.write(0);
			out.flush();
			//Step 2: recieve g and ack
			g = new BigInteger(readBlock(in, CryptoUtil.KEYSIZE/8 +1));
			if(debug){System.out.println("g = " + CryptoUtil.toHexString(g.toByteArray()));}
			out.write(0);
			out.flush();

			//Step 3: generate secret int
			secret = CryptoUtil.genRandomExponent(p);
			if(debug){System.out.println("secret = " + CryptoUtil.toHexString(secret.toByteArray()));}
			//Step 4: send g^secret
			out.write(CryptoUtil.formatByteArr(CryptoUtil.modExponent(g, secret, p).toByteArray()));
			out.flush();
			//Step 5: recieve half key and raise by secret and ack to make session key
			intKey = CryptoUtil.modExponent((new BigInteger(readBlock(in, CryptoUtil.KEYSIZE/8+1))), secret, p);
			if(debug){System.out.println("key = " + CryptoUtil.toHexString(intKey.toByteArray()));}
			out.write(0);
			out.flush();
			sessionKey = CryptoUtil.genSeededKey(intKey.toByteArray());
			//Send filename and get ack
			outgoing = CryptoUtil.wrapMsg(("FILENAME: " + destination).getBytes(), sessionKey);
		    //if(debug){System.out.println("CLIENT: " + CryptoUtil.toHexString(outgoing));}
		    out.write(outgoing);
		    out.flush();

		    while(in.available() < 32)
		    {
				//System.out.print((in.available()!=0)?in.available()+"\n":"");
			}
		    incoming = new byte[in.available()];
		    in.read(incoming);
		    //if(debug){System.out.println("SERVER: " + CryptoUtil.toHexString(incoming));}
			msg = CryptoUtil.unwrapMsg(incoming, sessionKey);
			if(debug){System.out.println("SERVER: " + msg);}
			if(!msg.equals("ACK FILENAME"))
			{
				throw new Exception("Invalid ack");
			}

			//Send filesize and get ack
			outgoing = CryptoUtil.wrapMsg(("FILESIZE: " + filesize).getBytes(), sessionKey);
		    //if(debug){System.out.println("CLIENT: " + CryptoUtil.toHexString(outgoing));}
		    out.write(outgoing);
		    out.flush();

		    while(in.available() < 32)
		    {
				//System.out.print((in.available()!=0)?in.available()+"\n":"");
			}
		    incoming = new byte[in.available()];
		    in.read(incoming);
		    //if(debug){System.out.println("SERVER: " + CryptoUtil.toHexString(incoming));}
			msg = CryptoUtil.unwrapMsg(incoming, sessionKey);
			if(debug){System.out.println("SERVER: " + msg);}
			if(!msg.equals("ACK FILESIZE"))
			{
				throw new Exception("Invalid ack");
			}

			//Send filedata and get ack
			int sent = 0;
			fis = new FileInputStream(file);
			while(sent < filesize)
			{
				if(filesize-sent > CryptoUtil.BLOCKSIZE)
				{
					outgoing = new byte[CryptoUtil.BLOCKSIZE];
				}
				else
				{
					outgoing = new byte[filesize-sent];
				}
				fis.read(outgoing, 0, outgoing.length);
				sent = sent + outgoing.length;
				//if(debug){System.out.println(outgoing.length);}
				//if(debug){System.out.println(CryptoUtil.wrapMsg(outgoing, sessionKey).length);}
			    out.write(CryptoUtil.wrapMsg(outgoing, sessionKey));
			    out.flush();
			    while(in.available() < 32){}
			   	incoming = new byte[in.available()];
		    	in.read(incoming);
			    msg = CryptoUtil.unwrapMsg(incoming, sessionKey);
				if(debug){System.out.println("SERVER: " + msg);}
				if(!msg.equals("ACK DATA"))
				{
					throw new Exception("Invalid ack");
				}
			}
			in.close();
			out.close();
			System.exit(0);

		}
		catch (UnknownHostException e) 
		{
		    System.out.println ("Usage: java Client hostname port#");
		    System.out.println ("First argument is not a valid hostname");
		    return;
		}
		catch (IOException e) 
		{
		    System.out.println ("Could not connect to " + ipaddress + ".");
		    return;
		}
		catch(Exception e)
		{
			System.out.println(e);
			e.printStackTrace();
			return;
		}
    }

    private String getInput(String msg)
    {
    	Scanner in = new Scanner(System.in);
    	System.out.print(msg);
    	return in.nextLine();
    }

    private byte[] readFile(File file) throws IOException, FileNotFoundException
    {
    	FileInputStream in = new FileInputStream(file);
    	byte[] data = new byte[(int)file.length()];
    	in.read(data);
    	return data;
    }

    private byte[] readBlock(InputStream in, int size) throws  IOException
    {
    	int read = 0;
    	int available;
    	byte[] data = new byte[size];
    	//System.out.println("Reading " + size + " byte block");
    	while(read < size)
    	{
    		available = in.available();
    		if(available + read > size)
    		{
    			available = size-read;
    		}
    		in.read(data, read , available);
    		read += available;
    	}
    	return data;
    }
}
import java.net.*;
import java.io.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.math.*;
import java.security.SecureRandom;


public class ServerThread extends Thread
{
    private Socket sock;  //The socket it communicates with the client on.
    private Server parent;  //Reference to Server object for message passing.
    private int idnum;  //The client's id number.
    public boolean debug;
	
    public ServerThread (Socket s, Server p, int id, boolean db)
    {
	parent = p;
	sock = s;
	idnum = id;
	debug = db;
	if(debug){System.out.println("DEBUG ON");}
    }

    public int getID ()
    {
	return idnum;
    }
	
    public Socket getSocket ()
    {
	return sock;
    }

    public void run ()
    {
    	//STEPS TO RUN
    	//1: Send session key encrypted and hashed with seeded key
    	//2: Recieve FIlename and ack (Decrypt and verify)
    	//3: Recieve filesize and ack (Decrypt and verify)
    	//4: Recieve data and ack (Decrypt and verify)
    	//5: Save to file
    	//6: Ack and shutdown

		InputStream in = null;
		OutputStream out = null;
		byte[] incoming = null;
		byte[] outgoing = null;
		String msg;
		SecretKey sessionKey;
		String fileName;
		int fileSize;
		byte[] fileData;
		BigInteger p;
		BigInteger g;
		BigInteger secret;
		BigInteger intKey;
		debug = this.debug;
		FileOutputStream fos;
		File file;

		try 
		{
		    in = sock.getInputStream();
		    out = sock.getOutputStream();

		    //Step 0: generate p, g, secret int
		    //System.out.println(new BigInteger(CryptoUtil.formatByteArr(BigInteger.TEN.toByteArray())));
		    if(debug){System.out.print("Generating BigInts");}
		    p = CryptoUtil.genSophieGermain();
		    if(debug){System.out.println("p = " + CryptoUtil.toHexString(p.toByteArray()));}
		    g = CryptoUtil.findPrimitiveRoot(p);
		    if(debug){System.out.println("g = " + CryptoUtil.toHexString(g.toByteArray()));}
		    secret = CryptoUtil.genRandomExponent(p);
		    if(debug){System.out.println("secret = " + CryptoUtil.toHexString(secret.toByteArray()));}
		    //Step 1: send p and get ack
		    out.write(CryptoUtil.formatByteArr(p.toByteArray()));
		    out.flush();
		    while(in.available() == 0){}
		    if(in.read() != 0)
		    {
		    	throw new Exception("Invalid ack");
		    }
		    //Step 2: send g and get ack
		    out.write(CryptoUtil.formatByteArr(g.toByteArray()));
		    out.flush();
		    while(in.available() == 0){}
		    if(in.read() != 0)
		    {
		    	throw new Exception("Invalid ack");
		    }
		    //Step 3: recieve opposite half key and make session key
		    intKey = CryptoUtil.modExponent((new BigInteger(readFromStream(in, CryptoUtil.KEYSIZE/8+1))), secret, p);
		    if(debug){System.out.println("key = " + CryptoUtil.toHexString(intKey.toByteArray()));}
		    sessionKey = CryptoUtil.genSeededKey(intKey.toByteArray());
		    //Step 4: send g^secret and get ack and make session key
		    out.write(CryptoUtil.formatByteArr((CryptoUtil.modExponent(g, secret, p)).toByteArray()));
		    out.flush();
		    while(in.available() == 0){}
		    if(in.read() != 0)
		    {
		    	throw new Exception("Invalid ack");
		    }
			//Step 2: recieve filename and ack
			while(in.available() < 48 || (in.available() % 16)!= 0)
			{
				//System.out.print((in.available()!=0)?in.available()+"\n":"");
			}
		    incoming = new byte[in.available()];
		    in.read(incoming);
			msg = CryptoUtil.unwrapMsg(incoming, sessionKey);
			if(debug){System.out.println("CLIENT: " + msg);}
			fileName = msg.replaceAll("FILENAME: ", "");

			outgoing = CryptoUtil.wrapMsg(("ACK FILENAME").getBytes(), sessionKey);
		    out.write(outgoing);
		    out.flush();

		   file = new File(fileName);
	    	if(!file.exists())
	    	{
	    		file.createNewFile();
	    	}
	    	else
	    	{
	    		file.delete();
	    		file.createNewFile();
	    	}

		    //Step 3: recieve file size and ack
		    while(in.available() < 32 || (in.available() % 16)!= 0)
		    {
				//System.out.print((in.available()!=0)?in.available()+"\n":"");
			}
		    incoming = new byte[in.available()];
		    in.read(incoming);
			msg = CryptoUtil.unwrapMsg(incoming, sessionKey);
			if(debug){System.out.println("CLIENT: " + msg);}
			fileSize = Integer.parseInt(msg.replaceAll("FILESIZE: ", ""));

			outgoing = CryptoUtil.wrapMsg(("ACK FILESIZE").getBytes(), sessionKey);
		    out.write(outgoing);
		    out.flush();

		    //step 4 read data
		    //incoming = readFromStream(in, fileSize);
			//if(debug){System.out.println("CLIENT: " + CryptoUtil.toHexString(incoming));
			fos = new FileOutputStream(file, true);
		    int recieved = 0;
		    while(recieved < fileSize)
			{
				if(fileSize-recieved > CryptoUtil.BLOCKSIZE)
				{
					incoming = new byte[roundUp(CryptoUtil.BLOCKSIZE + 20)];
				}
				else
				{
					incoming = new byte[roundUp(fileSize-recieved + 20)];
				}
				//if(debug){System.out.println("Looking for # bytes: " + incoming.length);}
				while(in.available() < incoming.length){}
				in.read(incoming);
				fileData = CryptoUtil.unwrapMsgBytes(incoming, sessionKey);
				fos.write(fileData, 0, fileData.length);
				msg = new String(fileData);
				if(debug){System.out.println("CLIENT: " + msg);}
				recieved = recieved + (fileData.length);
			    
			    outgoing = CryptoUtil.wrapMsg(("ACK DATA").getBytes(), sessionKey);
		    	out.write(outgoing);
		    	out.flush();
			}

		    //Step 5 save to file
		    if(debug){System.out.println("Closing thread " + idnum);}
		    in.close();
		    out.close();
		    return;
    	}
    	catch(Exception e)
    	{
    		if(parent.getFlag())
    		{
    			System.out.println("Shutting down.");
    			return;	
    		}
    		else
    		{
    			System.out.println("Error: " + e);
    			e.printStackTrace();
    			return;	
    		}
    	}		
	}
    public byte[] readFromStream(InputStream in ,int size) throws IOException
    {
    	//read size amnt from stream
    	byte[] data;
		data = new byte[size];
		int bytesRead = 0;
		int readCounter;
		while(bytesRead < data.length)
        {
            while((readCounter = in.read(data, bytesRead, (data.length-bytesRead))) != -1)
            {
                bytesRead = bytesRead + readCounter;
                if(bytesRead == data.length)
                {
                    break;
                }
            }
        }
    	return data;
    }
    public void saveFile(String name, byte[] data) throws FileNotFoundException, IOException
    {
    	File file = new File(name);
    	FileOutputStream fout = new FileOutputStream(file);
    	fout.write(data);
    	fout.close();
    }

    public int roundUp(int x)
    {
    	return x + (16-x%16);
    }
   
}
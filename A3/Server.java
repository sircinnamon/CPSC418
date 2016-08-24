import java.io.IOException;
import java.net.*;
import java.util.Vector;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.math.*;
import java.security.SecureRandom;
import java.util.Scanner;
import java.math.BigInteger;

public class Server
{
    private ServerSocket serversock;
    private Vector <ServerThread> serverthreads;  //holds the active threads
    private boolean shutdown;  //allows clients to shutdown the server
    private int clientcounter;  //id numbers for the clients
    private boolean debug = false;

    public static void main (String [] args)
    {
   	boolean debug = false;
	if (args.length != 1 && args.length != 2) {
	    System.out.println ("Usage: java Server port# (optional: debug)");
	    return;
	}

	try {
	    if(args.length == 2 && args[1].toLowerCase().equals("debug"))
	    {
	    	debug = true;
	    }
	    else if(args.length == 2)
	    {
	    	throw new IllegalArgumentException("Invalid Argument Format");
	    }
	    Server s = new Server (Integer.parseInt(args[0]), debug);
	}
	catch (ArrayIndexOutOfBoundsException e) {
	    System.out.println ("Usage: java Server port# (optional: debug)");
	    System.out.println ("Second argument is not a port number.");
	    return;
	}
	catch (NumberFormatException e) {
	    System.out.println ("Usage: java Server port# (optional: debug)");
	    System.out.println ("Second argument is not a port number.");
	    return;
	}
	catch (IllegalArgumentException e) {
	    System.out.println (e);
	    e.printStackTrace();
	    return;
	}
	catch (UnknownHostException e) {
	    System.out.println (e);
	    e.printStackTrace();
	    return;
	}
    }

    public Server (int port, boolean debug) throws UnknownHostException
    {
	clientcounter = 0;
	shutdown = false;
	try {
	    serversock = new ServerSocket (port);
	}
	catch (IOException e) {
	    System.out.println ("Could not create server socket.");
	    return;
	}
	serverthreads = new Vector <ServerThread> (0,1);
		
	if(debug){System.out.println ("Server IP address: " + serversock.getInetAddress().getLocalHost() + ",  port " + port);}

	listen (debug);
    }
	
    public boolean getFlag ()
    {
	return shutdown;
    }

    public void kill (ServerThread st)
    {
	if(debug){System.out.println ("Killing Client " + st.getID() + ".");}
		
	for (int i = 0; i < serverthreads.size(); i++) {
	    if (serverthreads.elementAt(i) == st)
		serverthreads.remove(i);
	}
    }

    public void killall ()
    {
	shutdown = true;
	if(debug){System.out.println ("Shutting Down Server.");}
		
	/* For each active thread, close it's socket.  This will cause the thread
	 * to stop blocking because of the IO operation, and check the shutdown flag.
	 * The thread will then exit itself when it sees shutdown is true.  Then exits. */
	for (int i = serverthreads.size() - 1; i >= 0; i--) {
	    try {
		System.out.println ("Killing Client " + serverthreads.elementAt(i).getID() + ".");
		serverthreads.elementAt(i).getSocket().close();
	    }
	    catch (IOException e)
		{System.out.println ("Could not close socket.");}
	    serverthreads.remove(i);
	}
	try {
	    serversock.close();
	} 
	catch (IOException e) {
	    System.out.println ("Could not close server socket.");
	}		
    }
	
    private void listen (boolean debug)
    {
	Socket client = new Socket ();
	ServerThread st;

	while (!shutdown) {
	    try {
		client = serversock.accept ();
		if(debug){System.out.println ("Client on machine " + client.getInetAddress().getHostAddress() + " has connected on port " + client.getLocalPort() + ".");}
				
		st = new ServerThread (client, this, clientcounter++, debug);
		serverthreads.add (st);
		st.start ();
	    }
	    catch (IOException e) {
	    }
	}
    }

    private String getInput(String msg)
    {
    	Scanner in = new Scanner(System.in);
    	System.out.print(msg);
    	return in.nextLine();
    }
}

package sslCertificationLibrary;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import com.sun.net.ssl.internal.ssl.Provider;
import java.security.Security;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * @author Joe Prasanna Kumar
 * This program simulates a client socket program which communicates with the SSL Server
 * 
 * Algorithm:
 * 1. Determine the SSL Server Name and port in which the SSL server is listening
 * 2. Register the JSSE provider
 * 3. Create an instance of SSLSocketFactory
 * 4. Create an instance of SSLSocket
 * 5. Create an OutputStream object to write to the SSL Server
 * 6. Create an InputStream object to receive messages back from the SSL Server
 * 
 */ 

public class SSLClient 
{
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception
	{
		String serverName = "localhost"; // SSL Server Name
		int sslPort = 4443; // Port where the SSL Server is listening
		PrintWriter out = null;
		BufferedReader in = null;
		
		// Registering the JSSE provider
		Security.addProvider(new Provider());
		
		
		System.setProperty("javax.net.ssl.trustStore","keystore.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "keystore");
		
		// Enable debugging to view the handshake and communication which happens between the SSLClient and the SSLServer
		System.setProperty("javax.net.debug","all");
		
		try 
		{
			// Creating Client Sockets
			SSLSocketFactory sslSocketFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
			SSLSocket sslSocket = (SSLSocket)sslSocketFactory.createSocket(serverName,sslPort);
			
			// Initializing the streams for Communication with the Server
			out = new PrintWriter(sslSocket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
			
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			String userInput = "Hello Testing ";
			out.println(userInput);
			
			while ((userInput = stdIn.readLine()) != null) 
			{
			    out.println(userInput);
			    System.out.println("echo: " + in.readLine());
			}
			
			out.println(userInput);
			
			// Closing the Streams and the Socket
			out.close();
			in.close();
			stdIn.close();
			sslSocket.close();
		}
		catch (Exception exp)
		{
			System.out.println(" Exception occurred .... " +exp);
			exp.printStackTrace();
		}
	}
}
package test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.PrivilegedActionException;
import java.security.Security;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import com.sun.net.ssl.internal.ssl.Provider;

/** 
 * @author Joe Prasanna Kumar
 * Adapted by Marcelo d'Almeida
 * 
 * This program simulates an SSL Server listening on a specific port for client requests
 * 
 * Algorithm:
 * 1. Regsiter the JSSE provider
 * 2. Set System property for keystore by specifying the keystore which contains the server certificate
 * 3. Set System property for the password of the keystore which contains the server certificate
 * 4. Create an instance of SSLServerSocketFactory
 * 5. Create an instance of SSLServerSocket by specifying the port to which the SSL Server socket needs to bind with
 * 6. Initialize an object of SSLSocket
 * 7. Create InputStream object to read data sent by clients
 * 8. Create an OutputStream object to write data back to clients.
 */ 


public class SSLServer 
{
	
	/**
	 * @param args
	 */
	public static void main(String[] args)
	{
		run();
	}
	
	public static void run()
	{
		// Port where the SSL Server needs to listen for new requests from the client
		int sslPort = 4443; 	
		
		// Registering the JSSE provider
		Security.addProvider(new Provider());
		
		//Specifying the Keystore details
		System.setProperty("javax.net.ssl.keyStore","keystore.jks");
		System.setProperty("javax.net.ssl.keyStorePassword","keystore");
		
		// Enable debugging to view the handshake and communication which happens between the SSLClient and the SSLServer
		System.setProperty("javax.net.debug","all");
		
		
		try 
		{
			// Initialize the Server Socket
			SSLServerSocketFactory sslServerSocketfactory = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
			SSLServerSocket sslServerSocket = (SSLServerSocket)sslServerSocketfactory.createServerSocket(sslPort);
			SSLSocket sslSocket = (SSLSocket)sslServerSocket.accept();
			
			// Create Input / Output Streams for communication with the client
			PrintWriter out = new PrintWriter(sslSocket.getOutputStream(), true);
			BufferedReader in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
			String inputLine;
			
			inputLine = in.readLine();
			while (inputLine != null) 
			{
				out.println(inputLine);
				System.out.println(inputLine);
				inputLine = in.readLine();
			}	
			
			// Close the streams and the socket
			out.close();
			in.close();
			sslSocket.close();
			sslServerSocket.close();
		}
		catch (Exception exp)
		{
			PrivilegedActionException priexp = new PrivilegedActionException(exp);
			System.out.println(" Priv exp --- " + priexp.getMessage());
			
			System.out.println(" Exception occurred .... " +exp);
			exp.printStackTrace();
		}
	}
}
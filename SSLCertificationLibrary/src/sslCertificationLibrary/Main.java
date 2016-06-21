package sslCertificationLibrary;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.net.ssl.internal.ssl.Provider;

import sslCertificationLibrary.verifier.ServerVerifier;

/**
 * 
 * @author Marcelo d'Almeida
 * 
 * This is the Main Class for the standalone operation mode
 * Given an URL (e.g. www.example.com), it gives WebSite's SSL certificates diagnosis
 * 
 */

public class Main 
{
	/**
	 * @param args
	 */
	public static void main(String[] args) 
	{
		
		// Registering the JSSE and BouncyCastle providers
		Security.addProvider(new Provider());
		Security.addProvider(new BouncyCastleProvider());
		
		String hostName;
		
		// Handling @param args options
		// one argument can be passed: the WebSite address (e.g. www.google.com)
		URL destinationURL = null;
		if (args.length == 1)
		{
			hostName = args[0];
		}
		else
		{
			hostName = "www.google.com";
		}
		
		try 
		{
			destinationURL = new URL("https://" + hostName);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		
		// all verifications are currently accessed through ServerVerifier Class
		ServerVerifier.verifySSLProtocols(destinationURL);
		ServerVerifier.verifySupportedCipherSuites(destinationURL);
		ServerVerifier.verifyCertificates(destinationURL);
		
		ServerVerifier.showCertificateValidityDateInfo(destinationURL);
	}
}

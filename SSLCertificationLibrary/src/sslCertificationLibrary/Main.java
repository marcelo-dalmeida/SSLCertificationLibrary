package sslCertificationLibrary;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.net.ssl.internal.ssl.Provider;

import sslCertificationLibrary.verifier.ServerVerifier;

/**
 * @author Marcelo d'Almeida
 */

public class Main 
{
	
	public static void main(String[] args) 
	{
		
		// Registering the JSSE (and BouncyCastle) provider
		Security.addProvider(new Provider());
		Security.addProvider(new BouncyCastleProvider());
		
		String hostName;
		
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
		
		
		ServerVerifier.verifySSLProtocols(destinationURL);
		ServerVerifier.verifySupportedCipherSuites(destinationURL);
		ServerVerifier.verifyCertificates(destinationURL);
		
		ServerVerifier.showCertificateValidityDateInfo(destinationURL);
	}
}

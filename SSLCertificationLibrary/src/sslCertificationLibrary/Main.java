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
		
		URL destinationURL = null;
		try 
		{
			destinationURL = new URL("https://www.elavon.com");
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		
		ServerVerifier.verifySSLProtocols(destinationURL);
		ServerVerifier.verifySupportedCipherSuites(destinationURL);
		ServerVerifier.verifyCertificates(destinationURL);
	}
}

package sslCertificationLibrary;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.net.ssl.internal.ssl.Provider;

public class Main {
	
	public static void main(String[] args) {

		// Registering the JSSE (and BouncyCastle) provider
		Security.addProvider(new Provider());
		Security.addProvider(new BouncyCastleProvider());
		
		URL destinationURL = null;
		try 
		{
			destinationURL = new URL("https://www.google.com");
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		ServerVerifier.verifyServerSupportedCipherSuites(destinationURL);

		ServerVerifier.verifyServerCertificates(destinationURL);
	}
}

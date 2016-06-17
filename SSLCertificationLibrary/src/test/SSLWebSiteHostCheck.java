package test;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import sslCertificationLibrary.verifier.ServerVerifier;

/**
 * @author Marcelo d'Almeida
 */

public class SSLWebSiteHostCheck 
{
	@BeforeClass
	public static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	public void testThatTrustedCertificateIsTrusted()
	{
		try {
		    String hostName = "www.elavon.com";
		    
			ServerVerifier.verifyCertificates(new URL("https://" + hostName));
			
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}	
}

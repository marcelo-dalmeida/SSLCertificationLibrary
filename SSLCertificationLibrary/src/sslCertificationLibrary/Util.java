package sslCertificationLibrary;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class Util {
	
	public static Set<X509Certificate> getTrustedCertificates()
	{
		// Load the JDK's cacerts keystore file
	    String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
	    FileInputStream fileInputStream;
	    KeyStore keystore;
	    PKIXParameters parameters = null;
	    
	    try 
		{
			fileInputStream = new FileInputStream(filename);
			keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			String password = "changeit";
		    keystore.load(fileInputStream, password.toCharArray());
		    
		    // This class retrieves the most-trusted CAs from the keystore
		    parameters = new PKIXParameters(keystore);
		    
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	    
	    // Get the set of trust anchors, which contain the most-trusted CA certificates
	    Set<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
	    Iterator<TrustAnchor> iterator = parameters.getTrustAnchors().iterator();
	    while (iterator.hasNext()) 
	    {
	        TrustAnchor trustAnchor = iterator.next();
	        // Get certificate
	        X509Certificate certificate = trustAnchor.getTrustedCert();
	        trustedCertificates.add(certificate);
	    }
	    return trustedCertificates;
	}
	
	public static void printDelimiter()
	{
		System.out.println();
        System.out.println("################################################################");
        System.out.println();
	}
}

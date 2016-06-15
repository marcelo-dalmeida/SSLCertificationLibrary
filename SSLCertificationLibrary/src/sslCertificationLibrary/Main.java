package sslCertificationLibrary;

import java.io.File;
import java.io.FileInputStream;
import java.net.SocketException;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.security.auth.x500.X500Principal;

public class Main {
	
	public static final String X509_CERTIFICATE = "X.509";
	public static final String TLSv1_2_PROTOCOL = "TLSv1.2";
	public static final String TLSv1_1_PROTOCOL = "TLSv1.1";
	public static final String TLSv1_PROTOCOL = "TLSv1";
	public static final String SSLv3_PROTOCOL = "SSLv3";

	public static void verifyServerSupportedCipherSuites(URL destinationURL)
	{
		final int VERIFICATION_TIMEOUT_DEFAULT = 10000;
		verifyServerSupportedCipherSuites(destinationURL, VERIFICATION_TIMEOUT_DEFAULT);
	}
	
	public static void verifyServerSupportedCipherSuites(URL destinationURL, int verificationTimeout)
	{
		try
		{
			float procedureProgress = 0;
			float timeProgress = 0;
			float verificationProgress = 0;
			
			System.out.println("Cipher Suites Verification Progress: " + procedureProgress*100 + "%");
			
			SSLContext sslContext = SSLContext.getInstance(TLSv1_2_PROTOCOL);
			// Init the SSLContext with a TrustManager[] and SecureRandom()
			sslContext.init(null, null, null);
			
			HttpsURLConnection connection = (HttpsURLConnection) destinationURL.openConnection();
	         
	        String[] clientSupportedCipherSuites = connection.getSSLSocketFactory().getSupportedCipherSuites();
	        
	        List<String> cipherSuitesToVerifyServerSupport = new ArrayList<String>();
	        List<String> serverSupportedCipherSuites = new ArrayList<String>();
	        List<String> serverNotSupportedCipherSuites = new ArrayList<String>();
	        List<String> cipherSuitesToVerificationPending;
	        
	        cipherSuitesToVerifyServerSupport.addAll(Arrays.asList(clientSupportedCipherSuites));
	        
	        int totalNumberOfCipherSuites = cipherSuitesToVerifyServerSupport.size();
	        int totalNumberOfPendingCipherSuites;
	        long startTime = System.currentTimeMillis();
	    	long currentTime = 0;
	    	
	        
	        while (!cipherSuitesToVerifyServerSupport.isEmpty() && currentTime < verificationTimeout)
	        {
	        	cipherSuitesToVerificationPending = new ArrayList<>();
	        	cipherSuitesToVerificationPending.addAll(cipherSuitesToVerifyServerSupport); 
	        	for (String cipherSuite : cipherSuitesToVerificationPending) 
		        {
		        	connection = (HttpsURLConnection) destinationURL.openConnection();
		        	try
		        	{
		        		connection.setSSLSocketFactory(new EnforcedCipherSuiteSSLSocketFactory(sslContext.getSocketFactory(), cipherSuite));
		        		connection.connect();
		        		serverSupportedCipherSuites.add(cipherSuite);
		        		cipherSuitesToVerifyServerSupport.remove(cipherSuite);
		        		
		        	} catch(SSLHandshakeException e) {
		        		
		        		serverNotSupportedCipherSuites.add(cipherSuite);
		        		cipherSuitesToVerifyServerSupport.remove(cipherSuite);
		        		
		        	} catch(SocketException e) {
		        		//Connection refused. Let's try again!
		        	}		
				}
	        	currentTime = System.currentTimeMillis() - startTime;
	        	
	        	totalNumberOfPendingCipherSuites = cipherSuitesToVerifyServerSupport.size();
	        	timeProgress = (float)(currentTime)/(float)(verificationTimeout);
	        	timeProgress = timeProgress > 1 ? 1 : timeProgress;
	        	verificationProgress = (float)(totalNumberOfCipherSuites - totalNumberOfPendingCipherSuites)/(float)(totalNumberOfCipherSuites);
	        	procedureProgress = Math.max(timeProgress, verificationProgress);
	        	System.out.println("Cipher Suites Verification Progress: " + procedureProgress*100 + "%");
	        }
	        System.out.println("Cipher Suites Verification Progress: " + procedureProgress*100 + "%");
	        
	        System.out.println("Cipher suites are supported by the server: ");
	        System.out.println("Cipher suites are NOT supported by the server: ");
	        System.out.println("Server did not report if it is supported by the server: ");
	        
		} catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		try
		{
			URL destinationURL = new URL("https://www.elavon.com");
			Main.verifyServerSupportedCipherSuites(destinationURL);

			SSLContext sslContext = SSLContext.getInstance(TLSv1_2_PROTOCOL);
			// Init the SSLContext with a TrustManager[] and SecureRandom()
			sslContext.init(null, null, null);
			
			HttpsURLConnection connection = (HttpsURLConnection) destinationURL.openConnection();
	        connection.setSSLSocketFactory(sslContext.getSocketFactory());
	        connection.connect();
	        
	        System.out.println("################################################################");
	        System.out.println(connection.getCipherSuite());
			
	        X509Certificate[] certs = (X509Certificate[]) connection.getServerCertificates();
	        
	        for (X509Certificate cert : certs) {
	            System.out.println("");
	            System.out.println("");
	            System.out.println("");
	            System.out.println("################################################################");
	            System.out.println("");
	            System.out.println("");
	            System.out.println("");
	            //System.out.println("Certificate is: " + cert);
	            if(cert.getType().equals(X509_CERTIFICATE)) {
	                try {
	                	X509Certificate certificate = ((X509Certificate) cert); 
	                    certificate.checkValidity();
	                    System.out.println("Certificate is active for current date");
	                    
	                    System.out.println("Subject");
	                    System.out.println(certificate.getSubjectX500Principal());
	                    
	                    System.out.println("Issuer");
	                    System.out.println(certificate.getIssuerX500Principal());
	                    
	                    System.out.println("Serial Number");
	                    System.out.println(certificate.getSerialNumber());
	                    
	                    System.out.println("Signature Algorithm");
	                    System.out.println(certificate.getSigAlgName());
	                    
	                    //System.out.println("Basic constraints");
	                    //System.out.println(certificate.getBasicConstraints());
	                    
	                    //System.out.println("Subject alternative names");
	                    
	                    CRLVerifier.verifyCertificateCRLs(certificate);
	                    
	                    
	                    System.out.println(certificate.getSubjectUniqueID());
	                    System.out.println(certificate.getIssuerAlternativeNames());
	                    System.out.println(certificate.getSubjectAlternativeNames());
	                    System.out.println(certificate.getNotBefore());
	                    System.out.println(certificate.getNotAfter());
	                    
	                    System.out.println("Verified");
	                    System.out.println(certificate.getSignature());
	                    
	                    //System.out.println(certificate.getSigAlgOID());
	                    //System.out.println(certificate.getType());
	                    //System.out.println(certificate.getVersion());
	                    
	                    	                    
	                    //FileOutputStream os = new FileOutputStream("/home/sebastien/Bureau/myCert"+i);
	                    //os.write(cert.getEncoded());
	                } catch(CertificateExpiredException cee) {
	                    System.out.println("Certificate is expired");
	                }
	            } else {
	                System.err.println("Unknown certificate type: " + cert);
	            }
	        }
	        
	        
	     // Load the JDK's cacerts keystore file
            String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
            FileInputStream is = new FileInputStream(filename);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "changeit";
            keystore.load(is, password.toCharArray());

            // This class retrieves the most-trusted CAs from the keystore
            PKIXParameters parameters = new PKIXParameters(keystore);

            // Get the set of trust anchors, which contain the most-trusted CA certificates
            Set<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
            List<X500Principal> trustedCertificateIssuers = new ArrayList<X500Principal>();
            Iterator<TrustAnchor> iterator = parameters.getTrustAnchors().iterator();
            while (iterator.hasNext()) 
            {
                TrustAnchor trustAnchor = iterator.next();
                // Get certificate
                X509Certificate certificate = trustAnchor.getTrustedCert();
                X500Principal certificateIssuer = certificate.getIssuerX500Principal();
                trustedCertificates.add(certificate);
                trustedCertificateIssuers.add(certificateIssuer);
                //System.out.println(certificate);
            }
	        
	        
	        
	        
	        Set<X509Certificate> trustedCerts = new HashSet<X509Certificate>();
	        Set<X509Certificate> intermediateCerts = new HashSet<X509Certificate>();
	        intermediateCerts.addAll(Arrays.asList(certs));
	        trustedCerts.addAll(trustedCertificates);
	        CertificateVerifier.verifyCertificate((X509Certificate)certs[0], trustedCerts, intermediateCerts);
	        certs[0].verify(certs[1].getPublicKey());
	        certs[1].verify(certs[2].getPublicKey());
	        //certs[2].verify(certs[2].getPublicKey());
	        System.out.println("Verified");
		} catch(Exception e){
			e.printStackTrace();
		}
	}
}

package sslCertificationLibrary.verifier;

import java.io.IOException;
import java.net.SocketException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;

import sslCertificationLibrary.utilities.EnforcedCipherSuiteSSLSocketFactory;
import sslCertificationLibrary.utilities.Util;

/**
 * @author Marcelo d'Almeida
 * 
 * Class for verifying server related things. It handles SSL protocols, 
 * cipher suites, and certificate checks.
 */

public class ServerVerifier {
	
	public static final String X509_CERTIFICATE = "X.509";
	public static final String TLS_v1_2_PROTOCOL = "TLSv1.2";
	public static final String TLS_v1_1_PROTOCOL = "TLSv1.1";
	public static final String TLS_v1_0_PROTOCOL = "TLSv1";
	public static final String SSL_v3_0_PROTOCOL = "SSLv3";
	
	/**
	 * Verify Cipher Suites supported by the server.
	 * It provides a 10 seconds default timeout. 
	 * 
	 * @param destinationURL - WebSite URL (e.g. www.example.com).
	 */
	public static void verifySupportedCipherSuites(URL destinationURL)
	{
		final int VERIFICATION_TIMEOUT_DEFAULT = 10000;
		verifySupportedCipherSuites(destinationURL, VERIFICATION_TIMEOUT_DEFAULT);
	}
	
	/**
	 * Verify the cipher suites supported by the server.
	 * It gets the cipher suites and tests it one by one through connection to the server.  
	 * 
	 * @param destinationURL - WebSite URL (e.g. www.example.com).
	 * @param verificationTimeout - Max amount of time given to the method to check all certificates.
	 */
	public static void verifySupportedCipherSuites(URL destinationURL, int verificationTimeout)
	{
		float procedureProgress = 0;
		float timeProgress = 0;
		float verificationProgress = 0;
		
		System.out.println("Cipher Suites Verification Progress: " + procedureProgress*100 + "%");
		
		HttpsURLConnection connection = null;
		SSLContext sslContext = null;
		try 
		{
			sslContext = SSLContext.getInstance(TLS_v1_2_PROTOCOL);
			
			// Init the SSLContext with a TrustManager[] and SecureRandom()
			sslContext.init(null, null, null);

			connection = (HttpsURLConnection) destinationURL.openConnection();
			
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
         
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
    	
        // Checks every cipher suite with the server and keep trying until time out. 
        while (!cipherSuitesToVerifyServerSupport.isEmpty() && currentTime < verificationTimeout)
        {
        	cipherSuitesToVerificationPending = new ArrayList<>();
        	cipherSuitesToVerificationPending.addAll(cipherSuitesToVerifyServerSupport); 
        	for (String cipherSuite : cipherSuitesToVerificationPending) 
	        {
        		try
	        	{
        			connection = (HttpsURLConnection) destinationURL.openConnection();
	        	
	        		connection.setSSLSocketFactory(new EnforcedCipherSuiteSSLSocketFactory(sslContext.getSocketFactory(), cipherSuite));
	        		connection.connect();
	        		serverSupportedCipherSuites.add(cipherSuite);
	        		cipherSuitesToVerifyServerSupport.remove(cipherSuite);
	        		
	        	} catch(SSLHandshakeException e) {
	        		
	        		serverNotSupportedCipherSuites.add(cipherSuite);
	        		cipherSuitesToVerifyServerSupport.remove(cipherSuite);
	        		
	        	} catch(SocketException e) {
	        		//Connection refused. Let's try again!
	        	} catch (IOException e) {
					e.printStackTrace();
				}		
			}
        	currentTime = System.currentTimeMillis() - startTime;
        	
        	// Handles 'progress bar'
        	totalNumberOfPendingCipherSuites = cipherSuitesToVerifyServerSupport.size();
        	timeProgress = (float)(currentTime)/(float)(verificationTimeout);
        	timeProgress = timeProgress > 1 ? 1 : timeProgress;
        	verificationProgress = (float)(totalNumberOfCipherSuites - totalNumberOfPendingCipherSuites)/(float)(totalNumberOfCipherSuites);
        	procedureProgress = Math.max(timeProgress, verificationProgress);
        	System.out.println("Cipher Suites Verification Progress: " + procedureProgress*100 + "%");
        }
        System.out.println("Cipher Suites Verification Progress: " + procedureProgress*100 + "%");
        
        // Show the result of cipher suites verification. Supported, not supported, and not reported
        System.out.println();
        
        System.out.println("Cipher suites are supported by the server: ");
        
        for (String serverSupported : serverSupportedCipherSuites) {
			System.out.println(serverSupported);
		}
        System.out.println();
        
        System.out.println("Cipher suites are NOT supported by the server: ");
        for (String serverNotSupported : serverNotSupportedCipherSuites) {
			System.out.println(serverNotSupported);
		}
        System.out.println();
        
        System.out.println("Server did not report if it is supported by the server: ");
        for (String serverDidNotReport : cipherSuitesToVerifyServerSupport) {
			System.out.println(serverDidNotReport);
		}
        Util.printDelimiter();
	}
	
	/**
	 * Verify the ssl protocols supported by the server.
	 * 
	 * @param destinationURL - WebSite URL (e.g. www.example.com).
	 */
	public static void verifySSLProtocols(URL destinationURL)
	{
		String[] sslProtocolsToTest = {SSL_v3_0_PROTOCOL, TLS_v1_0_PROTOCOL, TLS_v1_1_PROTOCOL, TLS_v1_2_PROTOCOL};
		List<String> sslProtocolsAccepted = new ArrayList<String>();
		List<String> sslProtocolsNotAccepted = new ArrayList<String>();
		
		sslProtocolsNotAccepted.addAll(Arrays.asList(sslProtocolsToTest));
		
		HttpsURLConnection connection = null;
		SSLContext sslContext = null;
		for (String sslProtocol : sslProtocolsToTest) 
		{	
			try 
			{
				sslContext = SSLContext.getInstance(sslProtocol);
				
				sslContext.init(null, null, null);
	
				connection = (HttpsURLConnection) destinationURL.openConnection();
				
				connection.setSSLSocketFactory(sslContext.getSocketFactory());
        		connection.connect();
        		sslProtocolsAccepted.add(sslProtocol);
        		sslProtocolsNotAccepted.remove(sslProtocol);
        		
			} catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			} catch (KeyManagementException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		Util.printDelimiter();
		
		System.out.println("SSL Protocols are supported by the server: ");
        for (String serverSupported : sslProtocolsAccepted) 
        {
			System.out.println(serverSupported);
		}
        System.out.println();
        
        System.out.println("SSL Protocols are NOT supported by the server: ");
        for (String serverNotSupported : sslProtocolsNotAccepted) 
        {
			System.out.println(serverNotSupported);
		}
        
        Util.printDelimiter();
        
	}
	
	/**
	 * Verify certificates provided by the server.
	 * 
	 * @param destinationURL - WebSite URL (e.g. www.example.com).
	 */
	public static void verifyCertificates(URL destinationURL)
	{
		HttpsURLConnection connection = null;
		SSLContext sslContext;
		X509Certificate[] certificates = null;
		try {
			sslContext = SSLContext.getInstance(TLS_v1_2_PROTOCOL);
			
			sslContext.init(null, null, null);
			
			connection = (HttpsURLConnection) destinationURL.openConnection();
		    connection.setSSLSocketFactory(sslContext.getSocketFactory());
		    connection.connect();
			
		    System.out.println("Using this cipher suite: ");
		    System.out.println(connection.getCipherSuite());
		    
			certificates = (X509Certificate[]) connection.getServerCertificates();
		    
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		} catch (SSLHandshakeException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	    
    
	    for (X509Certificate certificate : certificates) 
	    {
	        Util.printDelimiter();
	        
	        try 
	        { 
	            certificate.checkValidity();
	            System.out.println("Certificate is active for current date");
	            System.out.println();
	            
	            System.out.println("Subject: ");
	            System.out.println(certificate.getSubjectX500Principal());
	            System.out.println();
	            
	            System.out.println("Issuer: ");
	            System.out.println(certificate.getIssuerX500Principal());
	            System.out.println();
	            
	            System.out.println("Serial Number: ");
	            System.out.println(certificate.getSerialNumber());
	            System.out.println();
	            
	            System.out.println("Signature Algorithm: ");
	            System.out.println(certificate.getSigAlgName());
	            System.out.println();
	            
	            CRLVerifier.verifyCertificateCRLs(certificate);
	            System.out.println("CRL Verified");
	            System.out.println();
	            
	            
	            Collection<List<?>> issuerAlternativeNames = certificate.getIssuerAlternativeNames();
	            if (issuerAlternativeNames != null)
	            {
	            	System.out.println("Issuer alternative names: ");
	            	System.out.println(certificate.getIssuerAlternativeNames());
	            	System.out.println();
	            }
	            
	            Collection<List<?>> subjectAlternativeNames = certificate.getIssuerAlternativeNames();
	            if (issuerAlternativeNames != null)
	            {
	            	System.out.println("Subject alternative names: ");
	            	System.out.println(subjectAlternativeNames);
	            	System.out.println();
	            }
	            
	            System.out.println("Validity dates: ");
	            System.out.println(certificate.getNotBefore());
	            System.out.println(certificate.getNotAfter());
	            System.out.println();
	            
	            System.out.println("Certificate signature: ");
	            System.out.println(certificate.getSignature());
	            
	        } catch(CertificateExpiredException cee) {
	            System.err.println("Certificate is expired");
			} catch (CertificateNotYetValidException e) {
				e.printStackTrace();
			} catch (CertificateVerificationException e) {
				e.printStackTrace();
			} catch (CertificateParsingException e) {
				e.printStackTrace();
			}	           
	    }

	    
	    Util.printDelimiter();
	    
	    Set<X509Certificate> trustedCertificates = CertificateVerifier.getTrustedCertificates();
	    Set<X509Certificate> intermediateCertificates = new HashSet<X509Certificate>();
	    X509Certificate certificate = certificates[0];
	    
	    intermediateCertificates.addAll(Arrays.asList(certificates));
	    
	    try {
			CertificateVerifier.verifyCertificate(certificate, trustedCertificates, intermediateCertificates);
			
			for (int i = 0; i < certificates.length - 1; i++) {
		    	certificates[i].verify(certificates[i+1].getPublicKey());
			}
			System.out.println("Certificate chain verified");
			
		} catch (CertificateVerificationException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
	    
	    Util.printDelimiter();
	}
	
	/**
	 * Shows detailed information about validity such as the exact time left to expire and others.
	 * 
	 * @param destinationURL - WebSite URL (e.g. www.example.com).
	 */
	public static void showCertificateValidityDateInfo(URL destinationURL)
	{
		final String UTC_TIMEZONE = "UTC";
		
		HttpsURLConnection connection = null;
		SSLContext sslContext;
		X509Certificate[] certificates = null;
		try {
			sslContext = SSLContext.getInstance(TLS_v1_2_PROTOCOL);
			
			// Init the SSLContext with a TrustManager[] and SecureRandom()
			sslContext.init(null, null, null);
			
			connection = (HttpsURLConnection) destinationURL.openConnection();
		    connection.setSSLSocketFactory(sslContext.getSocketFactory());
		    connection.connect();
		    
			certificates = (X509Certificate[]) connection.getServerCertificates();
			

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (KeyManagementException e) {
			e.printStackTrace();
		} catch (SSLHandshakeException e){
			System.err.println(e.getMessage());
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		DateTimeFormatter dateTimePattern = DateTimeFormatter.ofPattern("MMM d yyyy  hh:mm a O");
	    
	    ZonedDateTime currentDate = ZonedDateTime.now(Clock.systemUTC());
		ZonedDateTime startDate;
		ZonedDateTime expirationDate;
		
		for (X509Certificate certificate : certificates)
		{
			// Conversion of Date to ZonedDateTime (Java 8)
			startDate = ZonedDateTime.ofInstant(certificate.getNotBefore().toInstant(), ZoneId.of(UTC_TIMEZONE));
			expirationDate = ZonedDateTime.ofInstant(certificate.getNotAfter().toInstant(), ZoneId.of(UTC_TIMEZONE));
			
			System.out.println("Subject: ");
            System.out.println(certificate.getSubjectX500Principal());
            System.out.println();
            
            System.out.println("Issuer: ");
            System.out.println(certificate.getIssuerX500Principal());
            System.out.println();
            
            System.out.println("Serial Number: ");
            System.out.println(certificate.getSerialNumber());
            System.out.println();
            
            System.out.println("Validity dates: ");
			System.out.println(startDate.format(dateTimePattern));
			System.out.println(expirationDate.format(dateTimePattern));
			System.out.println();
			
			System.out.println("Now: ");
			System.out.println(currentDate.format(dateTimePattern));
			System.out.println();
			
			
			if (startDate.isBefore(currentDate))
			{
				System.out.println("This certificate is valid since");
				Util.showTimeDifference(startDate, currentDate);
				System.out.println("ago");
			}
			else
			{
				System.out.println("This certificate is going to be valid from");
				Util.showTimeDifference(currentDate, expirationDate);
			}
			
			System.out.println();
			
			if (expirationDate.isAfter(currentDate))
			{
				System.out.println("This certificate is still valid for");
				Util.showTimeDifference(currentDate, expirationDate);
			}
			else
			{
				System.out.println("This certificate expired since");
				Util.showTimeDifference(expirationDate, currentDate);
				System.out.println("ago");
			}
			Util.printDelimiter();
		}
	}
}

package test;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.TimeZone;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.sun.net.ssl.internal.ssl.Provider;

import sslCertificationLibrary.verifier.CRLVerifier;
import sslCertificationLibrary.verifier.CertificateVerificationException;
import sslCertificationLibrary.verifier.CertificateVerifier;
import sslCertificationLibrary.verifier.ServerVerifier;

/**
 * @author Marcelo d'Almeida
 */

public class SSLCheck {
	
	static SSLSocket sslSocket = null;
	static PrintWriter out = null;
	static BufferedReader in = null;
	static X509Certificate[] serverCertificates = null;
	
	@BeforeClass
	public static void setUp()
	{
		//To get the server certificate in the first place in order to do the verification manually, 
		//irrespectively of whether it's valid or not, the easiest is to connect via an SSLSocket 
		//after having disabled any certificate verification.

		//Create an SSLContext that lets anything through:
	
		String serverName = "localhost"; // SSL Server Name
		int sslPort = 4443; // Port where the SSL Server is listening
		
		SSLContext sslContext = null;
		try {
			sslContext = SSLContext.getInstance(ServerVerifier.TLS_v1_2_PROTOCOL);
		} catch (NoSuchAlgorithmException e2) {
			e2.printStackTrace();
		}
		
		X509TrustManager disabledTrustManager = new X509TrustManager() {
		    @Override
		    public void checkClientTrusted(X509Certificate[] chain,
		            String authType) throws CertificateException {
		    }
	
		    @Override
		    public void checkServerTrusted(X509Certificate[] chain,
		            String authType) throws CertificateException {
		    }
	
		    @Override
		    public X509Certificate[] getAcceptedIssuers() {
		        return null;
		    }
		};
		
		
		
		try {
			sslContext.init(null, new TrustManager[] { disabledTrustManager },
			        null);
		} catch (KeyManagementException e1) {
			e1.printStackTrace();
		}
	
		//Create a socket, connect and start the handshake explicitly (since you're not really going to read form it):
	
		// Registering the JSSE (and BouncyCastle) provider
		Security.addProvider(new Provider());
		Security.addProvider(new BouncyCastleProvider());
		
		System.setProperty("javax.net.ssl.trustStore","keystore.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "keystore");
		
		// Enable debugging to view the handshake and communication which happens between the SSLClient and the SSLServer
		System.setProperty("javax.net.debug","all");
		
		SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
		
		try {
			sslSocket = (SSLSocket) sslSocketFactory.createSocket(serverName, sslPort);
			sslSocket.startHandshake();
			
			out = new PrintWriter(sslSocket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		
		//Get the peer certificates chain. The first item is the actual server certificate.
		try {
			serverCertificates = (X509Certificate[]) sslSocket
			        .getSession().getPeerCertificates();
		} catch (SSLPeerUnverifiedException e1) {
			e1.printStackTrace();
		}
		
		// 'null' will initialize the tmf with the default CA certs installed
		// with the JRE.
		TrustManagerFactory trustManagerFactory = null;
		try {
			trustManagerFactory = TrustManagerFactory
			        .getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init((KeyStore) null);
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		
		X509TrustManager trustManager = (X509TrustManager) trustManagerFactory.getTrustManagers()[0];
		
		try {
		    // Assuming RSA key here.
		    trustManager.checkServerTrusted(serverCertificates, "RSA");
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		
		//To get the server certificate directly, you can use this:
		
	}
	
	@Test
	public void testThatCertificateIsValid()
	{	
		for (X509Certificate serverCertificate : serverCertificates)
		{
			Date currentDate = new Date();
			Date startDate = serverCertificate.getNotBefore();
			Date expirationDate = serverCertificate.getNotAfter();
			Date currentDateUTC = null;
			Date startDateUTC = null;
			Date expirationDateUTC = null;
			
			DateFormat formatter = DateFormat.getDateTimeInstance(DateFormat.FULL, DateFormat.FULL);
			formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
			
			try {
				currentDateUTC = formatter.parse(formatter.format(currentDate));
				startDateUTC = formatter.parse(formatter.format(startDate));
				expirationDateUTC = formatter.parse(formatter.format(expirationDate));
			} catch (ParseException e) {
				e.printStackTrace();
			}
		
			assertTrue(currentDateUTC.before(expirationDateUTC));
			assertTrue(currentDateUTC.after(startDateUTC));
		}
	}
	
	//public void 
	
	@Test
	public void testThatCertificateIsNotTrusted()
	{
		try {

			try {
				/*
				InetAddress inetAddress = InetAddress.getByName("216.58.192.4");
				String hostName = inetAddress.getHostName();
			    System.out.println ("Host Name: " + hostName);//display the host
			    */
			    
			    String hostName = "www.elavon.com";
			    
				ServerVerifier.verifyCertificates(new URL("https://" + hostName));
			} catch (MalformedURLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			Set<X509Certificate> trustedCertificates = CertificateVerifier.getTrustedCertificates();
			Set<X500Principal> trustedCertificatesIssuers = CertificateVerifier.getTrustedCertificatesIssuers(trustedCertificates);
            
            System.out.println(serverCertificates.length);
            for (X509Certificate serverCertificate : serverCertificates)
            {
            	
            	CRLVerifier.verifyCertificateCRLs(serverCertificate);
            	System.out.println("CRL Verfied");
            	
	            X500Principal serverCertificateIssuer = serverCertificate.getIssuerX500Principal();
	            System.out.println(serverCertificate.getSubjectX500Principal());
	            System.out.println(serverCertificate.getIssuerX500Principal());
	            assertTrue(!trustedCertificatesIssuers.contains(serverCertificateIssuer));
            }
            
            Set<X509Certificate> intermidiateCertificates = new HashSet<X509Certificate>();
            intermidiateCertificates.add(serverCertificates[1]);
            
            
            //PKIXCertPathBuilderResult result = 
            CertificateVerifier.verifyCertificate(serverCertificates[1], trustedCertificates, intermidiateCertificates);
            
        } catch (CertificateVerificationException e) {
			e.printStackTrace();
		}
	}	
	
	@Test
	public void testThatCertificateIsSelfSigned()
	{
		X509Certificate serverCertificate = serverCertificates[1];
		try 
		{
			assertTrue(CertificateVerifier.isSelfSigned(serverCertificate));
		} catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}		
	}
	
	@AfterClass
	public static void tearDown()
	{
		// Closing the Streams and the Socket
		try {
			out.close();
			in.close();
			sslSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}

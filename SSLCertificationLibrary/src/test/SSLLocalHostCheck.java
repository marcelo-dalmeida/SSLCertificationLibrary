package test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.sun.net.ssl.internal.ssl.Provider;

import sslCertificationLibrary.verifier.CertificateVerifier;
import sslCertificationLibrary.verifier.ServerVerifier;

/**
 * @author Marcelo d'Almeida
 */

public class SSLLocalHostCheck 
{
	static SSLSocket sslSocket = null;
	static PrintWriter out = null;
	static BufferedReader in = null;
	static X509Certificate[] serverCertificates = null;
	
	@BeforeClass
	public static void setUp()
	{	
		try 
		{
			Thread.sleep(5000);
		} catch (InterruptedException e3) {
			e3.printStackTrace();
		} 
		
		//To get the server certificate in the first place in order to do the verification manually, 
		//irrespectively of whether it's valid or not, the easiest is to connect via an SSLSocket 
		//after having disabled any certificate verification.

		//Create an SSLContext that lets anything through:
	
		// SSL Server Name
		String serverName = "localhost"; 
		// Port where the SSL Server is listening
		int sslPort = 4443; 
		
		SSLContext sslContext = null;
		try {
			sslContext = SSLContext.getInstance(ServerVerifier.TLS_v1_2_PROTOCOL);
		} catch (NoSuchAlgorithmException e2) {
			e2.printStackTrace();
		}
		
		X509TrustManager disabledTrustManager = new X509TrustManager() 
		{
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
	
		// Registering the JSSE and BouncyCastle providers
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
	
	/**
	 * "TO DO"
	 */
	@Test
	public void testThatCertificateIsValid()
	{	
		for (X509Certificate serverCertificate : serverCertificates)
		{
			try {
				serverCertificate.checkValidity();
			} catch (CertificateExpiredException e1) {
				fail();
				e1.printStackTrace();
			} catch (CertificateNotYetValidException e1) {
				fail();
				e1.printStackTrace();
			}
		}
	}
	
	/**
	 * "TO DO"
	 */
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

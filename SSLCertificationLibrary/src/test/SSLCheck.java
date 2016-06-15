package test;

import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.sun.net.ssl.internal.ssl.Provider;

import sslCertificationLibrary.CRLVerifier;
import sslCertificationLibrary.CertificateVerificationException;
import sslCertificationLibrary.CertificateVerifier;

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
			sslContext = SSLContext.getInstance("TLS");
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
	
		// Registering the JSSE provider
		Security.addProvider(new Provider());
		
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
            
            System.out.println(serverCertificates.length);
            for (X509Certificate serverCertificate : serverCertificates)
            {
            	
            	CRLVerifier.verifyCertificateCRLs(serverCertificate);
            	System.out.println("VERIFIED VERIFIED VERIFIED");
            	
            	
            	Scanner scanner = new Scanner(System.in);
            	System.out.println("Continue?");
                scanner.nextLine();
	            X500Principal serverCertificateIssuer = serverCertificate.getIssuerX500Principal();
	            System.out.println(serverCertificate.getSubjectX500Principal());
	            System.out.println(serverCertificate.getIssuerX500Principal());
	            assertTrue(!trustedCertificateIssuers.contains(serverCertificateIssuer));
            }
            
            Set<X509Certificate> intermidiateCertificates = new HashSet<X509Certificate>();
            intermidiateCertificates.add(serverCertificates[1]);
            
            
            PKIXCertPathBuilderResult result = CertificateVerifier.verifyCertificate(serverCertificates[1], trustedCertificates,
        			intermidiateCertificates);
            
        } catch (CertificateException e) {
        	e.printStackTrace();
        } catch (KeyStoreException e) {
        	e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
        	e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
        	e.printStackTrace();
        } catch (IOException e) {
        	e.printStackTrace();
        } catch (CertificateVerificationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}	
	
	@Test
	public void testThatCertificateIsSelfSigned()
	{
		X509Certificate serverCertificate = serverCertificates[1];
		try {
			assertTrue(SSLCheck.isSelfSigned(serverCertificate));
		} catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}		
	}
	
	/**
	 * Checks whether given X.509 certificate is self-signed.
	 */
	public static boolean isSelfSigned(X509Certificate cert)
			throws CertificateException, NoSuchAlgorithmException,
			NoSuchProviderException 
	{
		try {
			// Try to verify certificate signature with its own public key
			PublicKey key = cert.getPublicKey();
			cert.verify(key);
			return true;
		} catch (SignatureException sigEx) {
			// Invalid signature --&gt; not self-signed
			return false;
		} catch (InvalidKeyException keyEx) {
			// Invalid key --&gt; not self-signed
			return false;
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

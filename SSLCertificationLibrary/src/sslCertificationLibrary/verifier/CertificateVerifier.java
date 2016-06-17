package sslCertificationLibrary.verifier;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * Class for building a certification chain for given certificate and verifying
 * it. Relies on a set of root CA certificates and intermediate certificates
 * that will be used for building the certification chain. The verification
 * process assumes that all self-signed certificates in the set are trusted
 * root CA certificates and all other certificates in the set are intermediate
 * certificates.
 * 
 * @author Svetlin Nakov (base code)
 * Adapted by Marcelo d'Almeida
 * 
 * @author Marcelo d'Almeida (additional code)
 */
public class CertificateVerifier 
{		
	
	/**
	 * Attempts to build a certification chain for given certificate and to verify
	 * it. Relies on a set of root CA certificates (trust anchors) and a set of
	 * intermediate certificates (to be used as part of the chain).
	 * @param certificate - certificate for validation
	 * @param trustedRootCertificates - set of trusted root CA certificates
	 * @param intermediateCertificates - set of intermediate certificates
	 * @return the certification chain (if verification is successful)
	 * @throws GeneralSecurityException - if the verification is not successful
	 * 		(e.g. certification path cannot be built or some certificate in the
	 * 		chain is expired)
	 */
	public static PKIXCertPathBuilderResult verifyCertificate(X509Certificate certificate, Set<X509Certificate> trustedRootCertificates,
			Set<X509Certificate> intermediateCertificates) throws CertificateVerificationException
	{	
		// Create the selector that specifies the starting certificate
		X509CertSelector selector = new X509CertSelector(); 
	    selector.setCertificate(certificate);
	    
	    // Create the trust anchors (set of root CA certificates)
	    Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
	    for (X509Certificate trustedRootCertificate : trustedRootCertificates) 
	    {
	    	trustAnchors.add(new TrustAnchor(trustedRootCertificate, null));
	    }
	    
	    Set<X509Certificate>  allCertificates = new HashSet<X509Certificate>();
	    allCertificates.addAll(trustedRootCertificates);
	    allCertificates.addAll(intermediateCertificates);
	    allCertificates.add(certificate);
	    PKIXCertPathBuilderResult result = null;
	    
	    try
	    {
	    	// Configure the PKIX certificate builder algorithm parameters
		    PKIXBuilderParameters pkixParameters = 
				new PKIXBuilderParameters(trustAnchors, selector);
			
			// Disable CRL checks (this is done manually as additional step)
			pkixParameters.setRevocationEnabled(false);
		
			// Specify a list of intermediate certificates
			CertStore intermediateCertificateStore = CertStore.getInstance("Collection",
				new CollectionCertStoreParameters(intermediateCertificates), "BC");
			pkixParameters.addCertStore(intermediateCertificateStore);
		
			// Build and verify the certification chain
			CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");
			result = (PKIXCertPathBuilderResult) builder.build(pkixParameters);
		
	    }catch (CertPathBuilderException certPathEx) {
	    	System.err.println("Unable to find certificate chain");
			//throw new CertificateVerificationException(
			//		"Error building certification path: " + 
			//		cert.getSubjectX500Principal(), certPathEx);
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}
    	return result;
	}
	
	/**
	 * Checks whether given X.509 certificate is self-signed.
	 */
	public static boolean isSelfSigned(X509Certificate certificate)
			throws CertificateException, NoSuchAlgorithmException,
			NoSuchProviderException 
	{
		try 
		{
			// Try to verify certificate signature with its own public key
			PublicKey key = certificate.getPublicKey();
			certificate.verify(key);
			return true;
			
		} catch (SignatureException sigEx) {
			// Invalid signature -- not self-signed
			return false;
		} catch (InvalidKeyException keyEx) {
			// Invalid key -- not self-signed
			return false;
		}
	}
	
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
	
	public static Set<X500Principal> getTrustedCertificatesIssuers()
	{
		Set<X509Certificate> trustedCertificates = getTrustedCertificates();
		return getTrustedCertificatesIssuers(trustedCertificates);
	}
	
	public static Set<X500Principal> getTrustedCertificatesIssuers(Set<X509Certificate> trustedCertificates)
	{
	    Set<X500Principal> trustedCertificatesIssuers = new HashSet<X500Principal>();
	    
	    for (X509Certificate certificate : trustedCertificates) 
	    {
            X500Principal certificateIssuer = certificate.getIssuerX500Principal();
            trustedCertificatesIssuers.add(certificateIssuer);
            //System.out.println(certificate);
		}
	    return trustedCertificatesIssuers;
	}
}

package sslCertificationLibrary.verifier;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

//Requires bouncy castle
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;


/**
 * Class that verifies CRLs for given X509 certificate. Extracts the CRL
 * distribution points from the certificate (if available) and checks the
 * certificate revocation status against the CRLs coming from the
 * distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
 * 
 * @author Svetlin Nakov
 * Adapted by Marcelo d'Almeida
 */

public class CRLVerifier {

	
	/*
	 * Requires Bouncy Castle
	 */
	/**
	 * Extracts the CRL distribution points from the certificate (if available)
	 * and checks the certificate revocation status against the CRLs coming from
	 * the distribution points. Supports HTTP, HTTPS, FTP and LDAP based URLs.
	 * 
	 * @param certificate the certificate to be checked for revocation
	 * @throws CertificateVerificationException if the certificate is revoked
	 */
	
	public static void verifyCertificateCRLs(X509Certificate certificate)
			throws CertificateVerificationException 
	{
		try 
		{
			List<String> crlDistributionPoints = getCrlDistributionPoints(certificate);
			for (String crlDistributionPoint : crlDistributionPoints) 
			{
				X509CRL crl = downloadCRL(crlDistributionPoint);
				if (crl.isRevoked(certificate)) {
					throw new CertificateVerificationException(
							"The certificate is revoked by CRL: " + crlDistributionPoint);
				}
			}
		} catch (Exception ex) {
			if (ex instanceof CertificateVerificationException) 
			{
				throw (CertificateVerificationException) ex;
			} 
			else 
			{
				throw new CertificateVerificationException(
						"Can not verify CRL for certificate: " + 
						certificate.getSubjectX500Principal());
			}
		}
	}
	
	
	/**
	 * Downloads CRL from given URL. Supports http, https, ftp and ldap based URLs.
	 */
	private static X509CRL downloadCRL(String crlURL) throws IOException,
			CertificateException, CRLException,
			CertificateVerificationException, NamingException 
	{
		if (crlURL.startsWith("http://") || crlURL.startsWith("https://")
				|| crlURL.startsWith("ftp://")) 
		{
			X509CRL crl = downloadCRLFromWeb(crlURL);
			return crl;
		} 
		else if (crlURL.startsWith("ldap://")) 
		{
			X509CRL crl = downloadCRLFromLDAP(crlURL);
			return crl;
		} 
		else 
		{
			throw new CertificateVerificationException(
					"Can not download CRL from certificate " +
					"distribution point: " + crlURL);
		}
	}

	/**
	 * Downloads a CRL from given LDAP url, e.g.
	 * ldap://ldap.infonotary.com/dc=identity-ca,dc=infonotary,dc=com
	 */
	private static X509CRL downloadCRLFromLDAP(String ldapURL) 
			throws CertificateException, NamingException, CRLException, 
			CertificateVerificationException 
	{
		Hashtable<String, String> environment = new Hashtable<String, String>();
		environment.put(Context.INITIAL_CONTEXT_FACTORY, 
				"com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(Context.PROVIDER_URL, ldapURL);

        DirContext context = new InitialDirContext(environment);
        Attributes attributes = context.getAttributes("");
        Attribute atribute = attributes.get("certificateRevocationList;binary");
        byte[] value = (byte[])atribute.get();
        if ((value == null) || (value.length == 0)) 
        {
        	throw new CertificateVerificationException(
        			"Can not download CRL from: " + ldapURL);
        } 
        else 
        {
        	InputStream inputStream = new ByteArrayInputStream(value);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        	X509CRL crl = (X509CRL)certificateFactory.generateCRL(inputStream);
        	return crl;
        }
	}
	
	/**
	 * Downloads a CRL from given HTTP/HTTPS/FTP URL, e.g.
	 * http://crl.infonotary.com/crl/identity-ca.crl
	 */
	private static X509CRL downloadCRLFromWeb(String crlURL)
			throws MalformedURLException, IOException, CertificateException,
			CRLException 
	{
		URL url = new URL(crlURL);
		InputStream crlStream = url.openStream();
		
		try 
		{
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509CRL crl = (X509CRL) certificateFactory.generateCRL(crlStream);
			return crl;
		} 
		finally 
		{
			crlStream.close();
		}
	}
	
	
	/*
	 * Requires Bouncy Castle
	 */
	/**
	 * Extracts all CRL distribution point URLs from the "CRL Distribution Point"
	 * extension in a X.509 certificate. If CRL distribution point extension is
	 * unavailable, returns an empty list. 
	 */
	public static List<String> getCrlDistributionPoints(
			X509Certificate certificate) throws CertificateParsingException, IOException 
	{
		byte[] crlDistributionPointsExtension = certificate.getExtensionValue(
				Extension.cRLDistributionPoints.getId());
		if (crlDistributionPointsExtension == null) 
		{
			List<String> emptyList = new ArrayList<String>();
			return emptyList;
		}
		
		ASN1InputStream asn1InputStream;
		ASN1Primitive primitive;
		
		asn1InputStream = new ASN1InputStream(
				new ByteArrayInputStream(crlDistributionPointsExtension));
		primitive = asn1InputStream.readObject();
		asn1InputStream.close();
		DEROctetString crlDistributionPointsOctet = (DEROctetString) primitive;
		
		byte[] crlDistributionPointsExtensionOctets = crlDistributionPointsOctet.getOctets();
		
		asn1InputStream = new ASN1InputStream(
				new ByteArrayInputStream(crlDistributionPointsExtensionOctets));
		primitive = asn1InputStream.readObject();
		asn1InputStream.close();
		CRLDistPoint distributionPoints = CRLDistPoint.getInstance(primitive);
		
		List<String> crlUrls = new ArrayList<String>();
		
		for (DistributionPoint distributionPoint : distributionPoints.getDistributionPoints()) 
		{
            DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
            // Look for URIs in fullName
            if (distributionPointName != null) 
            {
                if (distributionPointName.getType() == DistributionPointName.FULL_NAME) 
                {
                    GeneralName[] generalNames = GeneralNames.getInstance(
                        distributionPointName.getName()).getNames();
                    // Look for an URI
                    for (int j = 0; j < generalNames.length; j++) 
                    {
                        if (generalNames[j].getTagNo() == GeneralName.uniformResourceIdentifier) 
                        {
                            String url = DERIA5String.getInstance(
                                generalNames[j].getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
		}
		return crlUrls;
	}
}

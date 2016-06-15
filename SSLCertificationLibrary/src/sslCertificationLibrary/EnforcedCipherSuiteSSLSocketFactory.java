package sslCertificationLibrary;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class EnforcedCipherSuiteSSLSocketFactory extends SSLSocketFactory 
{
	private final String ENFORCED_CIPHER_SUITE;
	
	private final SSLSocketFactory delegate;
	
	public EnforcedCipherSuiteSSLSocketFactory(SSLSocketFactory delegate, String enforced_cipher_suite) {
	
	    this.delegate = delegate;
	    this.ENFORCED_CIPHER_SUITE = enforced_cipher_suite;
	}
	
	@Override
	public String[] getDefaultCipherSuites() {
	
	    return setupEnforcedCipherSuites(this.delegate);
	}
	
	@Override
	public String[] getSupportedCipherSuites() {
	
	    return setupEnforcedCipherSuites(this.delegate);
	}
	
	@Override
	public Socket createSocket(String arg0, int arg1) throws IOException,
	        UnknownHostException {
	
	    Socket socket = this.delegate.createSocket(arg0, arg1);
	    String[] cipherSuites = setupEnforcedCipherSuites(delegate);
	    ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
	
	    return socket;
	}
	
	@Override
	public Socket createSocket(InetAddress arg0, int arg1) throws IOException {
	
	    Socket socket = this.delegate.createSocket(arg0, arg1);
	    String[] cipherSuites = setupEnforcedCipherSuites(delegate);
	    ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
	
	    return socket;
	}
	
	@Override
	public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3)
	        throws IOException {
	
	    Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
	    String[] cipherSuites = setupEnforcedCipherSuites(delegate);
	    ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
	
	    return socket;
	}
	
	@Override
	public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3)
	        throws IOException, UnknownHostException {
	
	    Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
	    String[] cipherSuites = setupEnforcedCipherSuites(delegate);
	    ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
	
	    return socket;
	}
	
	@Override
	public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2,
	        int arg3) throws IOException {
	
	    Socket socket = this.delegate.createSocket(arg0, arg1, arg2, arg3);
	    String[] cipherSuites = setupEnforcedCipherSuites(delegate);
	    ((SSLSocket)socket).setEnabledCipherSuites(cipherSuites);
	
	    return socket;
	}
	
	private String[] setupEnforcedCipherSuites(SSLSocketFactory sslSocketFactory) 
	{
	    String[] suitesList = {ENFORCED_CIPHER_SUITE};
	    return suitesList;
	}
}

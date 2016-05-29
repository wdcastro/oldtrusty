import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.TrustManagerFactory;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public class server {
	
	public static String pass;
	public static int nextid = 0;
	public server(){
		

	}
	
	public static void main(String args[]){
		System.setProperty("https.protocol", "SSLv3");
		//code for listening to new socket connection
		if(args.length != 2){
			System.out.println("Usage: java server <portnumber> <pass>");
			System.exit(1);
		}
		
		pass = args[1];
		
		Boolean listening = true;
		
		
		
		try {
			//create sockets
			cert.initCryptoServer(args[1]);
			SSLContext context;
			context = SSLContext.getInstance("SSLv3");
			System.out.println("context protocol :" + context.getProtocol());
			
			
			TrustManager[] trustAllCerts = (TrustManager[]) new TrustManager[] {
					new TrustManager() {
		                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
		                }

		                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
		                }

		                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
		                	
		                    return new X509Certificate[0];
		                }
		            }
		    };
			
			KeyStore ks = KeyStore.getInstance("JKS");
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			
			FileInputStream fis = new FileInputStream("KeyStore");
			ks.load(fis, args[1].toCharArray());
			if(ks.containsAlias("oldtrusty")) {
		    	System.out.println("Found the server certificate");
		    }
		    else {
		    	System.out.println("You fucked up");
		    }
			fis.close();
			kmf.init(ks, args[1].toCharArray());
			
			
			System.out.println("Store lists------------------");
			Enumeration<String> en = ks.aliases();
			while(en.hasMoreElements()){
				System.out.println(en.nextElement());
			}
			System.out.println("Store lists end------------------");
			//System.out.println("contains noah "+ ks.aliases());
			//tmf.init(ks);
			context.init(kmf.getKeyManagers(), trustAllCerts, null);
			
			SSLServerSocketFactory ssf = (SSLServerSocketFactory) context.getServerSocketFactory();
			SSLServerSocket ss= (SSLServerSocket) ssf.createServerSocket(Integer.parseInt(args[0]));
			
			//ss.setNeedClientAuth(true);
			System.out.println("server socket created "+ args[0]);
			
			ss.setEnabledProtocols(new String[]{"SSLv3"});
			System.out.println("ssl version set");

			/*System.out.println("ciphers");
			String[] a = ss.getSSLParameters().getCipherSuites();
			for(int i = 0; i< a.length; i++){
			System.out.println(a[i]);
			}
			System.out.println("protocols");
			String[] b = ss.getSSLParameters().getProtocols();
			for(int i = 0; i< b.length; i++){
			System.out.println(b[i]);
			}*/
			
			/*
			System.out.println("supported protocols");
			String[] c = ss.getSupportedProtocols();
			for(int i = 0; i< c.length; i++){
			System.out.println(c[i]);
			}
			System.out.println("enabled ciphers");
			String[] d = ss.getEnabledCipherSuites();
			for(int i = 0; i< d.length; i++){
			System.out.println(d[i]);
			}*/
			while(listening){
				
				//start new thread on accept
				System.out.println("listening");
				new ServerThread((SSLSocket) ss.accept(), args[1]).start();
			}
			System.out.println("loop left");
		} catch (IOException e) {
			System.out.println(e);
			System.exit(-1);
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e);
			System.exit(-1);
		} catch (KeyManagementException e){
			System.out.println(e);
			System.exit(-1);
			
		} catch (InvalidKeyException | NoSuchPaddingException | CertificateException | SignatureException
				| NoSuchProviderException | KeyStoreException | IllegalBlockSizeException | BadPaddingException
				| InvalidParameterSpecException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			System.out.println(e);
			System.exit(-1);
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}

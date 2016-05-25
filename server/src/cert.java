import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Enumeration;

import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;

/**
 * @author Joel-Dunstan - 21318856
 * The cert class has the task of managing the server's certificates whether
 * it be creating the server's certificate, verifying digital signatures, getting the 
 * length of a circle of trust etc.
 * The SeverThread class which listens for clients starting a handshake will call these 
 * methods based upon the commands provided by the user. The server class will end up
 * using these methods to start up the server and initialize it and its ceritficates and
 * keys.
 */
public class cert {
	/**
	 * This is the mthod for encrypted a file. It takes in a byte array and 
	 * encrypts it using AES128 PBE (<b>P</b>assword <b>B</b>ased <b>E</b>ncryption)
	 * The salt essentially turns the password into 128 bits and the iv increases the 
	 * randomness of the encryption instead of just relying on the key. As a note Java by default
	 * applies a new IV each time, however I store the iv here so I can reuse the encryption
	 * properly without needing to keep track of variation. Storing the salt and iv does not
	 * weaken the AES128 PBE encryption as at the end of the day it still relies on a password
	 * that a possible man in the middle or intruder peeking into the servers files wouldn't know.
	 * Code based upon and adapted from:
	 * javapapers.com/java/java-file-encryption-decryption-using-aes-password-based-encryption-pbe/
	 * @param file the byte array of the file we're encrypting
	 * @param password the password that we will use for the encryption
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidParameterSpecException 
	 */
	public static byte[] encrypt(byte[] file, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {

			// password, iv and salt should be transferred to the other end
			// in a secure manner

			// salt is used for encoding
			// writing it to a file
			// salt should be transferred to the recipient securely
			// for decryption
		    byte[] salt;
		    byte[] iv;
		    byte[] encrypted;
			try {
				FileInputStream saltInFile = new FileInputStream("salt.enc");
				salt = new byte[saltInFile.available()];
				saltInFile.read(salt);
				saltInFile.close();
				
				FileInputStream ivInFile = new FileInputStream("iv.enc");
				iv = new byte[ivInFile.available()];
				ivInFile.read(iv);
				ivInFile.close();
				
				SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
				KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
				SecretKey secretKey = factory.generateSecret(keySpec);
				SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

				//
				Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
				c.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(iv));
				encrypted = c.doFinal(file);
			}
			catch (FileNotFoundException e) {
				salt = new byte[8];
				SecureRandom secureRandom = new SecureRandom();
				secureRandom.nextBytes(salt);
				FileOutputStream saltOutFile = new FileOutputStream("salt.enc");
				saltOutFile.write(salt);
				saltOutFile.close();

				SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
				KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
				SecretKey secretKey = factory.generateSecret(keySpec);
				SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

				//
				Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
				c.init(Cipher.ENCRYPT_MODE, secret);
				AlgorithmParameters params = c.getParameters();

				// iv adds randomness to the text and just makes the mechanism more
				// secure
				// used while initializing the cipher
				// file to store the iv
				FileOutputStream ivOutFile = new FileOutputStream("iv.enc");
				iv = params.getParameterSpec(IvParameterSpec.class).getIV();
				ivOutFile.write(iv);
				ivOutFile.close();
				encrypted = c.doFinal(file);
			}
			return encrypted;
	}
	
	/**
	 * This the method for decrypting a file which is sent to this method
	 * encrypted and in byte array format. The decryption is based off
	 * AES128 PBE (<b>P</b>assword <b>B</b>ased <b>E</b>ncryption) which was used
	 * to encrypt the file in the first place.
	 * javapapers.com/java/java-file-encryption-decryption-using-aes-password-based-encryption-pbe/
	 * @param file
	 * @param password
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] decrypt(byte[] file, String password) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] decrypted;
		FileInputStream saltInFile = new FileInputStream("salt.enc");
		byte[] salt = new byte[saltInFile.available()];
		saltInFile.read(salt);
		saltInFile.close();
		
		FileInputStream ivInFile = new FileInputStream("iv.enc");
		byte[] iv = new byte[ivInFile.available()];
		ivInFile.read(iv);
		ivInFile.close();
		
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
		SecretKey secretKey = factory.generateSecret(keySpec);
		SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

		//
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
		decrypted = c.doFinal(file);
		return decrypted;
	}
	
	/**
	 * Initialize all the server encryption and decryption mechanisms. In this method
	 * we will set up the keys, certificate(s) and keystore if the oldtrusty certificates
	 * and/or keystore don't exist:
	 * (In order)
	 * The server keys are created
	 * A Self Signed X509 certificate is created using the keys
	 * Store the certificates one in .cer format the other in .pem format
	 * Create the KeyStore
	 * Store the server certificate and private key in the KeyStore
	 * Store the KeyStore File
	 * @param password the password used by the server for encryption/decryption 
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchProviderException 
	 * @throws SignatureException 
	 * @throws CertificateException 
	 * @throws InvalidKeyException 
	 * @throws KeyStoreException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidParameterSpecException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	@SuppressWarnings({ "unused", "resource" })
	public static void initCryptoServer(String password) 
	throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException, CertificateException, SignatureException, NoSuchProviderException, KeyStoreException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		try {
			FileInputStream keystore = new FileInputStream("KeyStore");
			FileInputStream oldcer = new FileInputStream("oldtrusty.cer");
			FileInputStream oldpem = new FileInputStream("oldtrusty.pem");
		}
		catch (Exception e) {
			/*
			 * Code adapted from 
			 * http://www.pixelstech.net/article/1406724116-Generate-certificate-in-Java----Self-signed-certificate
			 */
			CertAndKeyGen keyGen = new CertAndKeyGen("RSA","SHA256WithRSA");
			keyGen.generate(2048);
			//Generate self signed certificate
			X509Certificate[] chain = new X509Certificate[1];
			chain[0]=keyGen.getSelfCertificate(new X500Name("O=oldtrusty"), (long)365*24*3600);
			PrivateKey privkey = keyGen.getPrivateKey();
			
			//Store the certificate in .cer format
			FileOutputStream fos = new FileOutputStream("oldtrusty.cer");
			fos.write(chain[0].getEncoded());
			fos.close();
			
			//Convert the X509 Certificate to Base64 String, store Certificate as .pem
			BASE64Encoder encoder = new BASE64Encoder();
		    String PEM = X509Factory.BEGIN_CERT+"\n"+encoder.encodeBuffer(chain[0].getEncoded())+X509Factory.END_CERT;
		    System.out.println(PEM);
		    byte[] pemByte = PEM.getBytes();
		    FileOutputStream pemOut = new FileOutputStream("oldtrusty.pem");
		    pemOut.write(pemByte);
		    pemOut.close();
			
			// Create the Key Store
			KeyStore ks = KeyStore.getInstance("JKS");
			char[] pass = password.toCharArray();
		    ks.load(null, pass);
		    //Add Server Certificate and Private Key
		    ks.setCertificateEntry("oldtrusty", chain[0]);
		    ks.setKeyEntry("private", privkey, password.toCharArray(), chain);
		    FileOutputStream keystore = new FileOutputStream("KeyStore");
		    ks.store(keystore, pass);
		    keystore.close();
		}
	}
	
	/**
	 * This method will validate certificates and save them to the keystore
	 * if the signature is valid and the date is valid.
	 * A signature is valid if it can be decrypted using the subject's 
	 * public key provided in the certificate entry. Once decrypted the Hash calculated
	 * will be calculated on the header to see if it matches the Hash provided after the decryption. 
	 * @param indip X509 Certificate to be Validated <i><b>I</b>'m <b>N</b>ot <b>D</b>odgy <b>I</b> <b>P</b>romise</i>
	 * @param fiscert the original byte array used to create the certificate 
	 * @throws GeneralSecurityException 
	 * @throws NoSuchAlgorithmException 
	 */
	public boolean validate(X509Certificate indip, byte[] fiscert) 
	throws NoSuchAlgorithmException, GeneralSecurityException {
		try {
			/*
			 * Checks the date is valid on the certificate
			 * There are two dates on the certificate the start date and the end date
			 * if the date (and time) is not within these dates (and times), then the
			 * checkValidity will throw an exception
			 */
			indip.checkValidity();
			//Grab the signature from the certificate
			byte[] sig = indip.getSignature();
			Signature sigtovalidate = Signature.getInstance(indip.getSigAlgName());
			sigtovalidate.initVerify(indip);
			sigtovalidate.update(fiscert);
			return sigtovalidate.verify(sig);
		}
		catch (CertificateExpiredException c) {
			System.out.println("Certificate Expired: " + c.getMessage());
			return false;
		}
		catch (CertificateNotYetValidException ny) {
			System.out.println("Certificate Not Valid Yet: " + ny.getMessage());
			return false;
		}
	}
	
	/**
	 * This method stores the certs that have been validated to be used later
	 * for people wanting to get files from the server. A keystore stores Certificates
	 * like so:
	 * <alias>, <Certificate>
	 * The alias identifies each certificate and what its vouching for , aliases are
	 * unique so if an alias already exists when you're trying to store a cert and alias
	 * under the same names, the keystore will recognize the alias and override the certificate
	 * currently associated with that alias. This makes it great for replacing invalid
	 * certificates if needed or simply removing certificates.
	 * Here I will assume all certificates have been self signed as there is no root authority
	 * hence the issuer and subject should be the same. The subject will be the alias.
	 * This will be used for the -u command on clients.
	 * @param validcert
	 * @param filename name of the file being vouched for
	 * @param password the password for the keystore
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public static void storeTrustedCert(X509Certificate validcert, String password)
	throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    FileInputStream keystore = new FileInputStream("KeyStore");
	    ks.load(keystore, pass);
	    keystore.close();
	    //This will allow someone to just upload their certificate to the server using -u
	    ks.setCertificateEntry(validcert.getSubjectX500Principal().toString(), validcert);
	    FileOutputStream out = new java.io.FileOutputStream("KeyStore");
	    ks.store(out, pass);
	    keystore.close();
	}
	
	/**
	 * This method is used for the vouching of files by clients and here it will check that
	 * @param cert2add
	 * @param filename
	 * @param password
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	public void addToTheCircleOfLife(X509Certificate cert2add, String filename, String password) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
	    ks.load(keystore, pass);
	    
	}

	private String getFilenameAlias(String filename, String password, KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
	    String theOne = null;
	    Enumeration<String> loa = ks.aliases();
	    while(loa.hasMoreElements()) {
	    	String c = loa.nextElement().toString();
	    	String[] splitc = c.split("-");
	    	if(splitc.length == 3) {
	    		if(c != null && splitc[0].equals(filename) && splitc[1].equals(splitc[2])) {
	    			theOne = c;
	    			break;
	    		}
	    	}
	    }
	    return theOne;
	}
	
	/**
	 * This method will be called upon detecting the -n command which
	 * is when the client has requested another client must be part of the circle
	 * of trust before they trust the file. For a client to be a part of the circle of
	 * trust they would have needed to sign another's certificate and hence I will
	 * simply look for a case where the alias contains
	 * <filename>-<issuer>-<name> 
	 * @param filename The name of the file
	 * @param name the name we're looking for
	 * @param password password for the keystore/encryption/server
	 * @return found true = found name false = not found name
	 */
	public static boolean wantedDOA(String filename,String name, String password) {
		boolean found = false;
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			char[] pass = password.toCharArray();
		    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
		    ks.load(keystore, pass);
		    keystore.close();
			Enumeration<String> loa = ks.aliases();
		    while(loa.hasMoreElements()) {
		    	String c = loa.nextElement().toString();
		    	String[] splitc = c.split("-");
		    	if(splitc.length == 3) {
		    		if(c != null && splitc[1].equals(filename) && splitc[2].contains(name)) {
		    			found = true;
		    			break;
		    		}
		    	}
		    }
		    return found;
		}
		catch (Exception e) {
			System.out.println(e + ": Name not found due to exception");
			found  = false;
			return found;
		}
	}
	
	/**
	 * This method will use the keystore and the filename to
	 * find all the vouches made for a file and simply record how
	 * many vouches have been made for that file, if there has been 
	 * enough vouches to meet the required diameter, then the file is trusted.
	 * @param rlength the required diameter for the circle of trust
	 * @return boolean true = rlength reached false = otherwise
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * 
	 */
	@SuppressWarnings("unused")
	public boolean gettingTheDist(int rlength, String password, String filename) 
	throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
	    ks.load(keystore, pass);
	    String theOne = getFilenameAlias(filename, password, ks);
	    if(theOne == null) {
	    	System.out.println("File does not exist in Keystore");
	    	return false;
	    }   
	    else {
	        
			Enumeration<String> es = ks.aliases();
	    	while(es.hasMoreElements()) {
	    		int count = 0;
	    		String check = es.nextElement();
	    	}
	    }
	    return false;
	}

//Will be commented out later	
public static void main(String args[]) 
throws IOException, KeyStoreException, GeneralSecurityException {
		cert.initCryptoServer(args[0]);
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			char[] pass = args[0].toCharArray();
		    FileInputStream keystore = new FileInputStream("KeyStore");
		    ks.load(keystore, pass);
		    if(ks.containsAlias("oldtrusty")) {
		    	System.out.println("Found the server certificate");
		    }
		    else {
		    	System.out.println("You fucked up");
		    }
		    keystore.close();
		    FileInputStream teste = new FileInputStream("Test.txt");
			byte[] test = new byte[teste.available()];
			teste.read(test);
			teste.close();
			byte[] ttw = encrypt(test, args[0]);
			FileOutputStream ttwtest = new FileOutputStream("TTW.txt");
			ttwtest.write(ttw);
			ttwtest.close();
			FileOutputStream dtest = new FileOutputStream("DTEST.txt");
			byte[] decryptest = decrypt(ttw, args[0]);
			dtest.write(decryptest);
			dtest.close();
		    Enumeration<String> s = ks.aliases();
		    while(s.hasMoreElements()) {
		    	System.out.println(s.nextElement().toString());
		    }
		}
		catch (Exception e) {
			System.out.println(e + "Didn't find Keystore");
		}
	}
}
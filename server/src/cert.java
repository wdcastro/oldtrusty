import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Enumeration;
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
 * it be creating the server's certificate, verifying digital signatures
 * To fully create a certificate we need to, in order:
 * 1) Initialize the certificate
 * 2) Add in the headers for the certificate
 * 3) Add in and create the Digital Signature for the server
 * 	3a) Create a irreversible Hash using data whether it be from a file or the certificate
 * 	3b) Create the digital signature
 * 4) Finalize Cert and store in a Keystore with an appropriate alias
 * 
 * To validate a digital signature and that the certificate
 * actually came from the right person we'll need to, in order:
 * 1) Retrieve the certificate
 * 2) Calculate the Digest based on the signature algorithm which will be SHA-256
 * 3) Decrypt the Signature with the Public Key provided
 * 4) Compare the two hashes together and see if they match
 * 5) Based on the result, in the case that they:
 * 	5a)
 * 		i)Match: Store the certificate in the keystore as a Trusted Certificate Entry,
 * 		acknowledge client as successful
 * 		ii)Don't Match: Discard the certificate and blacklist it via serial number,
 * 		send error message to client, tell them to make a new certificate
 */
public class cert {
	/**
	 * javapapers.com/java/java-file-encryption-decryption-using-aes-password-based-encryption-pbe/
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
	 * we will set up if they dont already exist:
	 * The server Keys Public and Private, if only one exists overwrite, assume lost or stolen.
	 * Create the certificate based upon these keys
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
	public static void initCryptoServer(String password) 
	throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, InvalidKeyException, CertificateException, SignatureException, NoSuchProviderException, KeyStoreException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		try {
			getServerKey("Public.key", password);
			getServerKey("Private.key", password);
		}
		catch (IOException e) {
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
			PublicKey pubkey = keyGen.getPublicKey();
			/*
			 * Code copied and adapted from:
			 * http://docs.oracle.com/javase/tutorial/security/apisign/step4.html
			 * They create files named public.key and private.key. 
			*/
			byte[] pub = encrypt(pubkey.getEncoded(), password);
			FileOutputStream pubkeyfos = new FileOutputStream("public.key");
			pubkeyfos.write(pub);
			pubkeyfos.close();
			byte[] pri = encrypt(privkey.getEncoded(), password);
			FileOutputStream prikeyfos = new FileOutputStream("private.key");
			prikeyfos.write(pri);
			prikeyfos.close();
			
			FileOutputStream fos = new FileOutputStream("oldtrusty.cer");
			fos.write(chain[0].getEncoded());
			fos.close();
			
			// Create the Key Store
			KeyStore ks = KeyStore.getInstance("JKS");
			char[] pass = password.toCharArray();
		    ks.load(null, pass);
		    ks.setCertificateEntry("oldtrusty", chain[0]);
		    FileOutputStream keystore = new java.io.FileOutputStream("KeyStore");
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
	public void storeTrustedCert(X509Certificate validcert, String password)
	throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
	    ks.load(keystore, pass);
	    //This will allow someone to just upload their certificate to the server using -u
	    ks.setCertificateEntry(validcert.getSubjectX500Principal().toString(), validcert);
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
	
	/**
	 * Retrieve the public or private key of the server.
	 * @param filename
	 * @return key The Private or Public key for the server
	 * @throws IOException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeySpecException 
	 */
	private static byte[] getServerKey(String filename, String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		FileInputStream keyFile = new java.io.FileInputStream(filename);
		byte[] key = new byte[keyFile.available()];
		keyFile.read(key);
		keyFile.close();
		byte[] dkey = decrypt(key, password);
		return dkey;
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
	 */
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
	    	@SuppressWarnings("unused")
			Enumeration<String> enumString = ks.aliases();
	    	
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
		    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
		    ks.load(keystore, pass);
		    if(ks.containsAlias("oldtrusty")) {
		    	System.out.println("Found the server certificate");
		    	System.out.println();
		    }
		    else {
		    	System.out.println("You fucked up");
		    }
		    keystore.close();
		}
		catch (FileNotFoundException e) {
			System.out.println("Didn't find Keystore");
		}
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
	}
}
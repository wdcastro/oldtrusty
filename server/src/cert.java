import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import sun.misc.*;
import sun.security.provider.X509Factory;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


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
	 * All this is done by the verify method provided by Java and by this awesome guy here
	 * http://www.jensign.com/JavaScience/IsCertTrusted/IsCertTrusted.java 
	 * @param indip X509 Certificate to be Validated <i><b>I</b>'m <b>N</b>ot <b>D</b>odgy <b>I</b> <b>P</b>romise</i>
	 * @param fiscert the original byte array used to create the certificate 
	 * @throws GeneralSecurityException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static boolean validate(X509Certificate indip, String signer, KeyStore ks) 
	throws NoSuchAlgorithmException, GeneralSecurityException {
		try {
			/*
			 * Checks the date is valid on the certificate
			 * There are two dates on the certificate the start date and the end date
			 * if the date (and time) is not within these dates (and times), then the
			 * checkValidity will throw an exception
			 */
			System.out.println("validate reached");
			System.out.println(indip+" "+signer+" "+ks);
			X509Certificate signerCert = (X509Certificate) ks.getCertificate(signer);
			System.out.println("signerCert is: "+ signerCert);
			if(indip.getIssuerX500Principal().equals(indip.getSubjectX500Principal())) {
				System.out.println("if conditions met validate");
				System.out.println("signercert pubkey is: " +signerCert.getPublicKey());
				indip.checkValidity();
				indip.verify(signerCert.getPublicKey());
				return true;
			}
			else {
				System.out.println("else conditions met validate");
				Enumeration<String> en = ks.aliases();

				X509Certificate signingcert = null;

				while (en.hasMoreElements())
				{
					X509Certificate storecert = null;
					String ali = (String)en.nextElement() ;
					if(ks.isCertificateEntry(ali))
					 {
						storecert = (X509Certificate)ks.getCertificate(ali);
						if( (storecert.getIssuerDN().getName()).equals(indip.getIssuerDN()))
						{
						 try{
							System.out.println("Found matching issuer DN cert in keystore:\r\nChecking signature on cert ...") ;
							indip.verify(storecert.getPublicKey()) ;
							System.out.println("Signature verified on certificate") ;
							signingcert = storecert;
							break;
						  }
						 catch(Exception exc){
							System.out.println("Failed to verify signature on certificate with matching cert DN");
						  }				
						}			
					}	
				}
				return true;
			}
		}
		catch (CertificateExpiredException c) {
			System.out.println("Certificate Expired: " + c.getMessage());
			return false;
		}
		catch (CertificateNotYetValidException ny) {
			System.out.println("Certificate Not Valid Yet: " + ny.getMessage());
			return false;
		}
		catch (Exception e) {
			System.out.println(e);
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
	 * the certificate is valid and then it will add the certificate to the corresponding alias
	 * in the keystore of the format
	 * <filename>-<issuer>-<subject>
	 * The filename being the filename of course, the issuer being the owner of the file
	 * or a previous signer.
	 * The subject is the one whose public key and signature is on the cert.
	 * A circle of trust is formed by 'linking' the aliases together.
	 * e.g.
	 * <Filename>-<A>-<B>
	 * <Filename>-<B>-<C>
	 * <Filename>-<C>-<D> and so on...
	 * @param cert2add
	 * @param filename
	 * @param password
	 * @throws IOException
	 * @throws GeneralSecurityException 
	 */
	public static void addToTheCircleOfLife(X509Certificate cert2add, String filename, KeyStore ks, String password) 
	throws IOException, GeneralSecurityException {
		//Validate the certificate
		if(validate(cert2add, cert2add.getSubjectX500Principal().toString(), ks)) {
		    //Create the string which will be the alias with format above
		    String alias = filename + "-" + cert2add.getIssuerX500Principal().toString() + "-" + cert2add.getSubjectX500Principal().toString();
		    //Add the entry
		    ks.setCertificateEntry(alias, cert2add);
		    //Save the KeyStore
		    FileOutputStream ksstore = new FileOutputStream("KeyStore");
		    char[] pass = password.toCharArray();
		    ks.store(ksstore, pass);
		    ksstore.close();
		}
		else {
			System.out.println("Validate Method return false, Certificate Invalid");
		}
	}

	/**
	 * Gets the first vouch for the file which should be by the person who added the file
	 * in the first place with say the person adding file is called Steve, then the Alias will be
	 * <Filename>-<Steve>-<Steve> for example.
	 * @param filename
	 * @param password
	 * @param ks
	 * @return theOne A string which is the name for the 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	private static String getFilenameAlias(String filename, KeyStore ks) 
	throws KeyStoreException {
	    String theOne = null;
	    Enumeration<String> loa = ks.aliases();
	    while(loa.hasMoreElements()) {
	    	String ss = loa.nextElement();
	    	String[] split = ss.split("-");
		    if(split.length == 3 && split[1].equals(split[2])) {
				theOne = ss;
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
	public static boolean wantedDOA(String filename,String name, KeyStore ks) {
		boolean found = false;
		try {
			Enumeration<String> loa = ks.aliases();
		    while(loa.hasMoreElements()) {
		    	String c = loa.nextElement();
		    	String[] splitc = c.split("-");
		    	if(splitc.length == 3) {
		    		if(c != null && splitc[0].equals(filename) && splitc[2].contains(name)) {
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
	 * @throws GeneralSecurityException 
	 * 
	 */
	public static int gettingTheDist(String filename, KeyStore ks) 
	throws IOException, GeneralSecurityException {
	    String theOne = getFilenameAlias(filename, ks);
	    if(theOne == null) {
	    	System.out.println("File does not exist in Keystore");
	    	return -1;
	    }   
	    else {
	    	System.out.println("\nGot through validation\n");
	    	int maxCount = 0;
	    	Enumeration<String> es = ks.aliases();
	    	ArrayList<String> aliases = Collections.list(es);
	    	/*
	    	 * The Arraylists are to keep track of the current circle(s) found
	    	 * the counts and issuers ArrayList are in sync, issuers[0] refers to count[0].
	    	 * This is to deal with when an issuer has got two or more certificates
	    	 * referring to them as issuer and each certificate having a different certificate
	    	 * I decided to use ArrayLists instead of possible recursion techniques to avoid
	    	 * exponential performance decreases when adding many different certificates to the 
	    	 * keystore.
	    	 * The ArrayList history is also synchronized with counts and issuers, this keeps
	    	 * track of the split that created the new circle. It does this by keeping the issuer
	    	 * name. 
	    	 */
	    	ArrayList<Integer> counts = new ArrayList<Integer>();
	    	ArrayList<String> issuers = new ArrayList<String>();
	    	ArrayList<String> history = new ArrayList<String>();
	    	//Initialize the ArrayLists each starting with the person who added the file
	    	counts.add(0);
	    	issuers.add(theOne.split("-")[1]);
	    	history.add(theOne.split("-")[1]);
	    	/*
	    	 * The nullcheck is used to check when all of the values in issuer are null
	    	 * if the rlength hasn't been reached by this point then the loop will end here
	    	 * and the method will return false
	    	 */
	    	//Start the counter for the ArrayLists
	    	int iteration = 0;
	    	for(int i = 0; i < issuers.size();)  {
	    		System.out.println("New iteration: " + iteration);
	    		System.out.println("issuers/counts index: " + i);
	    		System.out.println("Looking for issuer: " + issuers.get(i));
	    		System.out.println("Count: "+ counts.get(i) + "\n");
	    		/*
	    		 * If the issuer is null then a full circle has been found by either
	    		 * the current "circle" reaching back to client who added the file or 
	    		 * where the circle split into two (in other words when the issuer was found more than once
	    		 * inside the enumeration hence adding a new string object to issuers and an int to count)
	    		 * Hence no need to investigate further so continue on through issuers.
	    		 */
	    		if(issuers.get(i) == null) {
	    			System.out.println("Found current one to be null continue on\n");
	    			continue;
	    		}
	    		/*
	    		 * If it isn't null then more investigation needed, put null check as false 
	    		 * so the loop will reset by putting i to 0 and nullcheck to true in order to keep going 
	    		 * until the while loop conditions all are all false or the length has been reached
	    		 */
	    		//The keeps track of if the issuer has been found already
	    		boolean issuerfound = false;
	    		String issuer = issuers.get(i);
	    		/*
	    		 * Iterate through the list of aliases to find issuer
	    		 */
		    	for(String alias: aliases) {
		    		String[] check = alias.split("-");
		    		//If the check string array isn't of length 3 ignore it
		    		if(check.length == 3) {
			    		//Given that no other issuer has been found already and we found a new signer update the lists
			    		if(!issuerfound && check[1].equals(issuer) && !check[1].equals(check[2])) {
								if(validate((X509Certificate) ks.getCertificate(alias), check[2], ks)) {
									issuerfound = true;
									counts.set(i, counts.get(i) + 1);
									issuers.set(i, check[2]);
								}
								else {
									//Circle broken, certificate invalid
									System.out.println("Issuer Not Found Before, Certificate invalid");
									issuerfound = true;
									issuers.set(i, null);
								}
			    		}
			    		/*
			    		 * An issuer has been found already so we split the circle, now we know there is more than
			    		 * one circle of trust associated with this file so in order to deal with this,
			    		 * a new entry is added to the issuers and count list.
			    		 */
			    		else if(issuerfound && check[1].equals(issuer) && !check[1].equals(check[2])) {
			    			if(validate((X509Certificate) ks.getCertificate(alias), check[2], ks)) {
								counts.add(counts.get(i));
								issuers.add(check[2]);
								history.add(check[2]);
							}
							else {
								//Circle broken, certificate invalid
								System.out.println("Issuer Found Before, Certificate invalid");
								counts.add(counts.get(i));
								issuers.add(i, null);
								history.add(check[2]);
							}
			    		}
		    		}
		    	}
			    /*
			   	 * After the current loop does the count meet the rlength, if so, return true
			   	 * Just to be clear, this can be any circle, only one of them needs to meet rlength
			   	 * in order for this method to return true
			   	 */
		    	if(maxCount < counts.get(i)) {
			    	maxCount = counts.get(i);
			   	}
			   	/*
			   	 * If the issuer wasn't found at all then, circle complete, put issuer as null
			   	 * If the issuer has reached the original person who added the folder, circle complete
			   	 * If the issuer has reached the point where it previously split, circle complete
		    	 * I decided the end the circles here instead of chaining multiple circles together
		    	 * for one particular reason, there was no way to guarantee that when linking two circles
		    	 * together that everyone actually vouches for each other, hence the decision to end it
			     * at the issuer who added the file or at the part when it split.  
			   	 */
			   	if(!issuerfound || issuers.get(i) == history.get(0) || issuers.get(i) == history.get(i)) {
			   		issuers.set(i, null);
			   	}
		    	//Reset the loop if we got to the end and there's still some issuers that aren't null
			   	if(i == issuers.size() - 1) {
			   		boolean nullcheck = true;
				   	for(String nully: issuers) {
				   		if(nully != null) {
				   			nullcheck = false;
				   		}
				   	}
				   	if(nullcheck) {
				   		break;
				   	}
				   	else {
			    		System.out.println("Loop reset i = 0\n");
			    		i = 0;
				   	}
		    	}
		    	else {
		    		i++;
		    	}
		    	iteration++;
	    	}
    		return maxCount;
    	}
	}
	
	/**
	 * This method checks of the sender of the command for -a is in fact the one who added
	 * the file in the first place. We will do this by checking the keystore by seeing if there's
	 * an alias that matches
	 * <filename>-<sender>-<sender>
	 * This alias entry should have been added when the file was first added to the server. This will
	 * ensure that the only person who can overwrite a file added is the server itself and the client 
	 * who added it.
	 * @param filename
	 * @param sender
	 * @param password
	 * @return boolean
	 * @throws GeneralSecurityException 
	 * @throws IOException 
	 */
	 public static boolean checkTheAdder(String filename, String sender, KeyStore ks) 
	throws GeneralSecurityException, IOException {
		boolean adder = false;
		//Check if alias exists, return true if it does
		String alias = (filename+"-"+sender+"-"+sender).toLowerCase();
		System.out.println(alias);
		if(ks.containsAlias(alias)) {
		   	adder = true;
		}
		return adder;
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
		    keystore.close();
		    /*
		     * ENCRYPTION/DECRYPTION TESTING
		    FileInputStream teste = new FileInputStream("color.png");
			byte[] test = new byte[teste.available()];
			teste.read(test);
			teste.close();
			
			byte[] ttw = encrypt(test, args[0]);
			FileOutputStream ttwtest = new FileOutputStream("ecolor.png");
			ttwtest.write(ttw);
			ttwtest.close();
			
			FileInputStream eteste = new FileInputStream("ecolor.png");
			byte[] etestb = new byte[eteste.available()];
			eteste.read(etestb);
			eteste.close();
			FileOutputStream dtest = new FileOutputStream("d2color.png");
			byte[] decryptest = decrypt(etestb, args[0]);
			dtest.write(decryptest);
			dtest.close();
			*/

		    FileInputStream Bpem = new FileInputStream("B.pem");
		    CertificateFactory Bcf = CertificateFactory.getInstance("X.509");
		    X509Certificate Bcert = (X509Certificate) Bcf.generateCertificate(Bpem);
		    Bpem.close();
		    FileInputStream Cpem = new FileInputStream("C.pem");
		    CertificateFactory Ccf = CertificateFactory.getInstance("X.509");
		    X509Certificate Ccert = (X509Certificate) Ccf.generateCertificate(Cpem);
		    Cpem.close();
		    ks.setCertificateEntry(Bcert.getIssuerX500Principal().toString(), Bcert);
		    ks.setCertificateEntry(Ccert.getIssuerX500Principal().toString(), Ccert);
		    if(ks.containsAlias(Bcert.getIssuerX500Principal().toString())) {
		    	System.out.println("B cert added");
		    }
		    if(ks.containsAlias(Ccert.getIssuerX500Principal().toString())) {
		    	System.out.println("C cert added");
		    }
		    FileInputStream fispem = new FileInputStream("AB.pem");
		    CertificateFactory cf = CertificateFactory.getInstance("X.509");
		    X509Certificate cert = (X509Certificate) cf.generateCertificate(fispem);
		    fispem.close();
		    System.out.println("GOT AC");
		    FileInputStream BCfispem = new FileInputStream("BC.pem");
		    CertificateFactory BCcf = CertificateFactory.getInstance("X.509");
		    X509Certificate BCcert = (X509Certificate) BCcf.generateCertificate(BCfispem);
		    BCfispem.close();
		    System.out.println("GOT BC");
		    if(validate(cert, Bcert.getIssuerX500Principal().toString(), ks)) {
		    	System.out.println("AB Certificate Validated");
		    }
		    if(validate(BCcert, Ccert.getIssuerX500Principal().toString(), ks)) {
		    	System.out.println("BC Certificate Validated");
		    }
		    
			
			/*
			 * Getting the distance checking, here Ill just put certs that are valid
			 * since it uses only the aliases. I only need the certs to be valid for testing.
			 */
		    //First Circle nice and Linear! (PASS: FOUND LENGTH OF 3)
			ks.setCertificateEntry("Fake-A-A", cert);
			ks.setCertificateEntry("Fake-A-B", cert);//1
			ks.setCertificateEntry("Fake-B-C", cert);//2
			ks.setCertificateEntry("Fake-C-D", cert);//3
			//Create another Circle with shorter length than Linear (PASS: FOUND LENGTH OF 3)
			ks.setCertificateEntry("Fake-B-E", cert);//2
			/*Create another Circle with longer length than Linear 
			ks.setCertificateEntry("Fake-B-H", cert);//2
			ks.setCertificateEntry("Fake-H-I", cert);//3
			ks.setCertificateEntry("Fake-I-J", cert);//4
			ks.setCertificateEntry("Fake-J-K", cert);//5
			ks.setCertificateEntry("Fake-K-M", cert);//6
			/*
			Enumeration<String> s = ks.aliases();
		    while(s.hasMoreElements()) {
		    	String ss = s.nextElement();
		    	String[] split = ss.split("-");
			    if(split.length == 3 && split[1].equals(split[2])) {
					for(String part: split) {
						System.out.println(part);
					}
		    	}
		    
		    }
			*/
			String filename = "Fake";
			String sender = "A";
			String alias = (filename+"-"+sender+"-"+sender).toLowerCase();
			if(ks.containsAlias(alias)) {
				System.out.println("Found the Fake-A-A using Contains Alias");
			}
			if(checkTheAdder(filename,sender,ks)) {
				System.out.println("Found the Fake-A-A using checkTheAdder");
			}
			
		    int result = gettingTheDist(filename, ks);
		    System.out.println(result);
		    
		    
		}
		catch (Exception e) {
			System.out.println(e);
		}
	}
}
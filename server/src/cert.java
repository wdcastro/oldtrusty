import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Enumeration;
import sun.security.x509.*;
import javax.crypto.*;
import java.io.*;
import java.math.BigInteger;

/**
 * @author Joel-Dunstan-21318856
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
	 * Generate a key pair for the server, this can only be called within
	 * the program. This random number will be RSA based upon SHA256 with a size
	 * of 1024 bits and then it will save via the path provided by parameter
	 * @throws NoSuchAlgorithmException 
	 * @throws IOException 
	 * @throws NoSuchPaddingException 
	 */
	public static void keyGenerator() 
	throws NoSuchAlgorithmException, IOException, NoSuchPaddingException {
		//Initialize Key Generator
		KeyPairGenerator pkeygen = KeyPairGenerator.getInstance("DSA");
		//Produce a random number used for secure purposes based on SHA1 with RSA
		SecureRandom srand = SecureRandom.getInstance("SHA1PRNG");
		/*
		 * Tell the Key Generator to create keys of 1024 bits using the
		 * random number we just generated based on SHA1PRNG 
		*/
		pkeygen.initialize(2048, srand);
		//Create the Key Pair
		KeyPair pkey = pkeygen.generateKeyPair();
		//Grab the Private and Public Keys
		PrivateKey privkey = pkey.getPrivate();
		PublicKey pubkey = pkey.getPublic();
		/*
		 * Code copied and adapted from:
		 * http://docs.oracle.com/javase/tutorial/security/apisign/step4.html
		 * They create files named public.key and private.key. 
		 * TODO add a path to the files to put them in a certain location
		 */
		byte[] pub = pubkey.getEncoded();
		FileOutputStream pubkeyfos = new FileOutputStream("public.key");
		pubkeyfos.write(pub);
		pubkeyfos.close();
		//TODO encrypt private key file
		byte[] pri = privkey.getEncoded();
		FileOutputStream prikeyfos = new FileOutputStream("private.key");
		prikeyfos.write(pri);
		prikeyfos.close();	
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
	 * This method creates a cipher or Message Digest using a algorithm specified by
	 * the type parameter, an example might be creating a SHA-256 Hash.
	 * @param input a byte array to which we will be "type" to, e.g. SHA-256 on input
	 * @param type String which says what type of digest we'll use.
	 * @return mdHash The digest
	 * @throws NoSuchAlgorithmException 
	 */
	public byte[] createDigest(byte[] input, String type) 
	throws NoSuchAlgorithmException {
		//Initialize the Digest and create an object ready for updating
		MessageDigest md = MessageDigest.getInstance(type);
		//Update the MessageDigest Object with the data
		md.update(input);
		//Calculate the Digest using the type specified e.g. SHA-256
		byte[] mdHash = md.digest(input);
		//Return the Digest
		return mdHash;
	}
	
	/**
	 * Create a keystore for the Trusted certificates to be stored. We will later
	 * create a circle of trust by using aliases with say <filename><voucher> connecting
	 * subject to subject till we get to the required length. 
	 * @param password
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static void createKeyStore(String password)
	throws KeyStoreException, IOException, GeneralSecurityException {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    // Create the Key Store
	    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
	    ks.load(null, pass);
	    keystore.close();
	}
	
	/**
	 * This method stores the certs that have been validated to be used later
	 * for people wanting to get files from the server. A keystore stores Certificates
	 * like so:
	 * <alias>, <Certificate>
	 * The alias identifies each certificate and what its vouching for , aliases are
	 * unique so if an alias already exists when you're trying to store a cert and alias
	 * under the same names, the keystore will recognise the alias and override the certificate
	 * currently associated with that alias. This makes it great for replacing invalid
	 * certificates if needed or simply removing certificates.
	 * Here I will assume all certificates have been self signed as there is no root authority
	 * hence the issuer and subject should be the same. The subject will be the alias.
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
	 */
	@SuppressWarnings("unused")
	private static byte[] getServerKey(String filename) throws IOException {
		FileInputStream keyFile = new java.io.FileInputStream(filename);
		byte[] key = new byte[keyFile.available()];
		//TODO address encryption of private key file
		keyFile.read(key);
		keyFile.close();
		return key;
	}
	
	private String getFilenameAlias(String filename, String password) {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
	    ks.load(keystore, pass);
	    String theOne = null;;
	    Enumeration<String> loa = ks.aliases();
	    while(loa.hasMoreElements()) {
	    	String c = loa.nextElement().toString();
	    	if(c != null && c.contains(filename)) {
	    		theOne = c;
	    		break;
	    	}
	    }
	    return theOne;
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
	    String theOne = null;;
	    Enumeration<String> loa = ks.aliases();
	    while(loa.hasMoreElements()) {
	    	String c = loa.nextElement().toString();
	    	if(c != null && c.contains(filename)) {
	    		theOne = c;
	    		break;
	    	}
	    }
	    if(theOne == null) {
	    	System.out.println("File does not exist");
	    	return false;
	    }
	    else {
	    	String[] alias = theOne.split("-");
	    	int count = 0;
	    	for(int it = alias.length - 1; it > 1; it--) {
	    		if(it == 1) {
	    			X509Certificate certtoval = (X509Certificate) ks.getCertificate(alias[it]);
	    			if(validate(certtoval,certtoval.getEncoded())) {
	    				
	    			}
	    		}
	    		try {
	    			
	    		}
	    		catch (){
	    			
	    		}
	    	}
	    	if(count >= rlength) {
	    		return true;
	    	}
	    }
	    return false;
	}
	
	/**
	 * Create the server's certificate with all the necessary methods above and store
	 * it in the keystore with the alias "oldtrusty" which is of course reserved. Assumes
	 * keystore has been made already and may or may not have the server certificate there.
	 * @throws GeneralSecurityException 
	 * @throws IOException 
	 */
	public void createServerX509(String password) 
	throws GeneralSecurityException, IOException {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
	    ks.load(keystore, pass);
		if(ks.containsAlias("oldtrusty")) {
			System.out.println("Server Certificate already Exists under alias 'server'");
		}
		else {
			/*
			 * The code below is based upon 
			 * http://bfo.com/blog/2011/03/08/odds_and_ends_creating_a_new_x_509_certificate.html
			 * for creating a X509 Self Signed Certificate in which for this case is the server
			 */
			//Get Private and Public Key  
			byte[] bprivkey = getServerKey("Private");
			byte[] bpubkey = getServerKey("Public");
			//Put them into the required types
			KeyFactory keys = KeyFactory.getInstance("DSA");
			PrivateKey privkey = keys.generatePrivate(new PKCS8EncodedKeySpec(bprivkey));
			PublicKey pubkey = keys.generatePublic(new X509EncodedKeySpec(bpubkey));
			//Initialize the Certificate info
			X509CertInfo info = new X509CertInfo();
			//Set the start and end dates for certificate validity
			Date from = new Date();
			Date to = new Date(from.getTime() + 365 * 24 * 60 * 60);
			CertificateValidity interval = new CertificateValidity(from, to);
			//Set the Serial Number
			BigInteger sn = new BigInteger(64, new SecureRandom());
			X500Name owner = new X500Name("oldtrusty");
		    
			//Set all the certificate values, its Self Signed so subject and issuer
			info.set(X509CertInfo.VALIDITY, interval);
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
			info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
			info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
			info.set(X509CertInfo.KEY, new CertificateX509Key(pubkey));
			info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
			//Use SHA256 with RSA encryption for the Signature
			AlgorithmId algo = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid );
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
			
			// Sign the certificate to identify the algorithm that's used.
			X509CertImpl cert = new X509CertImpl(info);
			cert.sign(privkey, "SHA256withRSA");
			 
			// Update the algorithm, and resign.
			algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
			info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
			cert = new X509CertImpl(info);
			cert.sign(privkey, "SHA256withRSA");
			ks.setCertificateEntry("oldtrusty", cert);
		}
		keystore.close();
	}
	
//Will be commented out later	
public static void main(String args[]) 
throws IOException, KeyStoreException, GeneralSecurityException {
	cert.createKeyStore(args[1]);
	cert.keyGenerator();
	}
}
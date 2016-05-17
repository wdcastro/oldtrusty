import java.security.*;
import java.security.cert.*;
import javax.crypto.*;
import java.io.*;

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
	public static void keyGenerator() throws NoSuchAlgorithmException, IOException, NoSuchPaddingException {
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
	public boolean validate(X509Certificate indip, byte[] fiscert) throws NoSuchAlgorithmException, GeneralSecurityException {
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
	public byte[] createDigest(byte[] input, String type) throws NoSuchAlgorithmException {
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
	public static void createKeyStore(String password) throws KeyStoreException, IOException, GeneralSecurityException {
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
	 * The alias identifies each certificate and what its vouching for, aliases are
	 * unique so if an alias already exists when you're trying to store a cert and alias
	 * under the same names, the keystore will recognise the alias and override the certificate
	 * currently associated with that alias. This makes it great for replacing invalid
	 * certificates if needed or simply removing certificates.
	 * @param validcert
	 * @param filename name of the file being vouched for
	 * @param password the password for the keystore
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 */
	public void storeTrustedCert(X509Certificate validcert, String filename, String password) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
	    ks.load(keystore, pass);
	    //This will allow someone to just upload their certificate to the server
	    if(filename == null) {
	    	ks.setCertificateEntry(validcert.getSubjectX500Principal().toString(), validcert);
	    }
	    //This allows the certificate to be associated with a filename
	    else {
	    	ks.setCertificateEntry(filename + validcert.getSubjectX500Principal().toString(), validcert);
	    }
	    keystore.close();
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
	
	/**
	 * This method will use the keystore and the filename to
	 * find all the vouches made for a file and simply record how
	 * many vouches have been made for that file, if there has been 
	 * enough vouches to meet the required diameter, then the file is trusted.
	 * @param rlength the required diameter for the circle of trust
	 * @return boolean true = rlength reached false = otherwise
	 */
	public boolean gettingTheDist(int rlength, String filename) {
		
		return true;
	}
	
	/**
	 * Create the server's certificate with all the necessary methods above and store
	 * it in the keystore with the alias "server" which is of course reserved.
	 * @return server 
	 */
	public X509Certificate createServerX509() {
		return null;
	}
	
//Will be commented out later	
public static void main(String args[]) 
throws IOException, KeyStoreException, GeneralSecurityException {
	cert.createKeyStore("Imthemofokeystore");
	cert.keyGenerator();
	}
}
import java.security.*;
//import javax.crypto.*;
import java.io.*;

/**
 * The cert class has the task of managing the server's certificates whether
 * it be creating the server's certificate, verifying digital signatures
 * To fully create a certificate we need to, in order:
 * 1) Initialise the certificate
 * 2) Add in the headers for the certificate
 * 3) Add in and create the Digital Signature for the server
 * 	3a) Create a irreversible Hash using data whether it be from a file or the certificate
 * 	3b) Create the digital signature
 * 4) Finalise Cert and store in a Keystore with an appropriate alias
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
	 */
	public static void keyGenerator() throws NoSuchAlgorithmException, IOException {
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
		byte[] pri = privkey.getEncoded();
		FileOutputStream prikeyfos = new FileOutputStream("private.key");
		prikeyfos.write(pri);
		prikeyfos.close();	
	}
	
	/**
	 * This method will validate certificates and save them to the keystore
	 * if the signature is valid. A signature is valid if it can be decrypted
	 * using the subject's 
	 */
	public void validate() {
		
	}
	
	/**
	 * This method creates a cipher or Message Digest, I will primarily use
	 * SHA-256 to create a 32bit which in the case of verifying digital
	 * signatures which would have been encrypted by the signer's private key
	 * to be decrypted via the signer's public key.
	 * @param input a byte array to which we will be applying SHA-256 to
	 * @return sha256Hash The SHA-256 digest
	 * @throws NoSuchAlgorithmException 
	 */
	public byte[] createDigest(byte[] input) throws NoSuchAlgorithmException {
		//Initialize the Digest and create an object ready for updating
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		//Update the sha256 MessageDigest Object with the data
		sha256.update(input);
		//Calculate the 32 byte Digest using SHA-256
		byte[] sha256Hash = sha256.digest(input);
		//Return the Digest
		return sha256Hash;
	}
	
	public static void createKeyStore(String password) throws KeyStoreException, IOException, GeneralSecurityException {
		KeyStore ks = KeyStore.getInstance("JKS");
		char[] pass = password.toCharArray();
	    // Create the Key Store
	    FileInputStream keystore = new java.io.FileInputStream("KeyStore");
	    ks.load(null, pass);
	    keystore.close();
	}
	
	public static byte[] getServerKey(String filename) throws IOException {
		FileInputStream keyFile = new java.io.FileInputStream(filename);
		byte[] key = new byte[keyFile.available()];
		keyFile.read(key);
		keyFile.close();
		return key;
	}
	
//Will be commented out later	
public static void main(String args[]) 
throws IOException, KeyStoreException, GeneralSecurityException {
	cert.createKeyStore("Imthemofokeystore");
	cert.keyGenerator();
	}
}
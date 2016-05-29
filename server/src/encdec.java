import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class encdec {

	public encdec(){
		
	}
	
	public static void main(String[] args){
		FileManager fm = new FileManager();
		try {
			System.out.println(args[0].toString());
			System.out.println(args[1].toString());
			if(args[0].equals("encrypt")){
				System.out.println("encrypting");
				byte[] encrypted = cert.encrypt(fm.openFileAsByte(args[1], 1), "pass");
				fm.writeToFile(args[1] + "encrypted", encrypted, encrypted.length, 1);
				System.out.println("encrypt success");
			} else if(args[0].equals("decrypt")){
				System.out.println("decrypting");
				byte[] read = cert.decrypt(fm.openFileAsByte(args[1]+"encrypted",1), "pass");
				System.out.println(read);
				fm.writeToFile(args[1], read, read.length, 1);
				System.out.println("decrypt success");
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException
				| InvalidKeySpecException | NoSuchPaddingException
				| InvalidAlgorithmParameterException
				| IllegalBlockSizeException | BadPaddingException
				| InvalidParameterSpecException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
}

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;


/**
 * @author William Ignatius D'Castro - 21342121
 * For group project with Noah Macri and Joel Dunstan for CITS3002
 * Thread class that gets run when a connection is accepted
 * 
 */

public class ServerThread extends Thread{
	private SSLSocket socket = null;
	private int state = -1;
	private String password;
	private KeyStore ks;
	//-1 waiting for command
	// 0 add new file
	// 1 fetch file
	// 2 get directory list
	// 3 vouch


	

	
	public ServerThread(SSLSocket socket, String password, KeyStore ks){
		super("ServerThread");
		System.out.println("connection established");
		this.socket = socket;
		this.password = password;
		this.ks = ks;

	}

	@Override
	public void run() {
		System.out.println("thread running");
		System.out.println("IP: " + socket.getRemoteSocketAddress());
		System.out.println("peerid: " + socket.getSession().getPeerHost());
		Boolean isReading = true;
		FileManager fm = new FileManager();
		String[] commandsarray = new String[4];
		byte[] k = "k".getBytes();
		byte[] x = "x".getBytes();
		byte[] r = "r".getBytes();
		byte[] c = "c".getBytes();

		BufferedInputStream in = null; 
		BufferedOutputStream out = null;
		FileInputStream certinstream = null;
		try{
			in = new BufferedInputStream(socket.getInputStream(), 1024);
			out = new BufferedOutputStream(socket.getOutputStream(), 1024);
			
			
			
			System.out.println("receiving cert");
			Boolean certreceived = false;
			while(!certreceived){
				System.out.println("writing not completed looping");
				byte[] data = new byte[1024];
				int len = in.read(data, 0, 1024);
				if(len < 1024){
					System.out.println("writing completion detected");
					certreceived = true;
				}
				fm.writeToFile(socket.getSession().getPeerHost(), data, len, 0);
				for(int j = 0; j < data.length; j++){
					System.out.print(data[j]);
				}
			}
			System.out.println("cert received");
			CertificateFactory handshakecf = CertificateFactory.getInstance("X.509");
			certinstream = new FileInputStream(fm.getFileFile(socket.getSession().getPeerHost(), 0));
			System.out.println("certinstream null: " + (certinstream == null));
			Certificate handshakecert = handshakecf.generateCertificate(certinstream);
			System.out.println("handshakecert null: " + (certinstream == null));
			X509Certificate x509handshakecert = (X509Certificate) handshakecert;
			System.out.println("x509handshakecert null: " + (certinstream == null));
	
			
			
			if(cert.validate(x509handshakecert, x509handshakecert.getSubjectX500Principal().toString(), ks)){
				System.out.println("validation successful");
				cert.storeTrustedCert(x509handshakecert, password);
				out.write(k, 0, 1);
				out.flush();	
			} else {
				System.out.println("validation failed");
				out.write(c, 0, 1);
				out.flush();
				socket.close();
				isReading = false;
			}
			
			fm.clearcontents(socket.getSession().getPeerHost(), 0);
			
			

			while(isReading){
			
				System.out.println("state is: "+ state);
				
				
				
				if(state == -1){//waiting for command
					System.out.println("state is: "+ state);
					//int i = in.read();
					byte[] readbytes = new byte[196];
					int len = in.read(readbytes, 0, 196);
					System.out.println("length is "+ len);
					System.out.println();
					String commands = new String(readbytes,0, len, StandardCharsets.UTF_8);
					System.out.println("commands is: "+ commands);
					commandsarray = commands.split(",");
					
					for(int i = 0; i< commandsarray.length; i++){
						System.out.println(i+ ":" +commandsarray[i].toString());
					}
					
					System.out.println("read mode");

					
					if(commandsarray[0].equals("0")){//add
						System.out.println("0 confirmed");
						//append
						boolean failed = true;
						if(fm.listDir().contains(commandsarray[1])){							
							if(!fm.isWritable(commandsarray[1])){
								System.out.println("file is not writable");
								out.write(r, 0, 1);
								out.flush();
								isReading = false;
								break;
							}
							if(!cert.checkTheAdder(commandsarray[1]+"encrypted", x509handshakecert.getSubjectX500Principal().toString(),ks)){
								System.out.println("adder check failed");
								out.write(x, 0, 1);
								out.flush();
								isReading = false;								
								break;
							} else {
								failed = false;
								System.out.println("adder check success");
							}
						} else {
							System.out.println("adder check success");
							failed = false;
						}
						if(!failed){
						state = 0;
						out.write(k, 0, 1);
						out.flush();
						System.out.println("state is: "+ state);
						} else {
							System.out.println("one or more checks failed");
							isReading = false;
						}
						
					}
					
					if(commandsarray[0].equals("1")){//fetch
						if(!fm.doesFileExist(commandsarray[1])){
							//file doesnt exist
							System.out.println("file doesnt exists or can't be read");
							out.write(x, 0, 1);
							out.flush();
							isReading = false;
							break;
						} else if(!commandsarray[2].toString().equals("(null)") && Integer.parseInt(commandsarray[2])>cert.gettingTheDist(commandsarray[1], ks)){ 
							//file exists but does it meet length
							System.out.println("2 not null checking length");
							out.write(x, 0, 1);
							out.flush();
							isReading = false;
							break;
						} else if(!commandsarray[3].toString().equals("(null)") && !cert.wantedDOA(commandsarray[1], commandsarray[3], ks)) {
							System.out.println("3 not null checking user");
							System.out.println(commandsarray[3].toString());
							//file exists and meets length but does it include required name
							out.write(x, 0, 1);
							out.flush();
							isReading = false;
							break;							
						} else {
							System.out.println("1 confirmed");
							state = 1;
							out.write(k, 0, 1);
							out.flush();
						}
					}
					
					if(commandsarray[0].equals("2")){//list
						System.out.println("2 confirmed");
						state = 2;
						out.write(k, 0, 1);
						out.flush();
						
					}
						
					
						
						if(commandsarray[0].equals("3")){//vouch
							if(!fm.doesFileExist(commandsarray[1])){
								//does file exist
								out.write(x, 0, 1);
								out.flush();
								isReading = false;
								break;	
							} else {
								out.write(k, 0, 1);
								out.flush();
								state = 3;
							}
						}
						
						if(!commandsarray[0].equals("0") && !commandsarray[0].equals("1") && !commandsarray[0].equals("2") && !commandsarray[0].equals("3")){
							socket.close();
							isReading = false;
							System.out.println("command not recognised");
							System.out.println(commandsarray[0].toString());
						}
				
				
				}

				//code for adding file
				//
				//starts here
				
				if(state == 0){//waiting for file
					System.out.println("state 0 start");
					
					Boolean writingCompleted = false;
					while(!writingCompleted){
						System.out.println("writing not completed looping");
						byte[] data = new byte[1024];
						int len = in.read(data, 0, 1024);
						if(len < 1024){
							System.out.println("writing completion detected");
							writingCompleted = true;
						}
						fm.writeToFile(commandsarray[1], data, data.length, 1);
					}

					byte[] encrypted = cert.encrypt(fm.openFileAsByte((commandsarray[1]), 1), password);
					fm.writeToFile(commandsarray[1]+"encrypted", encrypted, encrypted.length, 1);
					cert.addToTheCircleOfLife(x509handshakecert, commandsarray[1]+"encrypted", ks, password);
					//fm.deleteFile(commandsarray[1]);
					isReading = false;
				}
				
				//code for adding file 
				//
				//ends here

				
				
				//code for fetching file
				//
				//starts here
				
				
				if(state == 1){//sending file
					System.out.println("state 1 start");										
					System.out.println("starting decrypt");
					byte[] read = fm.openFileAsByte(commandsarray[1]+"encrypted", 1);
					byte[] data = cert.decrypt(read, password);
					//byte[] data = abcd.openFileAsByte(commandsarray[1]);
					System.out.println("data length is " + data.length);
					System.out.println("writing");
					out.write(data, 0, data.length);
					out.flush();
					System.out.println("writing completed");
					isReading = false;
				}
				
				//code for fetching file
				//
				//ends here
				
				//code for listing dir
				//
				//starts here
				
				if(state == 2){
					ArrayList<String> directories = fm.listDir();
					byte[] bytestosend = new byte[128];
					String eol = System.getProperty("line.separator");
					String linestosend = "";
					for(int i = 0; i< directories.size(); i++){
						linestosend += directories.get(i)+eol;
						System.out.println(i+": "+ directories.get(i));
					}
					System.out.println();
					bytestosend= linestosend.getBytes();
					out.write(bytestosend, 0, bytestosend.length);
					out.flush();
					isReading = false;
					
				}
				
				//code for listing dir
				//
				//ends here
				
				//code for vouching files
				//
				//starts here
				
				if(state == 3){//waiting for cert
					System.out.println("state 3 start");
					Boolean writingCompleted = false;
					while(!writingCompleted){
						System.out.println("writing not completed looping");
						byte[] data = new byte[1024];
						int len = in.read(data, 0, 1024);
						if(len < 1024){
							System.out.println("writing completion detected");
							writingCompleted = true;
						}
						fm.writeToFile(commandsarray[1], data, len, 0);
						for(int j = 0; j < data.length; j++){
							System.out.print(data[j]);
						}
					}
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					certinstream = new FileInputStream(fm.getFileFile(commandsarray[1], 0));
					Certificate vouchcert = cf.generateCertificate(certinstream);
					System.out.println(vouchcert);
					X509Certificate x509cert = (X509Certificate) vouchcert;
					cert.addToTheCircleOfLife(x509cert, commandsarray[1], ks, password);
					System.out.println("vouched");
					isReading = false;
					
				}
				
				//code for vouching files
				//
				//ends here
				

		 }
			
			
			

		} catch(Exception e){
			System.out.println(e);
		} finally {		
			try {
				System.out.println("closing streams in serverthread");
				out.flush();			
				out.close();
				in.close();
				certinstream.close();
				server.endThread(socket.getSession().getPeerHost());
				socket.close();
				
			} catch (IOException e) {
				e.printStackTrace();
			}
			
		}

	}
	
	
	

}
	
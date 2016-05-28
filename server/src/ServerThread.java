import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;


//nvidia_guy21

public class ServerThread extends Thread{
	private SSLSocket socket = null;
	private int state = -1;
	private String password;
	//-1 waiting for command
		// 1 waiting for name for add
		// 2 receiving file for add
	//3 waiting for name for send
	//4 writing file for send
	
	////////////NEED TO MAKE SURE CERTS ARE STORED IN TRUSTSTORE

	

	
	public ServerThread(SSLSocket socket, String password){
		super("ServerThread");
		System.out.println("connection established");
		this.socket = socket;
		this.password = password;

	}

	@Override
	public void run() {
		System.out.println("thread running");
		try{
			
			
			Boolean isReading = true;
			FileManager fm = new FileManager();
			String[] commandsarray = new String[4];
			byte[] k = "k".getBytes();
			byte[] x = "x".getBytes();

			BufferedInputStream in = new BufferedInputStream(socket.getInputStream(), 1024);

			BufferedOutputStream out = new BufferedOutputStream(socket.getOutputStream(), 1024);
			
			
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
				fm.writeToFile("tempcert", data, len);
				for(int j = 0; j < data.length; j++){
					System.out.print(data[j]);
				}
			}
			System.out.println("cert received");
			CertificateFactory handshakecf = CertificateFactory.getInstance("X.509");
			Certificate handshakecert = handshakecf.generateCertificate(new FileInputStream(fm.getFileFile("tempcert")));
			X509Certificate x509handshakecert = (X509Certificate) handshakecert;

			if(cert.validate(x509handshakecert)){
				System.out.println("validation successful");
				cert.storeTrustedCert(x509handshakecert, password);
				out.write(k, 0, 1);
				out.flush();	
			} else {
				System.out.println("validation failed");
				socket.close();
				isReading = false;
			}
			
			

			while(isReading){
				/*
				System.out.println(Character.toString((char) in.read()));
				out.write("hello world 1", 0, 13);
				out.flush();
				System.out.println(Character.toString((char) in.read()));
				//out.newLine();
				out.write("asdfsadfsafds", 0 , 13);
				out.flush();
				isReading = false;*/
			
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
					isReading = false;
					
					if(commandsarray[0].equals("0")){//add
						System.out.println("0 confirmed");
						if(fm.listDir().contains(commandsarray[1])){
							out.write(x, 0, 1);
							out.flush();
							isReading = false;
							break;
						}
						state = 0;
						out.write(k, 0, 1);
						out.flush();
						System.out.println("state is: "+ state);
						
					}
					
					if(commandsarray[0].equals("1")){//fetch
						if(!fm.doesFileExist(commandsarray[1])){
							//file doesnt exist
							System.out.println("file doesnt exists");
							out.write(x, 0, 1);
							out.flush();
							isReading = false;
							break;
						} else if(!commandsarray[2].toString().equals("(null)") && !cert.gettingTheDist(Integer.parseInt(commandsarray[2]), password, commandsarray[1])){ 
							//file exists but does it meet length
							System.out.println("2 not null checking length");
							out.write(x, 0, 1);
							out.flush();
							isReading = false;
							break;
						} else if(!commandsarray[3].toString().equals("(null)") && !cert.wantedDOA(commandsarray[1], commandsarray[3], password)) {
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
							System.out.println("acknowledgement sent k 1");
						}
					}
					
					if(commandsarray[0].equals("2")){//list
						System.out.println("2 confirmed");
						state = 2;
						out.write(k, 0, 1);
						out.flush();
						
					}
						
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
						fm.writeToFile(commandsarray[1], cert.encrypt(data, password), len);
						for(int j = 0; j < data.length; j++){
							System.out.print(data[j]);
						}
					}
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
					FileManager abcd = new FileManager();
					
					//BufferedWriter bytestream = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()),1024);
					System.out.println("starting decrypt");
					//byte[] data = cert.decrypt(abcd.openFileAsByte(commandsarray[1]),password);
					byte[] data = abcd.openFileAsByte(commandsarray[1]);
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
					for(int i = 0; i< directories.size(); i++){
						bytestosend = (directories.get(i)+"%n").getBytes();
						System.out.println(i+": "+ directories.get(i));
						
						/*for(int bytesremain = 128 - bytestosend.length; bytesremain < 128; bytesremain++){
							bytestosend[bytesremain] = (Byte) null;
						}
						*/
						out.write(bytestosend, 0, bytestosend.length);
						out.flush();
					}
					
					isReading = false;
					
				}
				
				//code for vouching files
				//
				//starts here
				
				if(state == 3){//waiting for cert
					System.out.println("state 3 start");
					BufferedInputStream bytestream = new BufferedInputStream(socket.getInputStream(), 1024);
					Boolean writingCompleted = false;
					while(!writingCompleted){
						System.out.println("writing not completed looping");
						byte[] data = new byte[1024];
						int len = bytestream.read(data, 0, 1024);
						if(len < 1024){
							System.out.println("writing completion detected");
							writingCompleted = true;
						}
						fm.writeToFile(commandsarray[2], data, len);
						for(int j = 0; j < data.length; j++){
							System.out.print(data[j]);
						}
					}
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					Certificate vouchcert = cf.generateCertificate(new FileInputStream(fm.getFileFile(commandsarray[2])));
					X509Certificate x509cert = (X509Certificate) vouchcert;
					cert.addToTheCircleOfLife(x509cert, commandsarray[1], password);
					fm.deleteFile(commandsarray[2]);
					isReading = false;
					
				}
				
				//code for vouching files
				//
				//ends here
				

		 }
			
			out.flush();
			out.close();
			socket.close();

		} catch(Exception e){
			System.out.println(e);
		}
		
		
		
	}
	

}
	
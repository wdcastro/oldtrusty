import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
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
import java.security.cert.X509Certificate;

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
			SSLSession session = socket.getSession();
			Certificate[] certchain = session.getPeerCertificates();
			X509Certificate peercert = (X509Certificate) certchain[0];
			if(!cert.validate(peercert)){
				socket.close();
				isReading = false;
			}
			
			cert.storeTrustedCert(peercert, password);
			
			//create write/read streams
			BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
			BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()), 1024);
			
			int loopcount = 0;
			FileManager fm = new FileManager();
			
			
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
				
				
			
				loopcount++;
				System.out.println("loopcount: "+loopcount);				
				System.out.println("state is: "+ state);
				String[] commandsarray = new String[4];
				
				
				if(state == -1){//waiting for command
					System.out.println("state is: "+ state);
					//int i = in.read();
					char[] cbuf = new char[196];
					int len = in.read(cbuf, 0, 0);
					for(int j = 0; j< len; j++){
						System.out.print(cbuf[j]);
					}
					String commands = String.valueOf(cbuf);
					commandsarray = commands.split("");
					
					for(int j = 0; j< len; j++){
						System.out.print(commandsarray[j].toString());
					}
					
					System.out.println("read mode");
					if(commandsarray[0].equals("0")){
						System.out.println("0 confirmed");
						if(fm.listDir().contains(commandsarray[1])){
							out.write("x");
							out.flush();
							isReading = false;
							break;
						}
						state = 0;
						out.write("k");
						out.flush();
						System.out.println("state is: "+ state);
						
					}
					
					if(commandsarray[0].equals("1")){
						if(!fm.doesFileExist(commandsarray[1])){
							//does file exist
							out.write("x");
							out.flush();
							isReading = false;
							break;
						} else if(!commandsarray[2].equals("(null)") && !cert.gettingTheDist(Integer.parseInt(commandsarray[2]), password, commandsarray[1])){ 
							//file exists but does it meet length
							out.write("x");
							out.flush();
							isReading = false;
							break;
						} else if(!cert.wantedDOA(commandsarray[1], commandsarray[3], password)) {
							//file exists and meets length but does it include required name
							out.write("x");
							out.flush();
							isReading = false;
							break;							
						} else {
							System.out.println("1 confirmed");
							state = 1;
							out.write("k");
							out.flush();
						}
					}
				}
				
				
				
				//code for adding file
				//
				//starts here
				
				if(state == 0){//waiting for file
					System.out.println("state 0 start");
					FileManager abcd = new FileManager();
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
					abcd.writeToFile(commandsarray[1], cert.encrypt(data, password), len);
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
				
				
				if(state == 1){//waiting for file
					System.out.println("state 1 start");
					FileManager abcd = new FileManager();
					
					BufferedOutputStream bytestream = new BufferedOutputStream(socket.getOutputStream(), 1024);
					//BufferedWriter bytestream = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()),1024);
					
					byte[] data = cert.decrypt(abcd.openFileAsByte(commandsarray[1]),password);
					System.out.println("data length is " + data.length);
					System.out.println("writing");
					bytestream.write(data, 0, data.length);
					bytestream.flush();
					System.out.println("writing completed");
					isReading = false;
				}
					

		 }
				

		out.flush();
		out.close();
		socket.close();

		} catch(Exception e){
			System.out.println(e);
		}
		
	}
	

}
	
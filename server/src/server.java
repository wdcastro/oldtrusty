import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class server {
	public server(){
		

	}
	
	public static void main(String args[]){
		//code for listening to new socket connection
		if(args.length != 1){
			System.out.println("Usage: java server <portnumber>");
			System.exit(1);
		}
		
		Boolean listening = true;
		
		
		try {
			ServerSocket ss = new ServerSocket(Integer.parseInt(args[0]));
			while(listening){
				new ServerThread(ss.accept()).start();
			}
		} catch (IOException e) {
			System.out.println(e);
			System.exit(-1);
		}
		
	}
}

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;


public class ServerThread extends Thread{
	private Socket socket = null;
	
	public ServerThread(Socket socket){
		super("ServerThread");
		this.socket = socket;

	}

	@Override
	public void run() {
		try{
		// TODO process code
			socket.close();

		} catch(Exception e){
			System.out.println(e);
		}
		
	}

}

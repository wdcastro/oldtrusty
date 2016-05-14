import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;


public class FileManager {
	public FileManager(){
		
	}
	
	//Lists directory files by returning ArrayList
	public ArrayList<String> listDir(){
		ArrayList<String> dirlist = new ArrayList<String>();
		
		//find path to Files folder on server
		Path rootdir = Paths.get("");
		Path filedir = rootdir.resolve("files");
		
		//open stream and loop
		try(DirectoryStream<Path> stream = Files.newDirectoryStream(filedir)){
			for(Path file: stream){
				dirlist.add(file.getFileName().toString());
			}
			
		} catch (Exception e){
			System.out.println(e);
		}
		
		return dirlist;
		
	}
		
	

}

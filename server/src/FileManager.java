import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;


public class FileManager {
	public FileManager(){
		
	}
	
	public ArrayList<String> listDir(){
		ArrayList<String> dirlist = new ArrayList<String>();
		Path rootdir = Paths.get("");
		Path filedir = rootdir.resolve("files");
		System.out.println("path created dir");
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

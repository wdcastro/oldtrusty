import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;


public class FileManager {
	Path rootdir = Paths.get("");
	Path filedir = rootdir.resolve("files");
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
	
	public File getFileFile(String name){
		Path file = filedir.resolve(name);
		return file.toFile();
	}
	
	public boolean doesFileExist(String name){
		try{
			Path file = filedir.resolve(name);
		} catch (InvalidPathException e){
			return false;
		}
		
		return true;
		
	}
	
	public void deleteFile(String name){
		try{
			Path file = filedir.resolve(name);
			Files.delete(file);
		} catch (Exception e){
			System.out.println("cannot delete");
			System.out.println(e);
		}
	}
	
	public void writeToFile(String name, byte[] bytearray, int len){
		FileOutputStream fos;
		Path pathtofile = filedir.resolve(name);
		File file = pathtofile.toFile();
		try {
			fos = new FileOutputStream(file, true);
			fos.write(bytearray, 0, len);
			System.out.println("written to file");
			fos.flush();
			fos.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println(e);
		}

	}
	
	public void clearcontents(String name){
		FileOutputStream fos;
		Path pathtofile = filedir.resolve(name);
		File file = pathtofile.toFile();
		try {
			fos = new FileOutputStream(file, true);
			String s = "";
			fos.write(s.getBytes(), 0, 0);
			System.out.println("file cleared: " + name);
			fos.flush();
			fos.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println(e);
		}
		
	}
	
	public boolean isWritable(String name){
		try{
			Path file = filedir.resolve(name);
			return Files.isWritable(file);
		} catch (Exception e){
			System.out.println(e);
			return false;
		}
		
	}
	
	public boolean isReadable(String name){
		try{
			Path file = filedir.resolve(name);
			return Files.isWritable(file);
		} catch (Exception e){
			System.out.println(e);
			return false;
		}
	}
	
	public byte[] openFileAsByte(String name){
		Path pathtofile = filedir.resolve(name);
		byte[] data = null;
		try {
			 data = Files.readAllBytes(pathtofile);
		} catch (IOException e) {
			System.out.println(e);
		}
		return data;
		
	}
	
		
	

}

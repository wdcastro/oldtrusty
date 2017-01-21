import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

/**
 * @author William Ignatius D'Castro - 21342121
 * For group project with Noah Macri and Joel Dunstan for CITS3002
 * Class that manages I/O for files on local server directories
 * 
 */

public class FileManager {
	Path rootdir = Paths.get("");
	Path filedir = rootdir.resolve("files");
	Path certdir = rootdir.resolve("certs");
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
	
	public File getFileFile(String name, int type){
		Path file = null;
		if(type == 0){
			file = certdir.resolve(name);
		} else {
		file = filedir.resolve(name);
		}
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
			System.out.println("file deleted: "+name);
		} catch (Exception e){
			System.out.println("cannot delete");
			System.out.println(e);
		}
	}
	
	public void writeToFile(String name, byte[] bytearray, int len, int type){
		FileOutputStream fos = null;
		Path pathtofile = null;
		if(type == 0){
			pathtofile = certdir.resolve(name);
		} else {
			pathtofile = filedir.resolve(name);
		}
		File file = pathtofile.toFile();
		try {
			fos = new FileOutputStream(file, true);
			fos.write(bytearray, 0, len);
			//System.out.println("written to file");
			fos.flush();
			fos.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			System.out.println(e);
		} finally {
			try {
				fos.close();
				System.out.println("finally reached; writeToFile has closed fos");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

	}
	
	
	public void clearcontents(String name, int type){
		FileOutputStream fos = null;
		Path pathtofile = null;
		if(type == 0){
			pathtofile = certdir.resolve(name);
		} else {
			pathtofile = filedir.resolve(name);
		}
		File file = pathtofile.toFile();
		try {
			fos = new FileOutputStream(file, false);
			String s = "";
			fos.write(s.getBytes(), 0, 0);
			System.out.println("file cleared: " + name);
			fos.flush();
			fos.close();
		} catch (Exception e) {
			System.out.println(e);
		} finally{
			try {
				System.out.println("clearcontents fos closed");
				fos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
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
	
	public byte[] openFileAsByte(String name, int type){
		Path pathtofile = null;
		if(type == 0){
			pathtofile = certdir.resolve(name);
		} else {
			pathtofile = filedir.resolve(name);
		}
		
		byte[] data = null;
		try {
			 data = Files.readAllBytes(pathtofile);
		} catch (IOException e) {
			System.out.println(e);
		}
		return data;
		
	}
	
		
	

}

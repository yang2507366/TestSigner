import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class DefaultPassZipper implements PassZipper {

	ByteArrayOutputStream byteArrayOutputStream;
	ZipOutputStream zipOutputStream;
	
	public DefaultPassZipper(){
		this.byteArrayOutputStream = new ByteArrayOutputStream();
		this.zipOutputStream = new ZipOutputStream(this.byteArrayOutputStream);
	}
	
	public void addFile(String fileName, byte[] fileContent){
		try{
			ZipEntry entry = new ZipEntry(fileName);
			this.zipOutputStream.putNextEntry(entry);
			this.zipOutputStream.write(fileContent);
			this.zipOutputStream.closeEntry();
		}catch(IOException ex){
			ex.printStackTrace();
		}
	}
	
	public byte[] resultBytes(){
		try{
			this.zipOutputStream.finish();
			this.zipOutputStream.close();
			return this.byteArrayOutputStream.toByteArray();
		}catch(IOException ex){
			ex.printStackTrace();
		}
		return null;
	}
	
	public static byte[] readFile(String filePath) throws IOException{
		FileInputStream inputStream = new FileInputStream(filePath);
		byte[] buff = new byte[4096];
		int read = 0;
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		while((read = inputStream.read(buff)) != -1){
			bos.write(buff, 0, read);
		}
		inputStream.close();
		bos.flush();
		bos.close();
		
		return bos.toByteArray();
	}

}

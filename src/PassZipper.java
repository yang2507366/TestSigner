import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class PassZipper {

	ByteArrayOutputStream byteArrayOutputStream;
	ZipOutputStream zipOutputStream;
	
	public PassZipper(){
		this.byteArrayOutputStream = new ByteArrayOutputStream();
		this.zipOutputStream = new ZipOutputStream(this.byteArrayOutputStream);
	}
	
	public void addFile(String fileName, byte[] fileContent) throws IOException{
		ZipEntry entry = new ZipEntry(fileName);
		this.zipOutputStream.putNextEntry(entry);
		this.zipOutputStream.write(fileContent);
		this.zipOutputStream.closeEntry();
	}
	
	public byte[] resultBytes() throws IOException{
		this.zipOutputStream.finish();
		this.zipOutputStream.close();
		return this.byteArrayOutputStream.toByteArray();
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
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			PassZipper passZip = new PassZipper();
			
			Map<String, String> fileSHA1Map = new HashMap<String, String>();
			String passFolderPath = System.getProperty("user.dir") + File.separator + "test.raw";
			String[] subfiles = new File(passFolderPath).list();
			for(int i = 0; i < subfiles.length; ++i){
				String fileName = subfiles[i];
				String filePath = passFolderPath + File.separator + fileName;
				String SHA1String = PassManifestUtils.toHexString(PassManifestUtils.SHA1(new FileInputStream(filePath)));
				fileSHA1Map.put(fileName, SHA1String);
				
				passZip.addFile(fileName, PassZipper.readFile(filePath));
			}
			String manifestString = PassManifestUtils.generateManifest(fileSHA1Map);
			
			passZip.addFile("manifest.json", manifestString.getBytes());
			PassSigner passSigner = new PassSigner(System.getProperty("user.dir") + File.separator + "Certificate.p12", 
					"Gwmobile116", System.getProperty("user.dir") + File.separator + "WWDR.cer");
			byte[] signatureBytes = passSigner.signManifest(manifestString);
			passZip.addFile("signature", signatureBytes);
			
			byte[] zipBytes = passZip.resultBytes();
			FileOutputStream fos = new FileOutputStream(System.getProperty("user.dir") + File.separator + "test.pkpass");
			fos.write(zipBytes);
			fos.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;


public class Test {
	public static void main(String []args){
		try {
			PassZipper passZip = new DefaultPassZipper();
			
			Map<String, String> fileSHA1Map = new HashMap<String, String>();
			String passFolderPath = System.getProperty("user.dir") + File.separator + "test.raw";
			String[] subfiles = new File(passFolderPath).list();
			for(int i = 0; i < subfiles.length; ++i){
				String fileName = subfiles[i];
				String filePath = passFolderPath + File.separator + fileName;
				String SHA1String = PassManifestUtils.toHexString(PassManifestUtils.SHA1(new FileInputStream(filePath)));
				fileSHA1Map.put(fileName, SHA1String);
				
				passZip.addFile(fileName, DefaultPassZipper.readFile(filePath));
			}
			String manifestString = PassManifestUtils.generateManifest(fileSHA1Map);
			
			passZip.addFile("manifest.json", manifestString.getBytes());
			PassSigner passSigner = new DefaultPassSigner(System.getProperty("user.dir") + File.separator + "Certificate.p12", 
					"Gwmobile116", System.getProperty("user.dir") + File.separator + "WWDR.cer");
			byte[] signatureBytes = passSigner.signManifest(manifestString.getBytes());
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

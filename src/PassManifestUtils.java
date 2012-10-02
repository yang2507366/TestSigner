import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.Map;


public class PassManifestUtils {

	public static byte[] SHA1(byte[] inputBytes) throws NoSuchAlgorithmException{
		return MessageDigest.getInstance("SHA-1").digest(inputBytes);
	}
	
	public static byte[] SHA1(InputStream inputStream) throws IOException, NoSuchAlgorithmException{
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		int read = 0;
		byte[] buff = new byte[4096];
		while((read = inputStream.read(buff)) != -1){
			bos.write(buff, 0, read);
		}
		inputStream.close();
		bos.flush();
		byte[] inputBytes = bos.toByteArray();
		byte[] outputBytes = SHA1(inputBytes);
		
		return outputBytes;
	}

	public static String toHexString(byte[] bytes){
		String hexs = "0123456789abcdef";
		StringBuffer resultHex = new StringBuffer();
		for(int i = 0; i < bytes.length; ++i){
			int high4 = (bytes[i] >> 4) & 0xF;
			int low4 = bytes[i] & 0xF;
			resultHex.append(hexs.charAt(high4));
			resultHex.append(hexs.charAt(low4));
		}
		return resultHex.toString();
	}
	
	public static String generateManifest(Map<String, String> fileSHA1Map){
		StringBuffer manifestString = new StringBuffer();
		Iterator<String> files = fileSHA1Map.keySet().iterator();
		manifestString.append("{\n");
		while(files.hasNext()){
			String file = files.next();
			manifestString.append("\t\"" + file + "\" : \"" + fileSHA1Map.get(file) + "\",\n");
		}
		if(manifestString.length() > 2){
			manifestString.delete(manifestString.length() - 2, manifestString.length());
		}
		manifestString.append("\n}\n");
		return manifestString.toString();
	}

}

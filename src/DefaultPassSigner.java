import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;


public class DefaultPassSigner implements PassSigner {

	private X509Certificate signCertificate;
	private PrivateKey privateKey;
	private X509Certificate WWDRCACertificate;
	
	public DefaultPassSigner(String p12FilePath, String p12Password, String WWDRCertFilePath) 
			throws UnrecoverableKeyException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException{
		this(new FileInputStream(p12FilePath), p12Password, new FileInputStream(WWDRCertFilePath));
	}
	
	public DefaultPassSigner(InputStream p12InputStream, String p12Password, InputStream WWDRInputStream) 
			throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException{
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
		
		// sign certificate
		KeyStore tmpKeyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
		tmpKeyStore.load(p12InputStream, p12Password.toCharArray());
		p12InputStream.close();
		
		Enumeration<String> alias = tmpKeyStore.aliases();
		while(alias.hasMoreElements()){
			String aliasName = alias.nextElement();
			Key key = tmpKeyStore.getKey(aliasName, p12Password.toCharArray());
			if(key instanceof PrivateKey){
				this.privateKey = (PrivateKey)key;
				Object tmpCert = tmpKeyStore.getCertificate(aliasName);
				if(tmpCert instanceof X509Certificate){
					this.signCertificate = (X509Certificate)tmpCert;
					break;
				}
			}
		}
		
		// apple WWDRCA certificate
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		Certificate tmpCert = certFactory.generateCertificate(WWDRInputStream);
		WWDRInputStream.close();
		if(tmpCert instanceof X509Certificate){
			this.WWDRCACertificate = (X509Certificate)tmpCert;
		}
	}
	
	public byte[] signManifest(byte[] manifestBytes){
		try{
			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
	        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(this.privateKey);

	        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(
	                BouncyCastleProvider.PROVIDER_NAME).build()).build(sha1Signer, this.signCertificate));

	        List<X509Certificate> certList = new ArrayList<X509Certificate>();
	        certList.add(this.WWDRCACertificate);
	        certList.add(this.signCertificate);

	        Store certs = new JcaCertStore(certList);

	        generator.addCertificates(certs);
	        
	        CMSSignedData sigData = generator.generate(new CMSProcessableByteArray(manifestBytes), false);
	        byte[] signedDataBytes = sigData.getEncoded();
	        return signedDataBytes;
		}catch(Exception ex){
			ex.printStackTrace();
		}
        return null;
	}
	
	public byte[] signManifest(InputStream manifestInputStream) 
			throws OperatorCreationException, CertificateEncodingException, IOException, CMSException{
		
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        InputStream is = manifestInputStream;
        int read = 0;
        byte[] buffer = new byte[4086];
        while((read = is.read(buffer)) != -1){
        	bos.write(buffer, 0, read);
        }
        bos.flush();
        is.close();
        buffer = bos.toByteArray();
        
        return signManifest(buffer);
	}
	
	public byte[] signManifest(String manifest)
			throws OperatorCreationException, CertificateEncodingException, IOException, CMSException{
		return signManifest(manifest.getBytes());
	}
	
}

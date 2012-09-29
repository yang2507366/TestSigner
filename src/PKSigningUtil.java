import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public final class PKSigningUtil {

    private PKSigningUtil() {
    }
    
    public static byte[] signManifest(InputStream manifestInputStream, PKSigningInformation signingInformation) throws Exception{
        addBCProvider();
    	CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(
                signingInformation.getSigningPrivateKey());

        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider(
                BouncyCastleProvider.PROVIDER_NAME).build()).build(sha1Signer, signingInformation.getSigningCert()));

        List<X509Certificate> certList = new ArrayList<X509Certificate>();
        certList.add(signingInformation.getAppleWWDRCACert());
        certList.add(signingInformation.getSigningCert());

        Store certs = new JcaCertStore(certList);

        generator.addCertificates(certs);
        
        // read manifest
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
        
        CMSSignedData sigData = generator.generate(new CMSProcessableByteArray(buffer), false);
        byte[] signedDataBytes = sigData.getEncoded();
        
        return signedDataBytes;
    }

    public static PKSigningInformation loadSigningInformationFromPKCS12FileAndIntermediateCertificateFile(final String pkcs12KeyStoreFilePath,
            final String keyStorePassword, final String appleWWDRCAFilePath) throws IOException, NoSuchAlgorithmException, CertificateException,
            KeyStoreException, NoSuchProviderException, UnrecoverableKeyException {
        addBCProvider();

        KeyStore pkcs12KeyStore = loadPKCS12File(pkcs12KeyStoreFilePath, keyStorePassword);
        Enumeration<String> aliases = pkcs12KeyStore.aliases();

        PrivateKey signingPrivateKey = null;
        X509Certificate signingCert = null;

        while (aliases.hasMoreElements()) {
            String aliasName = aliases.nextElement();

            Key key = pkcs12KeyStore.getKey(aliasName, keyStorePassword.toCharArray());
            if (key instanceof PrivateKey) {
                signingPrivateKey = (PrivateKey) key;
                Object cert = pkcs12KeyStore.getCertificate(aliasName);
                if (cert instanceof X509Certificate) {
                    signingCert = (X509Certificate) cert;
                    break;
                }
            }
        }

        X509Certificate appleWWDRCACert = loadDERCertificate(appleWWDRCAFilePath);
        if (signingCert == null || signingPrivateKey == null || appleWWDRCACert == null) {
            throw new IOException("Couldn#t load all the neccessary certificates/keys");
        }

        return new PKSigningInformation(signingCert, signingPrivateKey, appleWWDRCACert);
    }

    public static KeyStore loadPKCS12File(final String filePath, final String password) throws IOException, NoSuchAlgorithmException,
            CertificateException, KeyStoreException, NoSuchProviderException {
        addBCProvider();
        KeyStore keystore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);

        keystore.load(new FileInputStream(filePath), password.toCharArray());
        return keystore;
    }

    public static X509Certificate loadDERCertificate(final String filePath) throws IOException, CertificateException {
        FileInputStream certificateFileInputStream = null;
        try {
            certificateFileInputStream = new FileInputStream(filePath);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            Certificate certificate = certificateFactory.generateCertificate(certificateFileInputStream);
            if (certificate instanceof X509Certificate) {
                return (X509Certificate) certificate;
            }
            throw new IOException("The key from '" + filePath + "' could not be decrypted");
        } catch (IOException ex) {
            throw new IOException("The key from '" + filePath + "' could not be decrypted", ex);
        } catch (NoSuchProviderException ex) {
            throw new IOException("The key from '" + filePath + "' could not be decrypted", ex);
        } finally {
        	if(certificateFileInputStream != null){
        		certificateFileInputStream.close();
        	}
        }
    }

    private static void addBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

    }
    
    public static void main(String []args){
    	File manifestFile = new File(System.getProperty("user.dir") + "/manifest.json");
    	
    	try {
			PKSigningInformation info = loadSigningInformationFromPKCS12FileAndIntermediateCertificateFile(
					System.getProperty("user.dir") + "/Certificate.p12",
					"Gwmobile116",
					System.getProperty("user.dir") + "/AWDRC.cer"
					);
			
			byte[] signedBytes = signManifest(new FileInputStream(manifestFile), info);
			FileOutputStream fos = new FileOutputStream(System.getProperty("user.dir") + "/signature");
			fos.write(signedBytes);
			fos.flush();
			fos.close();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
}

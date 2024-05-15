package kriptografija;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CRLReason;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

public class Algoritmi {

	public static byte[] enkripcijaSimetricno(byte[] ulaz, SecretKey simetricniKljuc) {
		try {
			Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.ENCRYPT_MODE, simetricniKljuc);
			return c.doFinal(ulaz);
		} catch (Exception e) {
			return null;
		}
	}

	public static byte[] dekripcijaSimetricno(byte[] ulaz, SecretKey simetricniKljuc) {
		try {
			Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.DECRYPT_MODE, simetricniKljuc);
			return c.doFinal(ulaz);
		} catch (Exception e) {
			return null;
		}
	}

	public static byte[] enkripcijaAsimetricno(byte[] ulaz, PublicKey javniKljuc) {
		try {
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.ENCRYPT_MODE, javniKljuc);
			return c.doFinal(ulaz);
		} catch (Exception e) {
			return null;
		}
	}

	public static byte[] dekripcijaAsimetricno(byte[] ulaz, PrivateKey privatniKljuc) {
		try {
			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.DECRYPT_MODE, privatniKljuc);
			return c.doFinal(ulaz);
		} catch (Exception e) {
			return null;
		}
	}

	public static String hesiranje(byte[] ulaz) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA256");
			byte[] hash = md.digest(ulaz);
			BigInteger number = new BigInteger(1, hash);
			StringBuilder sb = new StringBuilder(number.toString(16));
			while (sb.length() < 32) {
				sb.insert(0, '0');
			}
			return sb.toString();
		} catch (Exception e) {
			return null;
		}
	}

	public static byte[] kreirajDigitalniPotpis(byte[] ulaz, PrivateKey privatniKljuc) {
		try {
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privatniKljuc);
			signature.update(ulaz);
			return signature.sign();
		} catch (Exception e) {
			return null;
		}
	}

	public static boolean verifikujDigitalniPotpis(byte[] ulaz, byte[] digitalniPotpis, PublicKey javniKljuc) {
		try {
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(javniKljuc);
			signature.update(ulaz);
			return signature.verify(digitalniPotpis);
		} catch (Exception e) {
			return false;
		}
	}

	public static StanjeSertifikata verifikujSertifikat(File korisnickiSertifikatFajl, String alias) {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(korisnickiSertifikatFajl), "sigurnost".toCharArray());
			X509Certificate korisnickiSertifikat = (X509Certificate) ks.getCertificate(alias);

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate caSertifikat = (X509Certificate) cf.generateCertificate(new FileInputStream(new File("rootca.crt")));
			PublicKey caJavniKljuc = caSertifikat.getPublicKey();

			korisnickiSertifikat.checkValidity();
			korisnickiSertifikat.verify(caJavniKljuc);

			byte[] crlSadrzaj = Files.readAllBytes(Paths.get("crl.crl"));
			X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlSadrzaj));
			if (sertifikatPovucen(korisnickiSertifikat, crl)) {
				return StanjeSertifikata.POVUCEN;
			}
		} catch (Exception e) {
			e.printStackTrace();
			return StanjeSertifikata.NEVALIDAN;
		}

		return StanjeSertifikata.VALIDAN;
	}

	public static void povlacenjeSertifikata(File korisnickiSertifikat, String alias) {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(korisnickiSertifikat), "sigurnost".toCharArray());
			X509Certificate sertifikat = (X509Certificate) ks.getCertificate(alias);
			
			Calendar calendar = Calendar.getInstance();
			Date now = calendar.getTime();
			calendar.add(Calendar.YEAR, 1);
			Date endDate = calendar.getTime();

			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509v2CRLBuilder builder = new JcaX509v2CRLBuilder(sertifikat.getIssuerX500Principal(), now);
			byte[] crlSadrzaj = Files.readAllBytes(Paths.get("crl.crl"));
			X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlSadrzaj));
		
			if (sertifikatPovucen(sertifikat, crl)) {
				return;
			}

			InputStream inputStream = new FileInputStream(new File("crl.crl"));
			X509CRLHolder crlHolder = new X509CRLHolder(inputStream);
			builder.addCRL(crlHolder);
	        builder.addCRLEntry(sertifikat.getSerialNumber(), now, CRLReason.PRIVILEGE_WITHDRAWN.ordinal());
	        builder.setNextUpdate(endDate);
	        builder.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(sertifikat)); 
	        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(new BigInteger("1000")));
	        
	        PrivateKey privatniKljucCa = ucitajPrivatniKljucCA();
	        
	        X509CRLHolder cRLHolder = builder.build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(privatniKljucCa));
	        FileOutputStream fos = new FileOutputStream(new File("crl.crl"));
	        fos.write(cRLHolder.getEncoded());
	        fos.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("deprecation")
	public static void reaktivacijaSertifikata(File korisnickiSertifikat, String alias) throws Exception {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			byte[] crlSadrzaj = Files.readAllBytes(Paths.get("crl.crl"));
			X509CRL crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlSadrzaj));
			
			if(crl.getRevokedCertificates() == null || crl.getRevokedCertificates().isEmpty()) {
				return;
			}
			
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(new FileInputStream(korisnickiSertifikat), "sigurnost".toCharArray());
			X509Certificate sertifikat = (X509Certificate) ks.getCertificate(alias);
			X509CRLEntry povuceniSertifikat = crl.getRevokedCertificate(sertifikat.getSerialNumber());
			if(povuceniSertifikat != null) {	
				Set<? extends X509CRLEntry> skupPovucenihSertifikata = crl.getRevokedCertificates();
				
				Set<X509CRLEntry> povuceniSertifikati = new HashSet<>(skupPovucenihSertifikata);
				povuceniSertifikati.remove(povuceniSertifikat);
				X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name(crl.getIssuerDN().getName()), new Date());
				
				for (X509CRLEntry entry : povuceniSertifikati) {
			        BigInteger serialNumber = entry.getSerialNumber();
			        Date revocationDate = entry.getRevocationDate();
			        int reasonCode = 9;
			        builder.addCRLEntry(serialNumber, revocationDate, reasonCode);
			    }
				
				PrivateKey privatniKljucCa = ucitajPrivatniKljucCA();
				X509CRLHolder updatedCrlHolder = builder.build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privatniKljucCa));
				X509CRL updatedCrl = new JcaX509CRLConverter().setProvider("BC").getCRL(updatedCrlHolder);
				
				FileOutputStream fos = new FileOutputStream(new File("crl.crl"));
				fos.write(updatedCrl.getEncoded());
				fos.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void kreiranjeSertifikata(String korisnickoIme, String cn, String email) {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair parKljuceva = kpg.generateKeyPair();
			PrivateKey privatniKljuc = parKljuceva.getPrivate();
			PublicKey javniKljuc = parKljuceva.getPublic();
			
			kreiranjeZahtjeva(korisnickoIme, cn, email, privatniKljuc, javniKljuc);
			potpisivanjeZahtjeva(korisnickoIme, privatniKljuc);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void kreiranjeZahtjeva(String korisnickoIme, String cn, String email, PrivateKey privatniKljuc, PublicKey javniKljuc) throws Exception {
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privatniKljuc);
		X500NameBuilder nameBuilder = new X500NameBuilder();
		nameBuilder.addRDN(BCStyle.CN, cn);
		nameBuilder.addRDN(BCStyle.EmailAddress, email);
		nameBuilder.addRDN(BCStyle.C, "BA");
		nameBuilder.addRDN(BCStyle.ST, "RS");
		nameBuilder.addRDN(BCStyle.L, "Banja Luka");
		nameBuilder.addRDN(BCStyle.O, "Elektrotehnicki fakultet");
		nameBuilder.addRDN(BCStyle.OU, "ETF");
		X500Name tmp = nameBuilder.build();
		
		JcaPKCS10CertificationRequestBuilder genReq = new JcaPKCS10CertificationRequestBuilder(tmp, javniKljuc);
		PKCS10CertificationRequest csr = genReq.build(signer);

		File csrFajl = new File("req" + File.separator + korisnickoIme + ".csr");
		Files.write(csrFajl.toPath(), csr.getEncoded());
	}
	
	private static void potpisivanjeZahtjeva(String korisnickoIme, PrivateKey privatniKljuc) throws Exception {
		Date start = new Date();
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(start);
		calendar.add(Calendar.MONTH, 6);
		Date end = calendar.getTime();
		
		Scanner scanner = new Scanner(new File("serial"));
		String hexString = scanner.nextLine().trim();
		scanner.close();
		Integer serijskiBroj = Integer.parseInt(hexString, 16);
        
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate caSertifikat = (X509Certificate) cf.generateCertificate(new FileInputStream(new File("rootca.crt")));
		File csrFajl = new File("req" + File.separator + korisnickoIme + ".csr");
		byte[] csrSadrzaj = Files.readAllBytes(csrFajl.toPath());
		
		PKCS10CertificationRequest request = new PKCS10CertificationRequest(csrSadrzaj);
		X509CertificateHolder holder = new X509CertificateHolder(caSertifikat.getEncoded());
		X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(holder.getSubject(), new BigInteger(serijskiBroj.toString()),
				start, end, request.getSubject(), request.getSubjectPublicKeyInfo());
		certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
		certBuilder.addExtension(Extension.keyUsage, true,
				new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment | KeyUsage.keyEncipherment));
		
		PrivateKey privatniKljucCa = ucitajPrivatniKljucCA();
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privatniKljucCa);
		X509Certificate korisnickiSertifikat = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, null);
		char[] lozinka = "sigurnost".toCharArray();
		keyStore.setKeyEntry(korisnickoIme, privatniKljuc, lozinka, new X509Certificate[] {korisnickiSertifikat});
		
		FileOutputStream fos = new FileOutputStream(new File("certs" + File.separator + korisnickoIme + ".p12"));
		keyStore.store(fos, lozinka);
		fos.close();
		
		serijskiBroj++;
        PrintWriter pw = new PrintWriter(new FileWriter(new File("serial")));
        String updatedHexString = Integer.toHexString(serijskiBroj);
        pw.println(updatedHexString);
        pw.close();
	}
	
	private static PrivateKey ucitajPrivatniKljucCA() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] kljuc = Files.readAllBytes(Paths.get("ca.key"));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(kljuc);
        return keyFactory.generatePrivate(keySpec);
	}
	
	private static boolean sertifikatPovucen(X509Certificate sertifikat, X509CRL crl)  {
		Set<? extends X509CRLEntry> povuceniSertifikati = crl.getRevokedCertificates();
		if (povuceniSertifikati != null && !povuceniSertifikati.isEmpty()) {
		    for (X509CRLEntry entry : povuceniSertifikati) {
		        if (sertifikat.getSerialNumber().equals(entry.getSerialNumber())) {
		    		return true;
		    	}
		    }
		}
		return false;
	}
}
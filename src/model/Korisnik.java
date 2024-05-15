package model;

import java.io.File;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class Korisnik {
	private String korisnickoIme;
	private File folder;
	private X509Certificate sertifikat;
	private PrivateKey privatniKljuc;
	
	public Korisnik() {
		super();
		this.folder = new File("root" + File.separator + korisnickoIme);
	    try {
	    	if(!folder.exists())
		    	folder.mkdirs();
		    File fajl = new File(folder + File.separator + "fajlovi.txt");
		    if (!fajl.exists())
		    	fajl.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public Korisnik(String korisnickoIme, X509Certificate sertifikat, PrivateKey privatniKljuc) {
		super();
		this.korisnickoIme = korisnickoIme;
		this.sertifikat = sertifikat;
		this.privatniKljuc = privatniKljuc;
		this.folder = new File("root" + File.separator + korisnickoIme);
		try {
	    	if(!folder.exists())
		    	folder.mkdirs();
		    File fajl = new File(folder + File.separator + "fajlovi.txt");
		    if (!fajl.exists())
		    	fajl.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public String getKorisnickoIme() {
		return korisnickoIme;
	}

	public void setKorisnickoIme(String korisnickoIme) {
		this.korisnickoIme = korisnickoIme;
	}

	public File getFolder() {
		return folder;
	}

	public void setFolder(File folder) {
		this.folder = folder;
	}

	public X509Certificate getSertifikat() {
		return sertifikat;
	}

	public void setSertifikat(X509Certificate sertifikat) {
		this.sertifikat = sertifikat;
	}

	public PrivateKey getPrivatniKljuc() {
		return privatniKljuc;
	}

	public void setPrivatniKljuc(PrivateKey privatniKljuc) {
		this.privatniKljuc = privatniKljuc;
	}
}

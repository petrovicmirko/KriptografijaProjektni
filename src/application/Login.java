package application;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.Stage;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import kriptografija.Algoritmi;
import model.Korisnik;
import util.FileUtil;
import util.GUIUtil;

public class Login {
	private File korisnickiSertifikat;
	private int brojac;
	private String sacuvanoKorisnickoIme = "";
	private String sacuvanaLozinka = "";
	
	@FXML
	private TextField tfKorisnickoIme;
	
	@FXML
	private PasswordField pfLozinka;
	
	public Login(File korisnickiSertifikat) throws IOException {
		this.korisnickiSertifikat = korisnickiSertifikat;
		this.brojac = 0;
		String hesiranoImeSertifikata = Algoritmi.hesiranje(korisnickiSertifikat.getName().getBytes(StandardCharsets.UTF_8));
		BufferedReader br = new BufferedReader(new FileReader("korisnici.txt"));
		String line = br.readLine();
		while (line != null) {
			String[] parts = line.split("#");
			if (hesiranoImeSertifikata.equals(parts[2])) {
				sacuvanoKorisnickoIme = parts[0];
				sacuvanaLozinka = parts[1];
				break;
			}
			line = br.readLine();
		}
		br.close();
	}
	
	@FXML
	private void prijavaKorisnika(ActionEvent event) throws Exception {
		if ("".equals(tfKorisnickoIme.getText()) || "".equals(pfLozinka.getText())) {
			GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Morate unijeti korisnicko ime i lozinku!", null);
			return;
		}
		
		Stage stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		
		String hesiranoKorisnickoIme = Algoritmi.hesiranje(tfKorisnickoIme.getText().getBytes(StandardCharsets.UTF_8));
		String hesiranaLozinka = Algoritmi.hesiranje(pfLozinka.getText().getBytes(StandardCharsets.UTF_8));
		
		if (sacuvanoKorisnickoIme.equals(hesiranoKorisnickoIme) && sacuvanaLozinka.equals(hesiranaLozinka)) {
			KeyStore ks = KeyStore.getInstance("PKCS12"); 
			ks.load(new FileInputStream(korisnickiSertifikat), "sigurnost".toCharArray()); 
			X509Certificate sertifikat = (X509Certificate)ks.getCertificate(tfKorisnickoIme.getText());
			PrivateKey privatniKljuc = (PrivateKey)ks.getKey(tfKorisnickoIme.getText(), "sigurnost".toCharArray());
			Korisnik korisnik = new Korisnik(tfKorisnickoIme.getText(), sertifikat, privatniKljuc);
			Files files = new Files(korisnik);
			FXMLLoader loader = new FXMLLoader(getClass().getResource("Files.fxml"));
			loader.setController(files);
			stage.setScene(new Scene(loader.load()));
			stage.show();
		} else {
			GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Neispravno korisnicko ime ili lozinka!", null);
			brojac++;
		}
		
		if (brojac == 3) {
			Algoritmi.povlacenjeSertifikata(korisnickiSertifikat, FileUtil.getImeFajla(korisnickiSertifikat.getName()));
			GUIUtil.showAlert(AlertType.WARNING, "POVLACENJE SERTIFIKATA", "Vas sertifikat je povucen!", null);
			LoginFail loginFail = new LoginFail(korisnickiSertifikat, sacuvanoKorisnickoIme, sacuvanaLozinka);
			FXMLLoader loader = new FXMLLoader(getClass().getResource("LoginFail.fxml"));
			loader.setController(loginFail);
			stage.setScene(new Scene(loader.load()));
			stage.show();
		}
	}
}

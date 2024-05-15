package application;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.Stage;
import kriptografija.Algoritmi;
import model.Korisnik;
import util.GUIUtil;

public class LoginFail {
	private File korisnickiSertifikat;
	private String sacuvanoKorisnickoIme;
	private String sacuvanaLozinka;
	
	@FXML
	private TextField tfKorisnickoImeReaktivacija;
	
	@FXML
	private PasswordField pfLozinkaReaktivacija;
	
	public LoginFail(File korisnickiSertifikat, String sacuvanoKorisnickoIme, String sacuvanaLozinka) {
		this.korisnickiSertifikat = korisnickiSertifikat;
		this.sacuvanoKorisnickoIme = sacuvanoKorisnickoIme;
		this.sacuvanaLozinka = sacuvanaLozinka;
	}
	
	@FXML
	private void reaktivacijaSertifikata(ActionEvent event) throws Exception {
		if ("".equals(tfKorisnickoImeReaktivacija.getText()) || "".equals(pfLozinkaReaktivacija.getText())) {
			GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Morate unijeti korisnicko ime i lozinku!", null);
			return;
		}
		
		String hesiranoKorisnickoIme = Algoritmi.hesiranje(tfKorisnickoImeReaktivacija.getText().getBytes(StandardCharsets.UTF_8));
		String hesiranaLozinka = Algoritmi.hesiranje(pfLozinkaReaktivacija.getText().getBytes(StandardCharsets.UTF_8));
		
		Stage stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		FXMLLoader loader = null;
		if (sacuvanoKorisnickoIme.equals(hesiranoKorisnickoIme) && sacuvanaLozinka.equals(hesiranaLozinka)) {
			Algoritmi.reaktivacijaSertifikata(korisnickiSertifikat, tfKorisnickoImeReaktivacija.getText());
			GUIUtil.showAlert(AlertType.INFORMATION, "REAKTIVACIJA SERTIFIKATA", "Vas sertifikat je reaktiviran!", null);
			
			KeyStore ks = KeyStore.getInstance("PKCS12"); 
			ks.load(new FileInputStream(korisnickiSertifikat), "sigurnost".toCharArray()); 
			X509Certificate sertifikat = (X509Certificate)ks.getCertificate(tfKorisnickoImeReaktivacija.getText());
			PrivateKey privatniKljuc = (PrivateKey)ks.getKey(tfKorisnickoImeReaktivacija.getText(), "sigurnost".toCharArray());
			Korisnik korisnik = new Korisnik(tfKorisnickoImeReaktivacija.getText(), sertifikat, privatniKljuc);
			Files files = new Files(korisnik);
			loader = new FXMLLoader(getClass().getResource("Files.fxml"));
			loader.setController(files);
		} else {
			GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Vas sertifikat je povucen i vise se ne moze koristiti!", null);
			loader = new FXMLLoader(getClass().getResource("CertificateChooser.fxml"));
		}
		stage.setScene(new Scene(loader.load()));
		stage.show();
	}
	
	@FXML
	private void registracijaNaloga(ActionEvent event) throws IOException {
		Stage stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		Registration registration = new Registration();
		FXMLLoader loader = new FXMLLoader(getClass().getResource("Registration.fxml"));
		loader.setController(registration);
		stage.setScene(new Scene(loader.load()));
		stage.show();
	}
}

package application;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import javafx.scene.control.Alert.AlertType;
import kriptografija.Algoritmi;
import util.GUIUtil;

public class Registration {
	@FXML
	private TextField tfKorisnickoImeRegistracija;
	
	@FXML
	private PasswordField pfLozinkaRegistracija;
	
	@FXML
	private TextField tfIme;
	
	@FXML
	private TextField tfEmail;

	public Registration() {}

	@FXML
	private void registracijaKorisnika(ActionEvent event) throws IOException {
		if ("".equals(tfKorisnickoImeRegistracija.getText()) || "".equals(pfLozinkaRegistracija.getText()) 
				|| "".equals(tfIme.getText()) || "".equals(tfEmail.getText())) {
			GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Sva polja moraju biti popunjena!", null);
			return;
		}
		
		String hesiranoKorisnickoIme = Algoritmi.hesiranje(tfKorisnickoImeRegistracija.getText().getBytes(StandardCharsets.UTF_8));
		
		boolean postoji = false;
		BufferedReader br = new BufferedReader(new FileReader("korisnici.txt"));
		String line = br.readLine();
		while (line != null) {
			if (hesiranoKorisnickoIme.equals(line.split("#")[0])) {
				postoji = true;
				break;
			}
			line = br.readLine();
		}
		br.close();
		
		if (!postoji) {
			String hesiranaLozinka = Algoritmi.hesiranje(pfLozinkaRegistracija.getText().getBytes(StandardCharsets.UTF_8));
			String imeSertifikata = tfKorisnickoImeRegistracija.getText() + ".p12";
			String hesiranoImeSertifikata = Algoritmi.hesiranje(imeSertifikata.getBytes(StandardCharsets.UTF_8));
			
			PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("korisnici.txt", true)));
		    out.println(hesiranoKorisnickoIme + "#" + hesiranaLozinka + "#" + hesiranoImeSertifikata);
		    out.close();
		    
		    Algoritmi.kreiranjeSertifikata(tfKorisnickoImeRegistracija.getText(), tfIme.getText(), tfEmail.getText());
		    
		    GUIUtil.showAlert(AlertType.INFORMATION, "REGISTRACIJA", "Nalog uspjesno kreiran!", null);
		    
		    Stage stage = (Stage)((Node)event.getSource()).getScene().getWindow();
			FXMLLoader loader = new FXMLLoader(getClass().getResource("CertificateChooser.fxml"));
			stage.setScene(new Scene(loader.load()));
			stage.show();
		} else {
			GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Korisnicko ime zauzeto!", null);
		}
	}
}

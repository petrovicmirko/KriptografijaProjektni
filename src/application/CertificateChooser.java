package application;

import java.io.File;
import java.io.IOException;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import kriptografija.Algoritmi;
import kriptografija.StanjeSertifikata;
import util.FileUtil;
import util.GUIUtil;

public class CertificateChooser {

	public CertificateChooser() {}
	
	@FXML
	private void izaberiSertifikat(ActionEvent event) throws IOException {
		FileChooser fileChooser = new FileChooser();
		fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("PKCS12", "*.p12"));
		fileChooser.setInitialDirectory(new File("certs"));
		Stage stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		File izabraniSertifikat = fileChooser.showOpenDialog(stage);
		if (izabraniSertifikat != null) {
			StanjeSertifikata stanjeSertifikata = Algoritmi.verifikujSertifikat(izabraniSertifikat, FileUtil.getImeFajla(izabraniSertifikat.getName()));
			if (stanjeSertifikata == StanjeSertifikata.VALIDAN) {
				Login login = new Login(izabraniSertifikat);
				FXMLLoader loader = new FXMLLoader(getClass().getResource("Login.fxml"));
				loader.setController(login);
				stage.setScene(new Scene(loader.load()));
				stage.show();
			} else if (stanjeSertifikata == StanjeSertifikata.POVUCEN) {
				GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Povucen sertifikat", "Izabrani sertifikat je povucen!");
			} else {
				GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Nevalidan sertifikat", "Izabrani sertifikat nije validan!");
			}
		}
	}
}

package util;

import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;

public class GUIUtil {

	public static void showAlert(AlertType tip, String naslov, String zaglavlje, String sadrzaj) {
		Alert alert = new Alert(tip);
		alert.setTitle(naslov);
		alert.setHeaderText(zaglavlje);
		alert.setContentText(sadrzaj);
		alert.showAndWait();
	}
}

package util;

public class FileUtil {
	
	public static String getImeFajla(String punoImeFajla) {
		if (punoImeFajla.indexOf(".") > 0) {
			return punoImeFajla.substring(0, punoImeFajla.lastIndexOf("."));
		} else {
			return punoImeFajla;
		}
	}
}
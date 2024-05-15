package application;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.stream.Collectors;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.ListView;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import kriptografija.Algoritmi;
import model.Korisnik;
import util.FileUtil;
import util.GUIUtil;

public class Files implements Initializable {
	private Korisnik korisnik;
	private ObservableList<String> fajlovi;
	
	@FXML
	private ListView<String> list;

	public Files(Korisnik korisnik) {
		this.korisnik = korisnik;
		list = new ListView<>();
		fajlovi = FXCollections.observableArrayList();
	}

	@Override
	public void initialize(URL arg0, ResourceBundle arg1) {
		try {
			fajlovi.addAll(java.nio.file.Files.readAllLines((new File(korisnik.getFolder() + File.separator + "fajlovi.txt")).toPath()));
			list.setItems(fajlovi);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	@FXML
	private void dodajFajl(ActionEvent event) throws IOException {
		Stage stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		FileChooser fileChooser = new FileChooser();
		fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("TXT", "*.txt"),
				new FileChooser.ExtensionFilter("WORD", "*.docx"), new FileChooser.ExtensionFilter("PNG", "*.png"),
				new FileChooser.ExtensionFilter("JPG", "*.jpg"), new FileChooser.ExtensionFilter("PDF", "*.pdf"));
		fileChooser.setInitialDirectory(new File(System.getProperty("user.home")));
		File izabraniFajl = fileChooser.showOpenDialog(stage);
		if (izabraniFajl != null) {
			PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(korisnik.getFolder() + File.separator + "fajlovi.txt", true)));
		    out.println(izabraniFajl.getName());
		    out.close();
			
			File folderSaSegmentima = new File(korisnik.getFolder() + File.separator + FileUtil.getImeFajla(izabraniFajl.getName()));
		    if(!folderSaSegmentima.exists())
		    	folderSaSegmentima.mkdirs();
			File folderSaKljucevima = new File("keys" + File.separator + korisnik.getKorisnickoIme() + File.separator + FileUtil.getImeFajla(izabraniFajl.getName()));
		    if(!folderSaKljucevima.exists())
		    	folderSaKljucevima.mkdirs();
			byte[] sadrzajFajla = java.nio.file.Files.readAllBytes(izabraniFajl.toPath());
			int n = (new Random()).nextInt(7) + 4;
			int velicinaSegmenta = (int)Math.ceil((double)sadrzajFajla.length / n);
			List<byte[]> segmenti = new ArrayList<byte[]>();
		    int start = 0;
		    while (start < sadrzajFajla.length) {
		        int end = Math.min(sadrzajFajla.length, start + velicinaSegmenta);
		        segmenti.add(Arrays.copyOfRange(sadrzajFajla, start, end));
		        start += velicinaSegmenta;
		    }
		    for (int i = 0; i < segmenti.size(); i++) {
		    	String segment = "segment" + (i + 1);
		    	File segmentFajl = new File(folderSaSegmentima + File.separator + segment + File.separator + segment + ".txt");
		    	segmentFajl.getParentFile().mkdirs();
		    	File fajlSaKljucem = new File(folderSaKljucevima + File.separator + "segment" + (i + 1) + ".txt");
		    	enkripcija(segmenti.get(i), i + 1, segmentFajl, fajlSaKljucem);
		    }
		    
		    fajlovi.add(izabraniFajl.getName());
		    list.setItems(fajlovi);
		}
	}
	
	@FXML
	private void preuzmiFajl(ActionEvent event) throws IOException {
		String izabraniFajl = list.getSelectionModel().getSelectedItem();
		if (izabraniFajl == null) {
			GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Morate selektovati fajl!", null);
			return;
		}
		Stage stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		DirectoryChooser directoryChooser = new DirectoryChooser();
		directoryChooser.setInitialDirectory(new File(System.getProperty("user.home") + "/Desktop"));
		File izabraniDirektorijum = directoryChooser.showDialog(stage);
		if (izabraniDirektorijum != null) {
			List<File> fajlovi = new ArrayList<>();
			File direktorijum = new File(korisnik.getFolder() + File.separator + FileUtil.getImeFajla(izabraniFajl));
			dohvatiFajlove(direktorijum, fajlovi);
			fajlovi = fajlovi.stream().sorted(Comparator.comparing(File::getName)).collect(Collectors.toList());
			List<byte[]> segmenti = new ArrayList<>();
			int ukupnaDuzinaFajla = 0;
			for(File fajl : fajlovi) {
				File fajlSaKljucem = new File("keys" + File.separator + korisnik.getKorisnickoIme() + File.separator + FileUtil.getImeFajla(izabraniFajl) + File.separator + fajl.getName());
				byte[] dekriptovaniSegment = dekripcija(fajl, fajlSaKljucem);
				if (dekriptovaniSegment == null) {
					GUIUtil.showAlert(AlertType.ERROR, "GRESKA", "Fajl je kompromitovan!", null);
					return;
				}
				segmenti.add(dekriptovaniSegment);
				ukupnaDuzinaFajla += dekriptovaniSegment.length;
			}
			byte[] sadrzajFajla = new byte[ukupnaDuzinaFajla];
			ByteBuffer buffer = ByteBuffer.wrap(sadrzajFajla);
			for (int i = 0; i < segmenti.size(); i++) {
				buffer.put(segmenti.get(i));
			}
			sadrzajFajla = buffer.array();
			File file = new File(izabraniDirektorijum.getPath() + File.separator + izabraniFajl);
			FileOutputStream outputStream = new FileOutputStream(file);
			outputStream.write(sadrzajFajla);
			outputStream.close();
			GUIUtil.showAlert(AlertType.INFORMATION, "PREUZIMANJE FAJLA", "Fajl je uspjesno preuzet!", null);
		}
	}
	
	private void enkripcija(byte[] segment, int index, File izlazniFajl, File fajlSaKljucem) {
		try {
			SecretKey simetricniKljuc = KeyGenerator.getInstance("AES").generateKey();
			byte[] digitalniPotpis = Algoritmi.kreirajDigitalniPotpis(segment, korisnik.getPrivatniKljuc());
			byte[] podaci = new byte[segment.length + digitalniPotpis.length];
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(segment);
			outputStream.write(digitalniPotpis);
			podaci = outputStream.toByteArray();
			byte[] kriptovaniPodaci = Algoritmi.enkripcijaSimetricno(podaci, simetricniKljuc);
			String enkodovaniKljuc = new String(Base64.getEncoder().encode(simetricniKljuc.getEncoded()), StandardCharsets.UTF_8);
			String info = enkodovaniKljuc + "#" + segment.length;
			byte[] digitalnaEnvelopa = Algoritmi.enkripcijaAsimetricno(info.getBytes(), korisnik.getSertifikat().getPublicKey());
			FileOutputStream fileOutputStream = new FileOutputStream(izlazniFajl);
			fileOutputStream.write(kriptovaniPodaci);
			fileOutputStream.close();
			fileOutputStream = new FileOutputStream(fajlSaKljucem);
			fileOutputStream.write(digitalnaEnvelopa);
			fileOutputStream.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private byte[] dekripcija(File kriptovaniFajl, File fajlSaKljucem) throws IOException {
		try {
			PrivateKey privatniKljuc = korisnik.getPrivatniKljuc();
			FileInputStream fileInputStream = new FileInputStream(fajlSaKljucem);
			byte[] kljuc = Algoritmi.dekripcijaAsimetricno(fileInputStream.readAllBytes(), privatniKljuc);
			fileInputStream.close();
			String info = new String(kljuc, StandardCharsets.UTF_8);
			String[] parts = info.split("#");
			byte[] dekodovaniKljuc = Base64.getDecoder().decode(parts[0]);
			int duzinaSegmenta = Integer.parseInt(parts[1]);
			SecretKey simetricniKljuc = new SecretKeySpec(dekodovaniKljuc, 0, dekodovaniKljuc.length, "AES");
			fileInputStream = new FileInputStream(kriptovaniFajl);
			byte[] kriptovaniPodaci = fileInputStream.readAllBytes();
			fileInputStream.close();
			byte[] podaci = Algoritmi.dekripcijaSimetricno(kriptovaniPodaci, simetricniKljuc);
			byte[] segment = Arrays.copyOf(podaci, duzinaSegmenta);
			byte[] digitalniPotpis = Arrays.copyOfRange(podaci, duzinaSegmenta, podaci.length);
			if (!Algoritmi.verifikujDigitalniPotpis(segment, digitalniPotpis, korisnik.getSertifikat().getPublicKey())) {
				return null;
			}
			return segment;
		} catch (Exception e) {
			return null;
		}
	}
	
	private void dohvatiFajlove(File direktorijum, List<File> fajlovi) {
	    File[] fList = direktorijum.listFiles();
	    if(fList != null)
	        for (File file : fList) {      
	            if (file.isFile()) {
	            	fajlovi.add(file);
	            } else if (file.isDirectory()) {
	            	dohvatiFajlove(file, fajlovi);
	            }
	        }
	}
}

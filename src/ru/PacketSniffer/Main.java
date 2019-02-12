package ru.PacketSniffer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.bukkit.configuration.file.YamlConfiguration;

public class Main {
	static File log = new File("log.txt");
	static File ban = new File("banList.txt");
	static File configFile = new File("config.yml");
	public static YamlConfiguration config;
	public static boolean fastMode = false;
	public static String terminated = "Программа завершает работу...";

	public static void main(String args[]) throws Exception {
		String pass = "Stalkers39";
		if (args.length == 4 && args[0].equalsIgnoreCase("-f") && args[1].equals(pass)) {
			fastMode = true;
		}
		Scanner scanner = new Scanner(System.in);
		System.out.println("-====< VPNBlocker >====-\nРазработчик: Sitmobedaf > vk.com/host39 | Лицензия: CC BY-NC-ND | Версия: 1.0.2");
		if (fastMode) {
			System.out.println("Выполняется автоматический запуск программы...");
		} else {
			String result;
			boolean exit = false;
			do {
				System.out.print("Введите код активации, чтобы продолжить: ");
				result = scanner.nextLine();
				if (result.equals(pass)) {
					exit = true;
					break;
				}
				System.out.println("Введён неверный код активации.");
			} while (!exit);
			System.out.println("Авторизация пройдена успешно. Осуществляется запуск программы...");
		}
		System.out.println("Инициализация данных...");
		File f = new File("jnetpcap.dll");
		if (!f.exists()) {
			String arch = System.getProperty("sun.arch.data.model");
			if (arch.equals("32")) {
				ZipFile zf = new ZipFile("Software/jNetPcap_x" + arch + ".zip");
				try {
					InputStream in = zf.getInputStream(zf.getEntry("jnetpcap.dll"));
					FileUtils.copyInputStreamToFile(in, f);
				} finally {
					zf.close();
				}
			} else if (arch.equals("64")) {
				ZipFile zf = new ZipFile("Software/jNetPcap_x" + arch + ".zip");
				try {
					InputStream in = zf.getInputStream(zf.getEntry("jnetpcap.dll"));
					FileUtils.copyInputStreamToFile(in, f);
				} finally {
					zf.close();
				}
			} else {
				System.out.println("Не удалось определить архитектуру ОС.\n" + terminated);
			}
		}
		loadConfiguration();
		if (!log.exists()) {
			try {
				log.createNewFile();
			} catch (IOException e) {
			}
		}
		if (!ban.exists()) {
			try {
				ban.createNewFile();
			} catch (IOException e) {
			}
		}
		Sniffer.PacketSniffer(args, scanner);
	}

	public static void loadConfiguration() {
		if (!configFile.exists()) {
			try {
				configFile.createNewFile();
			} catch (IOException e) {
			}
		}
		config = YamlConfiguration.loadConfiguration(configFile);
	}
}
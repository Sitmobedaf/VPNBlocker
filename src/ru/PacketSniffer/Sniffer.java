package ru.PacketSniffer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.net.Inet4Address;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.BufferUnderflowException;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.InputMismatchException;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.json.JSONException;
import org.json.JSONObject;

public class Sniffer {
	private static Ip4 ip = new Ip4();
	private static Tcp tcp = new Tcp();
	private static Udp udp = new Udp();
	private static byte[] myinet = new byte[3];
	private static List<String> ports;
	private static List<String> checked = new ArrayList<String>();
	private static StringBuilder local = new StringBuilder();

	public static void PacketSniffer(String args[], Scanner scanner) throws Exception {
		Scanner s = new Scanner(Main.ban);
		while (s.hasNext()) {
			checked.add(s.next());
		}
		s.close();
		if (Main.config.getBoolean("SyncBanListOnLoad")) {
			System.out.println("Синхронизация списка заблокированных IP-адресов...");
			manageBanList();
		}
		System.out.println("Поиск сетевых интерфейсов...");
		List<PcapIf> alldevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.println("Произошла ошибка при загрузке сетевых интерфейсов.");
			scanner.close();
			return;
		}
		int choseDevice;
		if (Main.fastMode) {
			choseDevice = Integer.valueOf(args[2]);
		} else {
			System.out.println("Обнаруженные сетевые интерфейсы:");
			System.out.println("----------------------------------");
			int i = 0;
			for (PcapIf device : alldevs) {
				String name = (device.getName() != null) ? device.getName() : "отсутствует";
				String description = (device.getDescription() != null) ? device.getDescription() : "отсутствует";
				System.out.printf("Номер: %d | Имя: %s | Описание: %s\n", i++, name, description);
			}
			System.out.println("----------------------------------");
			System.out.print("Выберите один из доступных сетевых интерфейсов указав его номер: ");
			try {
				choseDevice = scanner.nextInt();
			} catch (InputMismatchException ex1) {
				System.out.println("Значение должно быть числовым.\n" + Main.terminated);
				scanner.close();
				return;
			}
		}
		PcapIf device;
		try {
			device = alldevs.get(choseDevice);
		} catch (IndexOutOfBoundsException ex2) {
			device = null;
		}
		if (device == null) {
			System.out.println("Сетевой интерфейс по указанному номеру не найден.\n" + Main.terminated);
			scanner.close();
			return;
		}
		if (Main.fastMode) {
			ports = new ArrayList<String>(Arrays.asList(args[3].split(",")));
		} else {
			System.out.print("Укажите локальные порты на которых должны отслеживаться соединения: ");
			ports = new ArrayList<String>(Arrays.asList(scanner.next().split(",")));
			scanner.close();
		}
		Iterator<PcapAddr> addr = device.getAddresses().iterator();
		while (addr.hasNext()) {
			PcapSockAddr sockAddr = addr.next().getAddr();
			String ip = FormatUtils.ip(sockAddr.getData());
			if (local.length() > 0 && addr.hasNext()) {
				local.append(", ");
			}
			try {
				local.append(Inet4Address.getByName(ip).getHostAddress());
			} catch (UnknownHostException e) {
			}
		}
		System.out.println("Определены следующие IP-адреса выбранного сетевого интерфейса: " + local.toString());
		System.out.printf("Выполняем сканирование с '%s':\n", (device.getDescription() != null) ? device.getDescription() : "Нет доступного описания");
		final int snaplen = Pcap.DEFAULT_SNAPLEN;
		final int flags = Pcap.MODE_PROMISCUOUS;
		final int timeout = Pcap.DEFAULT_TIMEOUT;
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		if (pcap == null) {
			System.out.println("Сетевой интерфейс по указанному номеру не найден: " + errbuf.toString());
			return;
		}
		pcap.loop(0, pcappackethandler, "pressure");
		pcap.close();
	}

	public static PcapPacketHandler<String> pcappackethandler = new PcapPacketHandler<String>() {
		public void nextPacket(PcapPacket pcappacket, String user) {
			if (pcappacket.hasHeader(ip)) {
				String protocol = "", srcIP = "", dstIP = "", srcPort = "", dstPort = "";
				try {
					if (FormatUtils.ip(ip.source()) != FormatUtils.ip(myinet) && FormatUtils.ip(ip.destination()) != FormatUtils.ip(myinet)) {
						protocol = ip.typeEnum().toString();
						srcIP = FormatUtils.ip(ip.source());
						dstIP = FormatUtils.ip(ip.destination());
					}
				} catch (ArrayIndexOutOfBoundsException | BufferUnderflowException e1) {
				}
				if (!checked.contains(srcIP)) {
					if (pcappacket.hasHeader(tcp)) {
						srcPort = String.valueOf(tcp.source());
						dstPort = String.valueOf(tcp.destination());
					} else if (pcappacket.hasHeader(udp)) {
						srcPort = String.valueOf(udp.source());
						dstPort = String.valueOf(udp.destination());
					}
					if (Main.config.getString("ListenProtocols").contains(protocol)) {
						if (local.toString().contains(dstIP) && ports.contains(dstPort)) {
							String info = "Новое подключение > Протокол: " + protocol + " Отправитель: " + srcIP + ":" + srcPort + " Получатель: " + dstIP + ":" + dstPort;
							getLogger(info, 0);
							if (!Main.config.getStringList("Whitelist").contains(srcIP)) {
								try {
									if (checkVPN(srcIP)) {
										// Добавляем в список забаненных
										try (FileWriter ban = new FileWriter("banList.txt", true); BufferedWriter banBuff = new BufferedWriter(ban); PrintWriter outBan = new PrintWriter(banBuff)) {
											outBan.println(srcIP);
										} catch (NullPointerException | IOException ex) {
											getLogger("Не удалось записать данные в список заблокированных IP-адресов.", 2);
										}
										manageBanList();
									}
								} catch (IOException e) {
									getLogger("Произошла ошибка при попытке проверить IP-адрес " + srcIP + ": " + e.getMessage(), 2);
								}
							}
							checked.add(srcIP);
						}
					}
				}
			}
		}
	};

	public static void getLogger(String data, int logLevel) {
		Calendar cal = Calendar.getInstance();
		SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
		String time = "[" + sdf.format(cal.getTime()) + "] ";
		String prefix = "";
		if (logLevel == 1) {
			prefix = "[Предупреждение] ";
		} else if (logLevel == 2) {
			prefix = "[Ошибка] ";
		}
		System.out.println(time + prefix + data);
		try (FileWriter log = new FileWriter("log.txt", true); BufferedWriter logBuff = new BufferedWriter(log); PrintWriter outLog = new PrintWriter(logBuff)) {
			outLog.println(time + prefix + data);
		} catch (NullPointerException | IOException ex) {
			System.out.println("[Ошибка] Не удалось записать данные в лог.");
		}
	}

	public static void manageBanList() {
		// Получаем список забаненных и блокируем в Windows Firewall
		StringBuilder banned = new StringBuilder();
		try {
			Scanner s = new Scanner(Main.ban);
			while (s.hasNext()) {
				if (banned.length() > 0 && s.hasNext()) {
					banned.append(",");
				}
				banned.append(s.next());
			}
			s.close();
			executeCommand("netsh advfirewall firewall set rule name=\"VPNBlocker\" new remoteip=\"" + banned.toString() + "\"");
		} catch (FileNotFoundException e1) {
		}
	}

	private static void executeCommand(String command) {
		try {
			Runtime.getRuntime().exec(command);
		} catch (Exception e) {
		}
	}

	public static boolean checkVPN(String ip) throws IOException {
		JSONObject json = null;
		String url, block;
		if (Main.config.getBoolean("NewIPHubAPI.UseNewAPI")) {
			url = "http://v2.api.iphub.info/ip/" + ip + "?key=" + Main.config.getString("NewIPHubAPI.Key");
			block = "block";
		} else {
			url = "http://legacy.iphub.info/api.php?ip=" + ip + "&showtype=4&email=Sitmobedaf@mail.ru";
			block = "proxy";
		}
		try {
			json = getJSONObjectFromURL(url);
		} catch (IOException e) {
			getLogger("Не удалось подключиться к сервису IPHub.info: " + e.getMessage(), 2);
		}
		if (json != null) {
			int resultstring = json.getInt(block);
			if (Main.config.getBoolean("ShowCountyName")) {
				String countryName = json.getString("countryName");
				String countryCode = json.getString("countryCode");
				if (countryName.isEmpty()) {
					getLogger("Не удалось определить страну для IP-адреса " + ip + ".", 0);
				} else {
					getLogger("Для IP-адреса " + ip + " определена страна: " + countryName + " (" + countryCode + ")", 0);
				}
			}
			if (resultstring == 1) {
				String info = "Адрес " + ip + " определён как VPN/Proxy. Будет предпринята попытка его заблокировать...";
				getLogger(info, 1);
				return true;
			} else {
				return false;
			}
		}
		return false;
	}

	public static JSONObject getJSONObjectFromURL(String url) throws IOException, JSONException {
		InputStream is = new URL(url).openStream();
		try {
			BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
			String jsonText = readAll(rd);
			JSONObject json = new JSONObject(jsonText);
			return json;
		} finally {
			is.close();
		}
	}

	private static String readAll(Reader rd) throws IOException {
		StringBuilder sb = new StringBuilder();
		int cp;
		while ((cp = rd.read()) != -1) {
			sb.append((char) cp);
		}
		return sb.toString();
	}
}
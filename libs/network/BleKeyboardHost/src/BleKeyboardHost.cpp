// FreeInk SDK — BLE HID host implementation.
//
// The real NimBLE central path compiles only under FREEINK_CAP_BLE_HID_HOST; the
// #else branch links stub bodies (and references no BLE code). Flow: scan ->
// connect on a dedicated FreeRTOS task -> bond -> set Report
// Protocol -> subscribe to the HID input report -> diff reports into key events.
// Connection runs on its own task so neither the main loop nor the NimBLE host
// task ever blocks on pairing.

#include "BleKeyboardHost.h"

#include <BoardConfig.h>  // FREEINK_CAP_BLE_HID_HOST

#ifndef FREEINK_BLE_HID_LIFECYCLE_DIAGNOSTICS
#define FREEINK_BLE_HID_LIFECYCLE_DIAGNOSTICS 0
#endif

namespace freeink {

BleKeyboardHost& BleKeyboardHost::getInstance() {
  static BleKeyboardHost instance;
  return instance;
}

}  // namespace freeink

#if FREEINK_CAP_BLE_HID_HOST

#include <NimBLEDevice.h>
#include <Preferences.h>

#include <cstring>
#include <string>

#include "HidKeymap.h"

namespace freeink {
namespace {

constexpr uint16_t kHidService = 0x1812;
constexpr uint16_t kAppearanceKeyboard = 0x03C1;
constexpr uint16_t kCharReport = 0x2A4D;
constexpr uint16_t kCharProtocolMode = 0x2A4E;
constexpr uint16_t kCharBootKbdInput = 0x2A22;
constexpr uint16_t kCharReportMap = 0x2A4B;
constexpr uint16_t kDescReportReference = 0x2908;

// Page-turner remotes often stream a held key (or omit a clean release frame). If no
// report arrives within this window, treat the key as released so one physical press
// yields one event and the next press re-triggers.
constexpr uint32_t kReleaseTimeoutMs = 150;
constexpr uint32_t kReconnectBackoffMs = 4000;
constexpr uint32_t kConnectTimeoutMs = 8000;
constexpr uint32_t kTeardownConnectWaitMs = kConnectTimeoutMs + 500;
constexpr size_t kScanDebugPayloadMax = 31;

void lifecycleStage(const char* stage) {
#if FREEINK_BLE_HID_LIFECYCLE_DIAGNOSTICS
  if (!stage || (std::strcmp(stage, "pre_init") != 0 && std::strcmp(stage, "nimble_init") != 0 &&
                 std::strcmp(stage, "client_created") != 0 && std::strcmp(stage, "host_ready") != 0 &&
                 std::strcmp(stage, "connect_start") != 0 && std::strcmp(stage, "link_connected") != 0 &&
                 std::strcmp(stage, "hid_service_found") != 0 && std::strcmp(stage, "security_ready") != 0 &&
                 std::strcmp(stage, "hid_input_ready") != 0 && std::strcmp(stage, "scan_start") != 0))
    return;
  Serial.printf("[BLEMEM] stage=%s free=%lu largest=%lu\n", stage,
                static_cast<unsigned long>(ESP.getFreeHeap()),
                static_cast<unsigned long>(ESP.getMaxAllocHeap()));
#else
  (void)stage;
#endif
}

portMUX_TYPE g_mux = portMUX_INITIALIZER_UNLOCKED;

NimBLEClient* g_client = nullptr;

// Connection task: connect() stores a target and notifies it; it runs the
// blocking connect+pair+discover sequence off the main and NimBLE host tasks.
TaskHandle_t g_connTask = nullptr;
volatile bool g_connecting = false;
char g_targetAddr[18] = {0};
uint8_t g_targetType = 0;
bool g_targetTryAltType = false;

uint32_t g_lastReconnectMs = 0;
uint8_t g_reconnectIdx = 0;

// HID Report Map hints (parsed once per connection in setupHid). Many BLE
// page-turner remotes are NOT plain boot keyboards: they place their code on the
// Consumer Control page (0x0C) or at a non-standard byte offset. These hints, plus
// the generic-extraction fallback in onReportIngest, let those remotes surface a
// stable key code so the host (capture-then-assign UI) can bind it. g_lastGenericCode
// edge-detects the generic path so one physical press = one key event.
bool g_hasKeyboardPage = false;
bool g_hasConsumerPage = false;
uint8_t g_preferredByteIndex = 0xFF;  // byte the report map suggests holds the code
uint8_t g_lastGenericCode = 0;        // last non-zero code seen on the generic path
volatile uint32_t g_lastReportMs = 0;  // millis() of the last HID notification (stale-release)

enum class YiserGesture : uint8_t { Idle, PendingConfirm, Vertical, Left, Right, AwaitRelease };
struct YiserGestureState {
  YiserGesture kind = YiserGesture::Idle;
  uint8_t step = 0;
  uint16_t firstAxis = 0;
  uint32_t startedMs = 0;
};
YiserGestureState g_yiserGesture;
constexpr uint32_t kYiserGestureTimeoutMs = 350;

#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
constexpr uint8_t kRawReportRingLen = 16;
RawReportDiagnostic g_rawReports[kRawReportRingLen] = {};
volatile uint8_t g_rawReportHead = 0;
volatile uint8_t g_rawReportTail = 0;
uint32_t g_rawReportSequence = 0;
uint32_t g_lastRawReportMs = 0;

void enqueueRawDiagnostic(const RawReportDiagnostic& raw) {
  portENTER_CRITICAL(&g_mux);
  const uint8_t next = static_cast<uint8_t>((g_rawReportHead + 1) % kRawReportRingLen);
  if (next == g_rawReportTail) {
    // Keep the newest reports; sequence gaps make any overflow visible in the
    // physical capture without allowing the callback to block or allocate.
    g_rawReportTail = static_cast<uint8_t>((g_rawReportTail + 1) % kRawReportRingLen);
  }
  g_rawReports[g_rawReportHead] = raw;
  g_rawReportHead = next;
  portEXIT_CRITICAL(&g_mux);
}
#endif

BleKeyboardHost& self() { return BleKeyboardHost::getInstance(); }

// Scan a HID Report Map descriptor for Usage Page (0x05 nn) items and note whether
// a keyboard (0x07) or consumer (0x0C) page is present, plus a heuristic byte index
// where the active code tends to live (keyboard reports: byte[2]; compact consumer
// reports: byte[1]). This is a hint, not a full descriptor parse.
void parseReportMapHints(const uint8_t* map, size_t len) {
  g_hasKeyboardPage = false;
  g_hasConsumerPage = false;
  g_preferredByteIndex = 0xFF;
  if (!map || len < 2) return;
  for (size_t i = 0; i + 1 < len; ++i) {
    if (map[i] == 0x05) {  // Usage Page (1-byte value follows)
      if (map[i + 1] == 0x07) g_hasKeyboardPage = true;
      else if (map[i + 1] == 0x0C) g_hasConsumerPage = true;
    }
  }
  if (g_hasKeyboardPage) g_preferredByteIndex = 2;
  else if (g_hasConsumerPage) g_preferredByteIndex = 1;
}

// Pick a representative "primary" code from a report that the standard keyboard
// slot decode did not handle (consumer / compact / non-standard layouts). Prefers
// the report-map-hinted byte, else the first meaningful non-zero byte. Returns 0
// when the report carries no code (a release frame).
uint8_t extractPrimaryCode(const uint8_t* p, size_t n, size_t* codeIdx = nullptr) {
  const size_t lim = n < 8 ? n : 8;
  // NOTE: do NOT skip 0x01 here. In a keyboard report 0x01 is ErrorRollOver, but in
  // a consumer / vendor report it is a valid button code (e.g. a 3-byte page-turner
  // report of "01 00 00" on press, "00 00 00" on release). Only zero means "no code".
  if (g_preferredByteIndex != 0xFF && g_preferredByteIndex < n && p[g_preferredByteIndex] != 0) {
    if (codeIdx) *codeIdx = g_preferredByteIndex;
    return p[g_preferredByteIndex];
  }
  for (size_t i = 0; i < lim; ++i) {
    if (p[i] != 0) {
      if (codeIdx) *codeIdx = i;
      return p[i];
    }
  }
  return 0;
}

#ifndef FREEINK_BLE_HID_SCAN_DEBUG
#ifdef FREEINK_BLE_KEYBOARD_SCAN_DEBUG
#define FREEINK_BLE_HID_SCAN_DEBUG FREEINK_BLE_KEYBOARD_SCAN_DEBUG
#else
#define FREEINK_BLE_HID_SCAN_DEBUG 0
#endif
#endif

// Raw HID report logging. Define FREEINK_BLE_HID_REPORT_DEBUG=1 in the firmware to
// dump every notification's bytes — the fastest way to learn what a new remote sends.
#ifndef FREEINK_BLE_HID_REPORT_DEBUG
#define FREEINK_BLE_HID_REPORT_DEBUG 0
#endif

#if FREEINK_BLE_HID_SCAN_DEBUG
void printPayloadHex(const NimBLEAdvertisedDevice* dev) {
  if (!dev) return;
  const std::vector<uint8_t>& payload = dev->getPayload();
  const size_t n = payload.size() < kScanDebugPayloadMax ? payload.size() : kScanDebugPayloadMax;
  Serial.print("  payload=");
  for (size_t i = 0; i < n; ++i) {
    if (payload[i] < 0x10) Serial.print('0');
    Serial.printf("%x", payload[i]);
  }
  if (payload.size() > n) Serial.print("...");
}
#endif

void onHidNotify(NimBLERemoteCharacteristic* characteristic, uint8_t* data, size_t len, bool) {
  uint8_t source = 0;
  if (characteristic) {
    source = characteristic->getUUID() == NimBLEUUID(kCharBootKbdInput) ? 2 : 1;
  }
  self().onReportIngest(data, len, source);
}

bool setupHid(NimBLEClient* client) {
  NimBLERemoteService* hid = client->getService(NimBLEUUID(kHidService));
  if (!hid) return false;

  // Prefer Report Protocol so we get full reports (and report ids) like a host.
  NimBLERemoteCharacteristic* proto = hid->getCharacteristic(NimBLEUUID(kCharProtocolMode));
  if (proto && proto->canWrite()) {
    uint8_t mode = 1;  // 1 = Report Protocol, 0 = Boot Protocol
    proto->writeValue(&mode, 1, false);
  }

  // Parse the HID Report Map for usage-page / byte-offset hints, so non-keyboard
  // page-turner remotes can be decoded by the generic fallback in onReportIngest.
  g_hasKeyboardPage = false;
  g_hasConsumerPage = false;
  g_preferredByteIndex = 0xFF;
  g_lastGenericCode = 0;
  if (NimBLERemoteCharacteristic* rmap = hid->getCharacteristic(NimBLEUUID(kCharReportMap))) {
    if (rmap->canRead()) {
      NimBLEAttValue v = rmap->readValue();
      parseReportMapHints(v.data(), v.size());
#if FREEINK_BLE_HID_REPORT_DEBUG
      Serial.printf("[BleHid] report map: kbd=%d consumer=%d preferredByte=%d len=%u\n", g_hasKeyboardPage,
                    g_hasConsumerPage, (int)g_preferredByteIndex, (unsigned)v.size());
#endif
    }
  }

  bool subscribed = false;
  const std::vector<NimBLERemoteCharacteristic*>& chars = hid->getCharacteristics(true);
  for (NimBLERemoteCharacteristic* c : chars) {
    if (!c) continue;
    if (c->getUUID() != NimBLEUUID(kCharReport) || !c->canNotify()) continue;
    // Report Reference descriptor (0x2908) byte[1] is the report type: 1=Input.
    bool isInput = true;
    NimBLERemoteDescriptor* ref = c->getDescriptor(NimBLEUUID(kDescReportReference));
    if (ref) {
      NimBLEAttValue v = ref->readValue();
      if (v.size() >= 2 && v[1] != 0x01) isInput = false;
    }
    if (isInput && c->subscribe(true, onHidNotify)) subscribed = true;
  }

  if (!subscribed) {  // fallback: boot keyboard input report
    NimBLERemoteCharacteristic* boot = hid->getCharacteristic(NimBLEUUID(kCharBootKbdInput));
    if (boot && boot->canNotify() && boot->subscribe(true, onHidNotify)) subscribed = true;
  }
  return subscribed;
}

bool hasHidService(NimBLEClient* client) {
  return client && client->getService(NimBLEUUID(kHidService)) != nullptr;
}

void doConnect(const char* addrStr, uint8_t type) {
  if (!g_client) {
    self().onConnectFailed("BLE client unavailable");
    return;
  }
  NimBLEDevice::getScan()->stop();
  NimBLEAddress addr(std::string(addrStr), type);
  if (!self().connectionPermitted()) {
    self().onConnectionDeferred();
    return;
  }
  lifecycleStage("connect_start");
  if (!g_client->connect(addr)) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.printf("[BleHid] connect failed: %s type=%u err=%d\n", addrStr, type, g_client->getLastError());
#endif
    if (!g_targetTryAltType) {
      self().onConnectFailed(g_client->getLastError() == BLE_HS_ETIMEOUT ? "Connect timeout" : "Connection failed");
      return;
    }
    type = type == 0 ? 1 : 0;
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.printf("[BleHid] retry connect: %s type=%u\n", addrStr, type);
#endif
    addr = NimBLEAddress(std::string(addrStr), type);
    if (!self().connectionPermitted()) {
      self().onConnectionDeferred();
      return;
    }
    if (!g_client->connect(addr)) {
#if FREEINK_BLE_HID_SCAN_DEBUG
      Serial.printf("[BleHid] connect failed: %s type=%u err=%d\n", addrStr, type, g_client->getLastError());
#endif
      self().onConnectFailed(g_client->getLastError() == BLE_HS_ETIMEOUT ? "Connect timeout" : "Connection failed");
      return;
    }
  }
  lifecycleStage("link_connected");
  if (!hasHidService(g_client)) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.printf("[BleHid] no HID service: %s\n", addrStr);
#endif
    g_client->disconnect();
    self().onConnectFailed("Not a HID device");
    return;
  }
  lifecycleStage("hid_service_found");
  // A bonded reconnect may already be encrypted when connect() returns. Calling
  // secureConnection() again in that state can turn a valid re-encryption into
  // the observed "Pairing failed" path on older remotes.
  const NimBLEConnInfo connectedInfo = g_client->getConnInfo();
  if (!connectedInfo.isEncrypted() && !g_client->secureConnection()) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.printf("[BleHid] security failed: %s err=%d\n", addrStr, g_client->getLastError());
#endif
    g_client->disconnect();
    self().onConnectFailed("Pairing failed");
    return;
  }
  lifecycleStage("security_ready");
  if (!setupHid(g_client)) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.printf("[BleHid] HID setup failed: %s\n", addrStr);
#endif
    g_client->disconnect();
    self().onConnectFailed("No HID input report");
    return;
  }
  lifecycleStage("hid_input_ready");
  const NimBLEConnInfo securedInfo = g_client->getConnInfo();
  const NimBLEAddress identity = securedInfo.getIdAddress();
  const std::string identityString = identity.isNull() ? std::string() : identity.toString();
  self().onLinkUp(addrStr, nullptr, type, identityString.empty() ? nullptr : identityString.c_str(),
                  identity.getType());  // name resolved from scan/bond lists
}

void connTaskFn(void*) {
  for (;;) {
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    doConnect(g_targetAddr, g_targetType);
    g_connecting = false;
  }
}

class ScanCB : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* dev) override {
    if (!dev) return;
    // Store named/HID advertisers by default; optionally keep anonymous
    // non-HID probe candidates during bring-up. HID is still validated at
    // connect time. The name falls back to the address. Keep the callback cheap
    // so heavy logging can't choke the C3's advertisement-report queue.
    const std::string a = dev->getAddress().toString();
    const bool named = dev->haveName();
    const std::string nm = named ? dev->getName() : a;
    const uint8_t type = dev->getAddress().getType();
    const int rssi = dev->getRSSI();
    const uint16_t appearance = dev->haveAppearance() ? dev->getAppearance() : 0;
    const bool keyboardAppearance = appearance == kAppearanceKeyboard;
    const bool connectable = dev->isConnectable();
    const bool hid = dev->isAdvertisingService(NimBLEUUID(kHidService)) || keyboardAppearance;
#if FREEINK_BLE_HID_SCAN_DEBUG
    if (named || hid || connectable) {
      Serial.printf("[BLE adv] %s  name='%s'  rssi=%d  hid=%d  app=0x%04x  conn=%d  addrType=%u",
                    a.c_str(), nm.c_str(), rssi, hid ? 1 : 0, appearance, connectable ? 1 : 0, type);
#if CONFIG_BT_NIMBLE_EXT_ADV
      Serial.printf("  legacy=%d  advType=0x%02x  data=%u  phy=%u/%u  len=%u", dev->isLegacyAdvertisement() ? 1 : 0,
                    dev->getAdvType(), dev->getDataStatus(), dev->getPrimaryPhy(), dev->getSecondaryPhy(),
                    dev->getAdvLength());
#else
      Serial.printf("  advType=0x%02x  len=%u", dev->getAdvType(), dev->getAdvLength());
#endif
      printPayloadHex(dev);
      Serial.println();
    }
#endif
    self().onScanResultIngest(a.c_str(), nm.c_str(), rssi, type, hid, connectable);
  }
};

class ClientCB : public NimBLEClientCallbacks {
  void onDisconnect(NimBLEClient*, int) override { self().onLinkDown(); }
  void onPassKeyEntry(NimBLEConnInfo& connInfo) override { NimBLEDevice::injectPassKey(connInfo, 123456); }
  uint32_t onPassKeyDisplay(NimBLEConnInfo&) override {
    const uint32_t passkey = NimBLEDevice::getSecurityPasskey();
    self().onPairingPasskey(passkey);
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.printf("[BleHid] pairing passkey: %06lu\n", static_cast<unsigned long>(passkey));
#endif
    return passkey;
  }
  void onConfirmPasskey(NimBLEConnInfo& connInfo, uint32_t) override {
    NimBLEDevice::injectConfirmPasskey(connInfo, true);
  }
  // Reject peripheral connection-parameter updates — some keyboards request one
  // on the first keypress and drop the link if it's negotiated.
  bool onConnParamsUpdateRequest(NimBLEClient*, const ble_gap_upd_params*) override { return false; }
};

ScanCB g_scanCb;
ClientCB g_clientCb;

}  // namespace

// --- Lifecycle ---------------------------------------------------------------
bool BleKeyboardHost::begin(const char* hostName) {
  if (begun_) return true;

#if FREEINK_BLE_HID_SCAN_DEBUG
  Serial.printf("[BleHid] begin: host='%s' bonds=%u\n", hostName ? hostName : "FreeInk", bondCount_);
#endif

  // Self-heal a partial teardown: if NimBLE still reports initialized (a previous
  // deinit raced and didn't complete), NimBLEDevice::init() would no-op and hand back
  // a dead stack. Force a clean deinit first so the init below actually runs.
  if (NimBLEDevice::isInitialized()) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.println("[BleHid] begin: NimBLE was already initialized; forcing deinit");
#endif
    NimBLEDevice::deinit(true);
    vTaskDelay(pdMS_TO_TICKS(20));
  }

  loadBonds();
#if FREEINK_BLE_HID_SCAN_DEBUG
  Serial.printf("[BleHid] begin: loaded bonds=%u\n", bondCount_);
#endif
  lifecycleStage("pre_init");
  if (!NimBLEDevice::init(hostName ? hostName : "FreeInk")) {
    Serial.println("[BleHid] begin: NimBLEDevice::init() failed");
    return false;
  }
  lifecycleStage("nimble_init");

  // HID page-turner reports are a few bytes; request the minimum ATT MTU so the
  // host doesn't reserve large per-connection GATT buffers. On RAM-constrained
  // targets (ESP32-C3, ~16 KB max contiguous block once the stack is up) every KB
  // back to the heap matters for the app (e.g. EPUB inflate windows).
  NimBLEDevice::setMTU(23);

  // Bonding for HID remotes. Default to Just Works because page-turners commonly
  // have no input/display capability; mandatory MITM makes those devices reject
  // pairing. Firmware that specifically needs host-display keyboard pairing can
  // opt in with FREEINK_BLE_HID_REQUIRE_MITM=1.
  NimBLEDevice::setSecurityAuth(/*bonding=*/true, /*mitm=*/FREEINK_BLE_HID_REQUIRE_MITM, /*sc=*/false);
  NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);
  NimBLEDevice::setSecurityPasskey(123456);
  NimBLEDevice::setSecurityInitKey(BLE_SM_PAIR_KEY_DIST_ENC);
  NimBLEDevice::setSecurityRespKey(BLE_SM_PAIR_KEY_DIST_ENC);

  NimBLEScan* scan = NimBLEDevice::getScan();
  // wantDuplicates = true: DON'T filter duplicates. A device's name/HID often
  // rides in the scan response (a separate PDU after the first advertisement);
  // with duplicate filtering on, the C3 controller drops that follow-up, so the
  // device shows up nameless or not at all. This (plus the windowed interval
  // below and the no-filter onResult) keeps scan response and extended adv data.
  scan->setScanCallbacks(&g_scanCb, true);
  scan->setActiveScan(true);  // send scan requests -> receive scan responses (names)
  // CONTINUOUS listening (window == interval, 100% duty; values are ms).
  // Extended advertising splits data into an AUX packet on a secondary
  // channel that the controller must catch at a precise moment after the primary
  // — if the scan window is closed when it lands, the name/HID UUID is lost. A
  // windowed (low-duty) scan is fine for legacy keyboards but starves AUX
  // reception, which is the only data this keyboard exposes. Duplicate filtering
  // is OFF (above) so the AUX packet (same address as the primary) isn't dropped.
  scan->setInterval(160);
  scan->setWindow(160);
#if CONFIG_BT_NIMBLE_EXT_ADV
  // Some BLE 5.x peripherals advertise on LE Coded. Scan both PHYs so the pairing
  // UI sees the same devices a desktop Bluetooth stack reports.
  scan->setPhy(NimBLEScan::SCAN_ALL);
#endif

  g_client = NimBLEDevice::createClient();
  if (!g_client) {
    // NimBLE can refuse a new client if a previous one wasn't reclaimed (e.g. rapid
    // deinit/init cycles). Don't dereference null — unwind cleanly so a later begin()
    // can retry from a clean state.
    Serial.println("[BleHid] begin: createClient() returned null");
    NimBLEDevice::deinit(true);
    return false;
  }
  lifecycleStage("client_created");
  g_client->setConnectTimeout(kConnectTimeoutMs);
  // Widen the link supervision timeout. The host runs on a single RISC-V core and
  // some operations block it for several seconds (e.g. the reader rebuilding a whole
  // chapter to reach its last page on a backward page turn across a section boundary).
  // NimBLE's default supervision timeout is only 2.56s, so those long renders overrun
  // it and the controller drops the link — the peripheral then fails to re-encrypt on
  // auto-reconnect (HCI 0x08 "Connection Timeout" -> BLE_HS err 520). Request a low
  // interval for keypress responsiveness with an 8s supervision timeout (units:
  // interval 1.25ms, timeout 10ms) so a slow page render can't sever the connection.
  // Peripheral-initiated updates are still rejected (see onConnParamsUpdateRequest), so
  // these host-chosen params hold for the life of the link.
  g_client->setConnectionParams(/*minInterval=*/12, /*maxInterval=*/24, /*latency=*/0, /*timeout=*/800);
  g_client->setClientCallbacks(&g_clientCb, false);

  xTaskCreate(connTaskFn, "ble-conn", 4096, nullptr, 3, &g_connTask);
  begun_ = true;
  lifecycleStage("host_ready");
#if FREEINK_BLE_HID_SCAN_DEBUG
  Serial.println("[BleHid] begin: ok");
#endif
  return true;
}

void BleKeyboardHost::end() {
  if (!begun_) return;
  begun_ = false;
  lifecycleStage("host_end_pre");

  NimBLEScan* scan = NimBLEDevice::getScan();
  if (scan && scan->isScanning()) scan->stop();

  // If auto-reconnect is in the middle of g_client->connect(), do not delete the
  // worker or deinit NimBLE under it. Let the blocking connect path unwind first;
  // killing it inside NimBLE leaves host/controller state inconsistent and can
  // crash on Bluetooth-off, sleep, or the next begin().
  if (g_connecting && g_client) g_client->cancelConnect();
  const uint32_t waitStart = millis();
  while (g_connecting && millis() - waitStart < kTeardownConnectWaitMs) {
    vTaskDelay(pdMS_TO_TICKS(20));
  }

  // Kill the connection worker once it is idle so it can't run doConnect() against
  // the stack while we tear it down.
  if (g_connTask) {
    vTaskDelete(g_connTask);
    g_connTask = nullptr;
  }
  g_connecting = false;

  // Close the link and explicitly delete the client BEFORE deinit. This is critical:
  // NimBLE keeps a fixed-size client array (m_pClients) that survives deinit/init, and
  // deleteClient() DEFERS deletion while the client is CONNECTED/DISCONNECTING (it sets
  // a flag and disconnects async). deinit() then tears down the host before that
  // deferred delete runs, so the slot leaks — and the next begin()'s createClient()
  // returns null forever (BLE can't restart). Waiting for a real disconnect, then
  // deleting while DISCONNECTED, frees the slot for good.
  if (g_client) {
    if (g_client->isConnected()) g_client->disconnect();
    for (int i = 0; i < 60 && g_client->isConnected(); ++i) {
      vTaskDelay(pdMS_TO_TICKS(10));
    }
    vTaskDelay(pdMS_TO_TICKS(150));  // let DISCONNECTING settle to DISCONNECTED
    NimBLEDevice::deleteClient(g_client);
    g_client = nullptr;
  }

  // Free the NimBLE host + BT controller memory back to the heap. Bonds live in
  // NVS and survive this; begin() re-initializes cleanly. Retry once if the stack
  // didn't fully tear down (stop raced something), so re-init isn't a no-op.
  NimBLEDevice::deinit(true);
  if (NimBLEDevice::isInitialized()) {
    vTaskDelay(pdMS_TO_TICKS(50));
    NimBLEDevice::deinit(true);
  }
  lifecycleStage("host_end_post");
  g_connecting = false;
  g_lastGenericCode = 0;
  g_lastReportMs = 0;
  resetPresetState();

  portENTER_CRITICAL(&g_mux);
  connected_ = false;
  connecting_ = false;
  scanning_ = false;
  deviceCount_ = 0;
  ringHead_ = 0;
  ringTail_ = 0;
  heldUsage_ = 0;
  portEXIT_CRITICAL(&g_mux);
}

void BleKeyboardHost::poll() {
  if (!begun_) return;

  // Reflect the live scanner state.
  scanning_ = NimBLEDevice::getScan()->isScanning();

  // Held-key release. Page-turner remotes stream a held key (and many omit a clean
  // release frame), so we do NOT synthesize host-side auto-repeat — that turned one
  // tap into dozens of page turns. Instead, when reports stop arriving, age the held
  // key / last generic code out so one physical press == one event and the next press
  // (even of the same button) re-triggers. Covers both the keyboard and generic paths.
  portENTER_CRITICAL(&g_mux);
  const uint8_t held = heldUsage_;
  portEXIT_CRITICAL(&g_mux);
  if ((held != 0 || g_lastGenericCode != 0) && (millis() - g_lastReportMs) > kReleaseTimeoutMs) {
    portENTER_CRITICAL(&g_mux);
    heldUsage_ = 0;
    portEXIT_CRITICAL(&g_mux);
    memset(prevKeys_, 0, sizeof(prevKeys_));
    g_lastGenericCode = 0;
  }

  // Auto-reconnect to a bonded HID peripheral.
  if (!connected_ && !g_connecting && !scanning_ && bondCount_ > 0) {
    if (connectionPermission_ && !connectionPermission_()) return;
    const uint32_t now = millis();
    if (now - g_lastReconnectMs > kReconnectBackoffMs) {
      g_lastReconnectMs = now;
      g_reconnectIdx = static_cast<uint8_t>(g_reconnectIdx % bondCount_);
      connect(bonds_[g_reconnectIdx].addr);
      g_reconnectIdx++;
    }
  }
}

// --- Discovery ---------------------------------------------------------------
void BleKeyboardHost::startScan(uint32_t ms) {
  if (!begun_) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.println("[BleHid] scan start ignored: host not begun");
#endif
    return;
  }
  if (connectionPermission_ && !connectionPermission_()) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.println("[BleHid] scan start denied by application");
#endif
    return;
  }
  if (g_connecting && g_client) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.println("[BleHid] scan start: cancelling pending reconnect");
#endif
    g_client->cancelConnect();
    const uint32_t waitStart = millis();
    while (g_connecting && millis() - waitStart < kTeardownConnectWaitMs) {
      vTaskDelay(pdMS_TO_TICKS(20));
    }
  }
  portENTER_CRITICAL(&g_mux);
  deviceCount_ = 0;
  portEXIT_CRITICAL(&g_mux);
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->clearResults();
#if FREEINK_BLE_HID_SCAN_DEBUG
  Serial.printf("[BleHid] scan start: active, continuous, %lu ms wasScanning=%d\n", static_cast<unsigned long>(ms),
                scan->isScanning() ? 1 : 0);
#endif
  const bool started = scan->start(ms, false, true);
  scanning_ = scan->isScanning();
  lifecycleStage("scan_start");
#if FREEINK_BLE_HID_SCAN_DEBUG
  Serial.printf("[BleHid] scan start result: started=%d scanning=%d\n", started ? 1 : 0, scanning_ ? 1 : 0);
#endif
}

void BleKeyboardHost::stopScan() {
  if (!begun_) return;
#if FREEINK_BLE_HID_SCAN_DEBUG
  Serial.printf("[BleHid] scan stop: wasScanning=%d devices=%u\n", NimBLEDevice::getScan()->isScanning() ? 1 : 0,
                deviceCount_);
#endif
  NimBLEDevice::getScan()->stop();
  scanning_ = false;
}

const DiscoveredDevice& BleKeyboardHost::device(uint8_t i) const {
  static const DiscoveredDevice kEmpty{};
  return i < deviceCount_ ? devices_[i] : kEmpty;
}

void BleKeyboardHost::releaseScanResults() {
  if (begun_) NimBLEDevice::getScan()->clearResults();
  portENTER_CRITICAL(&g_mux);
  deviceCount_ = 0;
  portEXIT_CRITICAL(&g_mux);
}

// --- Connection --------------------------------------------------------------
bool BleKeyboardHost::connect(const char* addr) {
  if (!begun_ || !addr || g_connecting) return false;
  if (connectionPermission_ && !connectionPermission_()) return false;

  uint8_t type = 0;
  bool knownType = false;
  for (uint8_t i = 0; i < deviceCount_; ++i) {
    if (strncmp(devices_[i].addr, addr, sizeof(devices_[i].addr)) == 0) {
      type = devices_[i].addrType;
      knownType = true;
      break;
    }
  }
  for (uint8_t i = 0; i < bondCount_; ++i) {
    if (strncmp(bonds_[i].addr, addr, sizeof(bonds_[i].addr)) == 0) {
      type = bonds_[i].addrType;
      knownType = true;
      break;
    }
  }

  strncpy(g_targetAddr, addr, sizeof(g_targetAddr) - 1);
  g_targetAddr[sizeof(g_targetAddr) - 1] = '\0';
  g_targetType = type;
  g_targetTryAltType = !knownType;
  g_connecting = true;
  connecting_ = true;
  connectFailed_ = false;
  pairingPasskeyReady_ = false;
  connectFailure_[0] = '\0';
  if (g_connTask) xTaskNotifyGive(g_connTask);
  return true;
}

void BleKeyboardHost::disconnect() {
  if (g_client && g_client->isConnected()) g_client->disconnect();
}

// --- Pairings ----------------------------------------------------------------
const PairedHidDevice& BleKeyboardHost::paired(uint8_t i) const {
  static const PairedHidDevice kEmpty{};
  return i < bondCount_ ? bonds_[i] : kEmpty;
}

void BleKeyboardHost::forget(const char* addr) {
  if (!addr) return;
  for (uint8_t i = 0; i < bondCount_; ++i) {
    if (strncmp(bonds_[i].addr, addr, sizeof(bonds_[i].addr)) != 0) continue;
    NimBLEDevice::deleteBond(NimBLEAddress(std::string(bonds_[i].addr), bonds_[i].addrType));
    for (uint8_t j = i + 1; j < bondCount_; ++j) bonds_[j - 1] = bonds_[j];
    bondCount_--;
    persistBonds();
    return;
  }
}

// --- Translated input --------------------------------------------------------
bool BleKeyboardHost::popKey(KeyEvent& out) {
  bool got = false;
  portENTER_CRITICAL(&g_mux);
  if (ringHead_ != ringTail_) {
    out = ring_[ringTail_];
    ringTail_ = static_cast<uint8_t>((ringTail_ + 1) % kKeyQueueLen);
    got = true;
  }
  portEXIT_CRITICAL(&g_mux);
  return got;
}

#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
bool BleKeyboardHost::popRawReport(RawReportDiagnostic& out) {
  bool got = false;
  portENTER_CRITICAL(&g_mux);
  if (g_rawReportHead != g_rawReportTail) {
    out = g_rawReports[g_rawReportTail];
    g_rawReportTail = static_cast<uint8_t>((g_rawReportTail + 1) % kRawReportRingLen);
    got = true;
  }
  portEXIT_CRITICAL(&g_mux);
  return got;
}

void BleKeyboardHost::clearRawReports() {
  portENTER_CRITICAL(&g_mux);
  g_rawReportHead = 0;
  g_rawReportTail = 0;
  g_rawReportSequence = 0;
  g_lastRawReportMs = 0;
  portEXIT_CRITICAL(&g_mux);
}
#endif

void BleKeyboardHost::enqueue(const KeyEvent& ev) {
  portENTER_CRITICAL(&g_mux);
  const uint8_t next = static_cast<uint8_t>((ringHead_ + 1) % kKeyQueueLen);
  if (next != ringTail_) {  // drop on overflow rather than block
    ring_[ringHead_] = ev;
    ringHead_ = next;
  }
  portEXIT_CRITICAL(&g_mux);
}

void BleKeyboardHost::emitUsage(uint8_t usage, uint8_t mods) {
  if (usage == 0) return;
  char ch;
  SpecialKey special;
  // Best-effort translation: known keyboard usages get a char / SpecialKey. Unknown
  // codes (page-turner consumer codes, vendor layouts) still surface with keycode set
  // so a capture-then-assign UI can bind them — hidTranslate already zeroes ch/special.
  hidTranslate(usage, mods, ch, special);
  KeyEvent ev;
  ev.ch = ch;
  ev.keycode = usage;
  ev.mods = mods;
  ev.special = special;
  ev.pressed = true;
  enqueue(ev);
}

void BleKeyboardHost::emitSpecial(const SpecialKey special) {
  if (special == SpecialKey::None) return;
  KeyEvent ev;
  ev.special = special;
  ev.pressed = true;
  enqueue(ev);
}

void BleKeyboardHost::resetPresetState() { g_yiserGesture = YiserGestureState{}; }

void BleKeyboardHost::processYiserReport(const uint8_t* data, const size_t len) {
  if (!data || len < 5) return;
  const uint32_t now = millis();
  // Standalone Confirm is emitted on its release report.  Do not discard that
  // pending state merely because the user held the ring for longer than the
  // directional-burst recognition window; the next report is still bounded
  // and PendingConfirm itself decides whether it is the matching release or
  // the beginning of a directional gesture.  Directional states retain the
  // short timeout so a partial burst cannot remain active indefinitely.
  if (g_yiserGesture.kind != YiserGesture::Idle && g_yiserGesture.kind != YiserGesture::PendingConfirm &&
      now - g_yiserGesture.startedMs > kYiserGestureTimeoutMs) {
    resetPresetState();
  }

  const uint8_t status = data[0];
  const uint8_t code = data[1];
  uint16_t axis = 0;
  memcpy(&axis, data + 3, sizeof(axis));  // HID payload may be unaligned.
  const bool pressed = status != 0;

  constexpr uint8_t kVertical[] = {0x2C, 0x18, 0x2C, 0x18, 0x2C, 0x18, 0x22};
  constexpr uint8_t kLeft[] = {0x96, 0xC8, 0xFA, 0x2C, 0x5E, 0x90, 0xC2};
  constexpr uint8_t kRight[] = {0x90, 0x5E, 0x2C, 0xC8, 0x96, 0x64, 0x32};

  switch (g_yiserGesture.kind) {
    case YiserGesture::Idle:
      if (!pressed) return;
      if (code == 0xA4) {
        emitSpecial(SpecialKey::Escape);  // Back
        return;
      }
      if (code == 0x2C) {
        // Confirm is delayed until the matching release. The same 0x2C code is
        // the first and fourth member of the directional ring gestures.
        g_yiserGesture.kind = YiserGesture::PendingConfirm;
        g_yiserGesture.step = 1;
        g_yiserGesture.firstAxis = axis;
        g_yiserGesture.startedMs = now;
        return;
      }
      if (code == kLeft[0]) {
        g_yiserGesture.kind = YiserGesture::Left;
        g_yiserGesture.step = 1;
        g_yiserGesture.startedMs = now;
        return;
      }
      if (code == kRight[0]) {
        g_yiserGesture.kind = YiserGesture::Right;
        g_yiserGesture.step = 1;
        g_yiserGesture.startedMs = now;
      }
      return;

    case YiserGesture::PendingConfirm:
      if (!pressed) {
        if (code == 0x2C && axis == 0x01F4) emitSpecial(SpecialKey::Enter);  // Confirm
        resetPresetState();
        return;
      }
      // Directional bursts never use the standalone Confirm axis value.
      if (code == 0x18 || (code == 0x2C && axis != 0x01F4)) {
        g_yiserGesture.kind = YiserGesture::Vertical;
        g_yiserGesture.step = 2;
        g_yiserGesture.startedMs = now;
        return;
      }
      resetPresetState();
      return;

    case YiserGesture::Vertical:
      if (!pressed || g_yiserGesture.step >= sizeof(kVertical) || code != kVertical[g_yiserGesture.step]) {
        resetPresetState();
        return;
      }
      ++g_yiserGesture.step;
      if (g_yiserGesture.step == sizeof(kVertical)) {
        emitSpecial(g_yiserGesture.firstAxis >= 0x0200 ? SpecialKey::Down : SpecialKey::Up);
        g_yiserGesture.kind = YiserGesture::AwaitRelease;
      }
      return;

    case YiserGesture::Left:
      if (!pressed || g_yiserGesture.step >= sizeof(kLeft) || code != kLeft[g_yiserGesture.step]) {
        resetPresetState();
        return;
      }
      ++g_yiserGesture.step;
      if (g_yiserGesture.step == sizeof(kLeft)) {
        emitSpecial(SpecialKey::Left);
        g_yiserGesture.kind = YiserGesture::AwaitRelease;
      }
      return;

    case YiserGesture::Right:
      if (!pressed || g_yiserGesture.step >= sizeof(kRight) || code != kRight[g_yiserGesture.step]) {
        resetPresetState();
        return;
      }
      ++g_yiserGesture.step;
      if (g_yiserGesture.step == sizeof(kRight)) {
        emitSpecial(SpecialKey::Right);
        g_yiserGesture.kind = YiserGesture::AwaitRelease;
      }
      return;

    case YiserGesture::AwaitRelease:
      if (!pressed) resetPresetState();
      return;
  }
}

// --- Internal hooks from the BLE backend -------------------------------------
void BleKeyboardHost::onReportIngest(const uint8_t* data, size_t len, const uint8_t source) {
  if (!data || len == 0) return;
  const uint32_t reportMs = millis();
  g_lastReportMs = reportMs;  // freshness for the stale-release timeout in poll()

#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
  RawReportDiagnostic raw;
  raw.sequence = ++g_rawReportSequence;
  raw.uptimeMs = reportMs;
  const uint32_t delta = g_lastRawReportMs == 0 ? 0 : reportMs - g_lastRawReportMs;
  raw.deltaMs = delta > 0xFFFFu ? 0xFFFFu : static_cast<uint16_t>(delta);
  g_lastRawReportMs = reportMs;
  raw.source = source;
  raw.reportType = 1;  // setupHid subscribes only to HID input reports.
  raw.reportId = source == 1 && len == 9 ? data[0] : 0xFF;
  raw.length = len > 0xFFFFu ? 0xFFFF : static_cast<uint16_t>(len);
  raw.storedLength = len > RawReportDiagnostic::kMaxPayloadBytes
                         ? RawReportDiagnostic::kMaxPayloadBytes
                         : static_cast<uint8_t>(len);
  raw.truncated = len > RawReportDiagnostic::kMaxPayloadBytes;
  memcpy(raw.payload, data, raw.storedLength);
#endif

#if FREEINK_BLE_HID_REPORT_DEBUG
  {
    char buf[64];
    size_t off = 0;
    const size_t dump = len < 16 ? len : 16;
    for (size_t i = 0; i < dump && off + 3 < sizeof(buf); ++i) {
      off += snprintf(buf + off, sizeof(buf) - off, "%02X ", data[i]);
    }
    Serial.printf("[BleHid] report len=%u %s\n", (unsigned)len, buf);
  }
#endif

  // Normalize: strip a leading report id (len 9). Boot/report-protocol keyboard
  // reports are [mod][reserved][k0..k5] (8 bytes) or a compact [mod][k0..k5] (7).
  const uint8_t* p = data;
  size_t n = len;
  if (n == 9) {
    p += 1;
    n -= 1;
  }

  if (inputPreset_ == InputPreset::YiserJ6Ring) {
    processYiserReport(p, n);
#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
    enqueueRawDiagnostic(raw);
#endif
    return;
  }

  // --- Standard keyboard report path -----------------------------------------
  uint8_t mod = 0;
  uint8_t keys[6] = {0};
  bool keyboardShaped = false;
  if (n >= 8) {
    mod = p[0];
    for (int i = 0; i < 6; ++i) keys[i] = p[2 + i];
    keyboardShaped = true;
  } else if (n == 7) {
    mod = p[0];
    for (int i = 0; i < 6; ++i) keys[i] = p[1 + i];
    keyboardShaped = true;
  }

  bool emittedKb = false;
  if (keyboardShaped) {
#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
    raw.state |= RAW_STATE_KEYBOARD_SHAPED;
#endif
    // Emit a press for every key newly present versus the previous report.
    for (int i = 0; i < 6; ++i) {
      const uint8_t k = keys[i];
      if (k == 0 || k == 0x01 /*ErrorRollOver*/) continue;
      bool wasDown = false;
      for (int j = 0; j < 6; ++j) {
        if (prevKeys_[j] == k) {
          wasDown = true;
          break;
        }
      }
      if (!wasDown) {
        emitUsage(k, mod);
        emittedKb = true;
      }
    }

    // Track the last held key for auto-repeat.
    uint8_t cur = 0;
    for (int i = 0; i < 6; ++i) {
      if (keys[i] != 0 && keys[i] != 0x01) cur = keys[i];
    }
#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
    if (cur == 0) raw.state |= RAW_STATE_RELEASE_EDGE;
    if (emittedKb) raw.state |= RAW_STATE_PRESS_EDGE;
#endif
    portENTER_CRITICAL(&g_mux);
    if (cur == 0) {
      heldUsage_ = 0;
    } else if (cur != heldUsage_) {
      heldUsage_ = cur;
      heldMods_ = mod;
      heldSince_ = millis();
      lastRepeat_ = millis();
    }
    portEXIT_CRITICAL(&g_mux);

    memcpy(prevKeys_, keys, sizeof(prevKeys_));
  }

  // --- Generic fallback for non-keyboard remotes -----------------------------
  // Many page turners are not boot keyboards: they emit on the Consumer Control
  // page or place the code at a non-standard byte. When the keyboard slots produced
  // nothing and the device doesn't look like a pure keyboard, scan the report for a
  // representative code and surface it (edge-detected so one press == one event).
  const bool tryGeneric = !emittedKb && (g_hasConsumerPage || !g_hasKeyboardPage || n < 7);
  if (tryGeneric) {
#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
    raw.state |= RAW_STATE_GENERIC_PATH;
#endif
    size_t codeIdx = 0;
    const uint8_t code = extractPrimaryCode(p, n, &codeIdx);
    // Gamepad-style modes keep constant bits in the button byte and only clear
    // the pressed bit on release (ino gamebrick mode T: 0x13 pressed -> 0x12
    // released, bit0 is the button). "code changed" alone emits a phantom
    // second press on that release frame. A press must SET at least one bit
    // the previous code didn't have; a bit-subset of the previous code is a
    // (partial) release, never a new press. Value-coded remotes are unaffected
    // in practice: their release frame is all-zero (code 0), and the 150 ms
    // stale-release timeout in poll() zeroes g_lastGenericCode between any two
    // human-separated presses.
    const bool pressEdge = code != 0 && code != g_lastGenericCode && (code & ~g_lastGenericCode) != 0;
    const bool releaseEdge = code != 0 && code != g_lastGenericCode && (code & ~g_lastGenericCode) == 0;
#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
    if (code == 0 || releaseEdge) raw.state |= RAW_STATE_RELEASE_EDGE;
    if (pressEdge) raw.state |= RAW_STATE_PRESS_EDGE;
    if (codeIdx == 0 && n >= 5) raw.state |= RAW_STATE_AXIS_CANDIDATE;
#endif
    if (codeIdx == 0 && n >= 5) {
      // Gamepad/axis-pair mode (ino gamebrick T): byte 0 is a status byte whose
      // bit0 is "pressed" (0x13 press -> 0x12 release), bytes 1-4 are two 16-bit
      // LE axes centered at ~2000. Every button raises the same pressed bit; the
      // identity lives in where the axes sit. The FIRST press frame is not
      // trustworthy (a direction press starts near center and ramps toward its
      // extreme over several frames), but the release frame still carries the
      // final held values ("12 D0 07 84 03" = up, "12 D0 07 10 0E" = down,
      // "12 B8 0B D0 07" = A, "12 B8 0B C4 09" = B). So classify on the release
      // edge: quantize each axis into low/center/high and emit a synthetic code
      // from the zone pair. Both-axes-centered carries no identity (bare
      // release) and emits nothing.
      if (releaseEdge) {
        uint16_t axis1, axis2;  // memcpy: p may be unaligned (RISC-V faults on unaligned loads)
        memcpy(&axis1, p + 1, sizeof(axis1));
        memcpy(&axis2, p + 3, sizeof(axis2));
        constexpr uint16_t kAxisCenter = 2000;
        constexpr uint16_t kAxisDeadband = 300;  // B rests at center+500; center noise stays inside +/-300
        const auto zone = [](uint16_t v) -> uint8_t {
          if (v < kAxisCenter - kAxisDeadband) return 0;
          if (v > kAxisCenter + kAxisDeadband) return 2;
          return 1;
        };
        const uint8_t zonePair = zone(axis1) * 3 + zone(axis2);
        if (zonePair != 4) {  // 4 = both centered: nothing to bind
          emitUsage(0x40 + zonePair, 0);
        }
      }
    } else if (pressEdge) {
      // Value-coded remotes (e.g. "01 00 00" press, all-zero release): the code
      // byte IS the identity; emit on the press edge as before.
      emitUsage(code, 0);
    }
    g_lastGenericCode = code;
  } else if (emittedKb) {
    g_lastGenericCode = 0;
  }

#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
  enqueueRawDiagnostic(raw);
#endif
}

void BleKeyboardHost::onScanResultIngest(const char* addr, const char* name, int rssi, uint8_t type, bool hid,
                                         bool connectable) {
  if (!addr) return;
  // A "real" name (not the address fallback) should never be downgraded back to
  // the address on a later primary-only advertisement.
  const bool realName = name && name[0] && strcmp(name, addr) != 0;
#if !FREEINK_BLE_HID_SHOW_UNNAMED_DEVICES
  if (!realName && !hid) {
#if FREEINK_BLE_HID_SCAN_DEBUG
    Serial.printf("[BleHid] scan filtered: %s name='%s' rssi=%d hid=%d conn=%d type=%u\n", addr, name ? name : "",
                  rssi, hid ? 1 : 0, connectable ? 1 : 0, type);
#endif
    return;
  }
#endif
  portENTER_CRITICAL(&g_mux);

  // Upsert by address.
  uint8_t idx = deviceCount_;
  for (uint8_t i = 0; i < deviceCount_; ++i) {
    if (strncmp(devices_[i].addr, addr, sizeof(devices_[i].addr)) == 0) {
      idx = i;
      break;
    }
  }

  if (idx != deviceCount_) {
    // Known device: refresh RSSI; upgrade to a real name / HID flag if we just
    // learned one (these can arrive in a later advertisement or scan response).
    DiscoveredDevice& d = devices_[idx];
    d.rssi = rssi;
    if (hid) d.hid = true;
    if (connectable) d.connectable = true;
    if (realName) {
      strncpy(d.name, name, sizeof(d.name) - 1);
      d.name[sizeof(d.name) - 1] = '\0';
      d.hasName = true;
    }
    portEXIT_CRITICAL(&g_mux);
    return;
  }

  // New device.
  if (deviceCount_ < kMaxDiscovered) {
    idx = deviceCount_++;
  } else {
    // Full: evict the weakest-RSSI entry if this one is stronger, so nearby
    // input peripherals are not crowded out by distant beacons.
    uint8_t weakest = 0;
    for (uint8_t i = 1; i < deviceCount_; ++i) {
      if (devices_[i].rssi < devices_[weakest].rssi) weakest = i;
    }
    if (rssi <= devices_[weakest].rssi) {
      portEXIT_CRITICAL(&g_mux);
      return;
    }
    idx = weakest;
  }

  DiscoveredDevice& d = devices_[idx];
  strncpy(d.addr, addr, sizeof(d.addr) - 1);
  d.addr[sizeof(d.addr) - 1] = '\0';
  strncpy(d.name, name && name[0] ? name : addr, sizeof(d.name) - 1);
  d.name[sizeof(d.name) - 1] = '\0';
  d.rssi = rssi;
  d.addrType = type;
  d.hasName = realName;
  d.hid = hid;
  d.connectable = connectable;
#if FREEINK_BLE_HID_SCAN_DEBUG
  Serial.printf("[BleHid] scan accepted: idx=%u count=%u addr=%s name='%s' rssi=%d hid=%d conn=%d type=%u\n", idx,
                deviceCount_, d.addr, d.name, d.rssi, d.hid ? 1 : 0, d.connectable ? 1 : 0, d.addrType);
#endif
  portEXIT_CRITICAL(&g_mux);
}

void BleKeyboardHost::onLinkUp(const char* addr, const char* name, uint8_t type, const char* identityAddr,
                               const uint8_t identityType) {
  // Resolve a friendly name from the scan or bond lists if the caller has none.
  const char* resolved = (name && name[0] && (!addr || strcmp(name, addr) != 0)) ? name : nullptr;
  const char* lookupAddresses[2] = {addr, identityAddr};
  for (const char* lookup : lookupAddresses) {
    if (resolved || !lookup || !lookup[0]) continue;
    for (uint8_t i = 0; i < deviceCount_; ++i) {
      if (strncmp(devices_[i].addr, lookup, sizeof(devices_[i].addr)) == 0 && devices_[i].hasName &&
          devices_[i].name[0] && strcmp(devices_[i].name, lookup) != 0) {
        resolved = devices_[i].name;
        break;
      }
    }
  }
  for (const char* lookup : lookupAddresses) {
    if (resolved || !lookup || !lookup[0]) continue;
    for (uint8_t i = 0; i < bondCount_; ++i) {
      if (strncmp(bonds_[i].addr, lookup, sizeof(bonds_[i].addr)) == 0 && bonds_[i].name[0]) {
        resolved = bonds_[i].name;
        break;
      }
    }
  }
  char resolvedName[sizeof(connName_)] = {};
  if (resolved) {
    strncpy(resolvedName, resolved, sizeof(resolvedName) - 1);
  }
  connName_[0] = '\0';
  if (resolved) {
    strncpy(connName_, resolvedName, sizeof(connName_) - 1);
    connName_[sizeof(connName_) - 1] = '\0';
  } else if (identityAddr && identityAddr[0]) {
    strncpy(connName_, identityAddr, sizeof(connName_) - 1);
    connName_[sizeof(connName_) - 1] = '\0';
  } else if (addr) {
    strncpy(connName_, addr, sizeof(connName_) - 1);
    connName_[sizeof(connName_) - 1] = '\0';
  }

  // Persist the NimBLE identity address, not a temporary OTA address. This
  // keeps resolvable-private-address reconnects attached to the existing bond.
  const char* canonicalAddr = identityAddr && identityAddr[0] ? identityAddr : addr;
  const uint8_t canonicalType = identityAddr && identityAddr[0] ? identityType : type;
  if (canonicalAddr) {
    int knownIndex = -1;
    for (uint8_t i = 0; i < bondCount_; ++i) {
      if ((addr && strncmp(bonds_[i].addr, addr, sizeof(bonds_[i].addr)) == 0) ||
          strncmp(bonds_[i].addr, canonicalAddr, sizeof(bonds_[i].addr)) == 0 ||
          (resolvedName[0] && strcmp(bonds_[i].name, resolvedName) == 0)) {
        knownIndex = i;
        break;
      }
    }
    bool needsPersist = false;
    if (knownIndex >= 0) {
      PairedHidDevice& b = bonds_[knownIndex];
      if (strncmp(b.addr, canonicalAddr, sizeof(b.addr)) != 0) {
        strncpy(b.addr, canonicalAddr, sizeof(b.addr) - 1);
        b.addr[sizeof(b.addr) - 1] = '\0';
        needsPersist = true;
      }
      if (b.addrType != canonicalType) {
        b.addrType = canonicalType;
        needsPersist = true;
      }
      if (resolvedName[0] && strcmp(b.name, resolvedName) != 0) {
        strncpy(b.name, resolvedName, sizeof(b.name) - 1);
        b.name[sizeof(b.name) - 1] = '\0';
        needsPersist = true;
      }
      if (needsPersist) persistBonds();
    } else if (bondCount_ < kMaxBonds) {
      PairedHidDevice& b = bonds_[bondCount_++];
      strncpy(b.addr, canonicalAddr, sizeof(b.addr) - 1);
      b.addr[sizeof(b.addr) - 1] = '\0';
      b.name[0] = '\0';
      if (resolvedName[0]) {
        strncpy(b.name, resolvedName, sizeof(b.name) - 1);
        b.name[sizeof(b.name) - 1] = '\0';
      }
      b.addrType = canonicalType;
      persistBonds();
    }
  }

  g_reconnectIdx = 0;
  connecting_ = false;
  connected_ = true;
}

void BleKeyboardHost::onLinkDown() {
  connected_ = false;
  connecting_ = false;
  resetPresetState();
  portENTER_CRITICAL(&g_mux);
  heldUsage_ = 0;
  portEXIT_CRITICAL(&g_mux);
}

void BleKeyboardHost::onConnectFailed(const char* reason) {
  connected_ = false;
  connecting_ = false;
  resetPresetState();
  portENTER_CRITICAL(&g_mux);
  strncpy(connectFailure_, reason && reason[0] ? reason : "Connection failed", sizeof(connectFailure_) - 1);
  connectFailure_[sizeof(connectFailure_) - 1] = '\0';
  connectFailed_ = true;
  heldUsage_ = 0;
  portEXIT_CRITICAL(&g_mux);
}

void BleKeyboardHost::onConnectionDeferred() {
  connecting_ = false;
  pairingPasskeyReady_ = false;
  resetPresetState();
  portENTER_CRITICAL(&g_mux);
  heldUsage_ = 0;
  portEXIT_CRITICAL(&g_mux);
}

bool BleKeyboardHost::takeConnectFailure(char* out, size_t outLen) {
  if (!out || outLen == 0) return false;
  bool failed = false;
  portENTER_CRITICAL(&g_mux);
  if (connectFailed_) {
    strncpy(out, connectFailure_, outLen - 1);
    out[outLen - 1] = '\0';
    connectFailed_ = false;
    failed = true;
  }
  portEXIT_CRITICAL(&g_mux);
  return failed;
}

void BleKeyboardHost::onPairingPasskey(uint32_t passkey) {
  portENTER_CRITICAL(&g_mux);
  pairingPasskey_ = passkey;
  pairingPasskeyReady_ = true;
  portEXIT_CRITICAL(&g_mux);
}

bool BleKeyboardHost::takePairingPasskey(uint32_t& out) {
  bool ready = false;
  portENTER_CRITICAL(&g_mux);
  if (pairingPasskeyReady_) {
    out = pairingPasskey_;
    pairingPasskeyReady_ = false;
    ready = true;
  }
  portEXIT_CRITICAL(&g_mux);
  return ready;
}

// --- NVS persistence ---------------------------------------------------------
void BleKeyboardHost::loadBonds() {
  Preferences p;
  if (!p.begin("freeink-hid", true)) return;
  bondCount_ = p.getUChar("n", 0);
  if (bondCount_ > kMaxBonds) bondCount_ = kMaxBonds;
  if (bondCount_ > 0) p.getBytes("b", bonds_, bondCount_ * sizeof(PairedHidDevice));
  p.end();
  bool cleaned = false;
  for (uint8_t i = 0; i < bondCount_; ++i) {
    if (bonds_[i].name[0] && strcmp(bonds_[i].name, bonds_[i].addr) == 0) {
      bonds_[i].name[0] = '\0';
      cleaned = true;
    }
  }
  if (cleaned) persistBonds();
}

void BleKeyboardHost::persistBonds() {
  Preferences p;
  if (!p.begin("freeink-hid", false)) return;
  p.putUChar("n", bondCount_);
  if (bondCount_ > 0) p.putBytes("b", bonds_, bondCount_ * sizeof(PairedHidDevice));
  p.end();
}

}  // namespace freeink

#else  // !FREEINK_CAP_BLE_HID_HOST — stub bodies, no BLE code linked.

namespace freeink {

bool BleKeyboardHost::begin(const char*) { return false; }
void BleKeyboardHost::end() {}
void BleKeyboardHost::poll() {}
void BleKeyboardHost::startScan(uint32_t) {}
void BleKeyboardHost::stopScan() {}
const DiscoveredDevice& BleKeyboardHost::device(uint8_t) const {
  static const DiscoveredDevice kEmpty{};
  return kEmpty;
}
void BleKeyboardHost::releaseScanResults() {}
bool BleKeyboardHost::connect(const char*) { return false; }
void BleKeyboardHost::disconnect() {}
const PairedHidDevice& BleKeyboardHost::paired(uint8_t) const {
  static const PairedHidDevice kEmpty{};
  return kEmpty;
}
void BleKeyboardHost::forget(const char*) {}
bool BleKeyboardHost::popKey(KeyEvent&) { return false; }
#if FREEINK_BLE_HID_RAW_DIAGNOSTICS
bool BleKeyboardHost::popRawReport(RawReportDiagnostic&) { return false; }
void BleKeyboardHost::clearRawReports() {}
#endif
void BleKeyboardHost::onScanResultIngest(const char*, const char*, int, uint8_t, bool, bool) {}
void BleKeyboardHost::onReportIngest(const uint8_t*, size_t, uint8_t) {}
void BleKeyboardHost::onLinkUp(const char*, const char*, uint8_t, const char*, uint8_t) {}
void BleKeyboardHost::onLinkDown() {}
void BleKeyboardHost::onConnectFailed(const char*) {}
void BleKeyboardHost::onConnectionDeferred() {}
bool BleKeyboardHost::takeConnectFailure(char*, size_t) { return false; }
void BleKeyboardHost::onPairingPasskey(uint32_t) {}
bool BleKeyboardHost::takePairingPasskey(uint32_t&) { return false; }
void BleKeyboardHost::enqueue(const KeyEvent&) {}
void BleKeyboardHost::emitUsage(uint8_t, uint8_t) {}
void BleKeyboardHost::emitSpecial(SpecialKey) {}
void BleKeyboardHost::resetPresetState() {}
void BleKeyboardHost::processYiserReport(const uint8_t*, size_t) {}
void BleKeyboardHost::persistBonds() {}
void BleKeyboardHost::loadBonds() {}

}  // namespace freeink

#endif  // FREEINK_CAP_BLE_HID_HOST

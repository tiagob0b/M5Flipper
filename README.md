# M5Flipper
Hardware hacking tool para M5Paper V1.1 — WiFi Scanner, Deauth, Beacon Spam, Evil Twin, PMKID/Handshake capture, WPS Scanner, Channel Analyzer e mais. Inspirado no Flipper Zero.

Um canivete suíço de segurança Wi-Fi que roda no M5Paper (ESP32 + ecrã EPD 4.7")
com interface totalmente por toque. Captura, analisa e injeta frames 802.11 sem
necessidade de computador externo.

  ---

  ## Hardware necessário

  | Componente | Especificação |
  |---|---|
  | Placa | M5Stack M5Paper V1.1 |
  | SoC | ESP32-D0WDQ6-V3 |
  | Ecrã | EPD 4.7" IT8951 · 960×540 · touch GT911 |
  | Armazenamento | MicroSD (SPI compartilhado com EPD) |
  | RTC | BM8563 |

  🔗 Shop: [https://https://shop.m5stack.com/products/m5paper-esp32-development-kit-v1-1-960x540-4-7-eink-display-235-ppi](https://shop.m5stack.com/products/m5paper-esp32-development-kit-v1-1-960x540-4-7-eink-display-235-ppi)

  ---

  ## Funções implementadas

  ### 📡 WiFi Scanner
  Varre redes 2.4 GHz e exibe lista ordenada com SSID, BSSID, canal, autenticação
  (OPEN / WEP / WPA / WPA2 / WPA3) e barras de sinal. A partir de qualquer rede
  seleccionada estão acessíveis todas as outras ferramentas abaixo.

  ---

  ### 💀 Deauth Attack
  Injeta frames 802.11 de desautenticação (Management, subtype 0xC0) em broadcast
  contra o AP alvo. Exibe contador de pacotes enviados e tempo de ataque em tempo real.

  > ⚠️  Uso exclusivamente em redes próprias ou com autorização expressa.

  ---

  ### 🔍 Probe Monitor
  Modo promíscuo com channel hopping (canais 1–13, 250 ms cada).
  Captura frames Probe Request e regista:
  - MAC do dispositivo
  - SSID procurado (ou broadcast `<any>`)
  - RSSI e contagem de frames

  Até 50 entradas com scroll. Gravação em CSV no SD.

  ---

  ### 🛡️  PMKID Capture
  Captura o PMKID do EAPOL Frame 1 (AP → STA) sem necessitar de cliente associado.
  Grava o resultado em formato **hc22000** pronto para Hashcat:
  WPA01**
  Visualização e exportação via SD Analyzer.

  ---

  ### 🤝 Handshake WPA2
  Captura o 4-way handshake EAPOL completo (Frame 1 + Frame 2).
  Extrai ANonce, SNonce e MIC. Grava em formato **hc22000**:
  WPA02**01

  ---

  ### 📣 Beacon Spam
  Injeta beacons 802.11 a ~100 frames/segundo. Dois modos:

  | Modo | Comportamento |
  |---|---|
  | **RANDOM** | SSIDs e MACs gerados aleatoriamente, rotação a cada 30 beacons |
  | **CLONE** | Clona SSID + MAC do AP seleccionado no WiFi Scanner |

  Exibe lista circular dos últimos 8 SSIDs transmitidos.

  ---

  ### 👥 Client Tracker
  Modo promíscuo com detecção de STAs associadas. Dois modos:

  | Modo | Comportamento |
  |---|---|
  | **Global** | Channel hopping 1–13 (300 ms/canal), lista todos os clientes visíveis |
  | **Filtrado** | Fixado no canal do AP seleccionado, lista apenas clientes desse AP |

  Regista MAC, BSSID, RSSI, contagem de frames e última actividade.
  Gravação em CSV no SD. Até 40 entradas.

  ---

  ### 😈 Evil Twin (AP Falso + Captive Portal)
  Cria um AP clone sem password no mesmo canal do alvo.
  - **DNS wildcard** → redireciona todo o tráfego para o portal
  - **Captive portal HTML** → página de login idêntica à de router doméstico
  - **Deauth contínuo** → desliga clientes do AP real forçando ligação ao clone
  - Credenciais capturadas gravadas em `/creds_TIMESTAMP.txt` no SD
  - Ecrã atualizado a cada 1,5 s com lista de passwords obtidas

  > ⚠️  Uso exclusivamente em ambientes controlados e com autorização.

  ---

  ### 📊 Channel Analyzer
  Analisa utilização dos 13 canais 2.4 GHz:
  - Gráfico de barras com contagem de APs por canal
  - Código de cor: cinza claro (0) → preto (4+ APs)
  - Grid pontilhado a 25/50/75%
  - Marcadores `*` nos canais não sobrepostos (1, 6, 11)
  - Selecção por toque numa barra → detalhe com até 3 SSIDs, auth e RSSI
  - Recomendação automática do canal menos congestionado
  - Botões `[<]` `[>]` para navegar canais

  ---

  ### 🔓 WPS Scanner
  Varre os 13 canais em modo promíscuo (500 ms/canal) e detecta APs com WPS activo
  via parsing do Vendor Specific IE (OUI `00:50:F2:04`).

  Informação extraída por AP:
  | Campo | Descrição |
  |---|---|
  | **Versão** | 1.0 ou 2.0 |
  | **Estado** | NConf (não configurado) / Conf (configurado) |
  | **Locked** | AP Setup Locked — bloqueado após tentativas de PIN falhadas |

  Barra de progresso do scan em tempo real. WPS v1.0 é vulnerável a ataques
  Pixie Dust e brute-force de PIN (8 dígitos → efetivamente 11 000 combinações).

  ---

  ### 🗂️  SD Analyzer
  Navega e analisa os ficheiros gravados pelo M5Flipper no cartão SD.
  Detecção automática por prefixo de nome:

  | Prefixo | Tipo |
  |---|---|
  | `wifi_*.csv` | WiFi Scan |
  | `hs_*.hc22000` | Handshake WPA2 |
  | `pmkid_*.hc22000` | PMKID |
  | `clients_*.csv` | Client Tracker |
  | `creds_*.txt` | Evil Twin |

  Preview de conteúdo com parsing de linhas hc22000 (exibe hash type, SSID, BSSID,
  STA, MIC/PMKID). Botão `[>> Serial]` para dump direto no monitor série.
  Apagar ficheiros diretamente no dispositivo.

  ---

  ### ⚙️  System Info
  - Nível de bateria, RAM livre, chip ID
  - Hora e data via RTC BM8563 (editável por toque)
  - Botões de Reiniciar e Desligar

  ---

  ## Configuração Arduino IDE

  ### Dependências

  | Biblioteca | Fonte |
  |---|---|
  | M5Unified | Library Manager |
  | DNSServer | built-in ESP32 Arduino |
  | WebServer | built-in ESP32 Arduino |

  ### Board

  Board Manager URL: https://m5stack.oss-cn-shenzhen.aliyuncs.com/resource/arduino/package_m5stack_index.json
  Board: M5Stack > M5Paper

  ### Partition Scheme
  Recomendado: **Huge APP (3MB No OTA/1MB SPIFFS)** — o código excede 1 MB.

  ---

  ## Estrutura de ficheiros no SD

  /
  ├── wifi_20260413_142530.csv       ← WiFi Scan
  ├── hs_20260413_143012.hc22000     ← Handshake WPA2
  ├── pmkid_20260413_143500.hc22000  ← PMKID
  ├── clients_20260413_144000.csv    ← Client Tracker
  └── creds_20260413_150000.txt      ← Evil Twin credentials

  ---

  ## Aviso legal

  Este projeto é desenvolvido exclusivamente para fins **educacionais e de investigação
  em segurança**. A utilização das funcionalidades de ataque (Deauth, Evil Twin,
  Beacon Spam, PMKID/Handshake capture) em redes sem autorização expressa do
  proprietário é **ilegal** na maioria das jurisdições.

  O autor não se responsabiliza por qualquer utilização indevida.

  ---
  
  ## Demo
  
 [![Assista à demo](https://img.youtube.com/vi/3ELKX3h7WS8/0.jpg)](https://www.youtube.com/watch?v=3ELKX3h7WS8)

  ## Roadmap

  - [x] WiFi Scanner
  - [x] Deauth Attack
  - [x] Probe Monitor
  - [x] PMKID Capture
  - [x] Handshake WPA2
  - [x] Beacon Spam
  - [x] Client Tracker
  - [x] Evil Twin + Captive Portal
  - [x] Channel Analyzer
  - [x] WPS Scanner
  - [x] SD Analyzer
  - [X] WPS Scanner
  - [X] Deauth Detector
  - [ ] Karma Attack
  - [ ] WPA Enterprise Detector
  - [ ] Hidden SSID Revealer
  - [ ] Signal Logger / Wardriving
  - [ ] BLE Scanner (bloqueado por limitação de IRAM do SDK actual)

  ---

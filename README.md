# wazuh-log-exporter-sender

Compliance-pohjainen lokien arkistointityökalu Wazuh single-node -asennuksille.

Kerää Wazuhin rotaamat lokitiedostot tunneittain, allekirjoittaa ja/tai salaa ne
GPG:llä ja lähettää SFTP-palvelimelle. Suunniteltu KATAKRI 2020 / NIST SP 800-92
-vaatimusten täyttämiseen.

**Nolla ulkoisia Python-riippuvuuksia** — toimii pelkällä stdlib:llä + OpenSSH + GPG.
Sopii air-gap-ympäristöihin, joissa pip ei ole käytettävissä.

---

## Sisällysluettelo

- [Arkkitehtuuri](#arkkitehtuuri)
- [Tiedostorakenne](#tiedostorakenne)
- [Vaatimukset](#vaatimukset)
- [Asennus](#asennus)
- [Wazuhin konfigurointi](#wazuhin-konfigurointi)
- [Konfiguraatiotiedosto](#konfiguraatiotiedosto)
- [GPG-avainten hallinta](#gpg-avainten-hallinta)
- [SFTP-yhteys](#sftp-yhteys)
- [Systemd-ajastus](#systemd-ajastus)
- [Testaus](#testaus)
- [SFTP-säilöön päätyvät tiedostot](#sftp-säilöön-päätyvät-tiedostot)
- [KATAKRI 2020 -vaatimusten kattavuus](#katakri-2020--vaatimusten-kattavuus)
- [Vianetsintä](#vianetsintä)

---

## Arkkitehtuuri

```
Wazuh (Docker, single-node)
│
│  /opt/wazuh/logs/archives/YYYY/Mon/ossec-archive-DD-HH.json.gz
│  /opt/wazuh/logs/alerts/YYYY/Mon/ossec-alerts-DD-HH.json.gz
│
│  [systemd timer — joka tunti :05]
│
│  archiver.py
│    1. Löytää käsittelemättömät .json.gz -tiedostot
│    2. Laskee SHA-256
│    3. GPG-allekirjoitus (.sig)    ← optio
│    4. GPG-salaus (.gpg)           ← optio
│    5. SFTP-siirto (sftp -b batch)
│    6. Päivittää state.json
│    7. Kirjaa audit-merkinnän
│
SFTP-palvelin
  /archive/wazuh/
    ossec-archive-20-14.json.gz
    ossec-archive-20-14.json.gz.sha256
    ossec-archive-20-14.json.gz.sig    ← jos signing ON
    ossec-archive-20-14.json.gz.gpg   ← jos encryption ON
```

---

## Tiedostorakenne

```
wazuh-log-exporter-sender/
├── archiver.py                  # Pääskripti
├── archiver.conf.example        # Konfiguraatiopohja
├── requirements.txt             # Ei ulkoisia riippuvuuksia (dokumentaatio)
├── ossec-conf-snippet.xml       # Wazuhin ossec.conf -muutokset
├── setup.sh                     # Asennusskripti
└── systemd/
    ├── wazuh-archiver.service   # Systemd-palvelu
    └── wazuh-archiver.timer     # Systemd-ajastin (tunneittain)
```

---

## Vaatimukset

| Komponentti | Versio | Paketti (Debian/Ubuntu) |
|-------------|--------|------------------------|
| Python 3 | 3.8+ | `python3` |
| OpenSSH client | mitä tahansa | `openssh-client` |
| GnuPG | 2.x | `gnupg` |

GPG tarvitaan vain jos `signing = true` tai `encryption = true`.

```bash
# Tarkista saatavuus
python3 --version
sftp -V
gpg --version
```

---

## Asennus

### 1. Kloonaa repo

```bash
git clone git@github.com:mikkokuusela/wazuh-log-exporter-sender.git
cd wazuh-log-exporter-sender
```

### 2. Aja asennusskripti (root)

```bash
sudo bash setup.sh
```

Skripti tekee seuraavat:
- Luo järjestelmäkäyttäjän `wazuh-archiver`
- Asentaa skriptin `/usr/local/bin/wazuh-archiver`
- Luo hakemistot oikeilla käyttöoikeuksilla
- Kopioi konfiguraatiopohjan `/etc/wazuh-archiver/archiver.conf`
- Asentaa systemd-unitit

### 3. Muokkaa konfiguraatio

```bash
sudo nano /etc/wazuh-archiver/archiver.conf
```

Täytä vähintään:
- `[wazuh] log_dirs` — lokihakemistojen polut hostilla
- `[sftp] host`, `username`, `ssh_key_path`, `remote_dir`

### 4. Aseta SFTP-yhteys

```bash
# Luo SSH-avainpari
sudo ssh-keygen -t ed25519 -f /etc/wazuh-archiver/sftp_key -N ""
sudo chown root:wazuh-archiver /etc/wazuh-archiver/sftp_key
sudo chmod 440 /etc/wazuh-archiver/sftp_key

# Kopioi julkinen avain SFTP-palvelimelle
cat /etc/wazuh-archiver/sftp_key.pub
# → lisää tämä SFTP-palvelimen authorized_keys-tiedostoon

# Tallenna palvelimen host key
sudo ssh-keyscan -H sftp.example.com | sudo tee /etc/wazuh-archiver/known_hosts
sudo chown root:wazuh-archiver /etc/wazuh-archiver/known_hosts
sudo chmod 640 /etc/wazuh-archiver/known_hosts
```

### 5. Konfiguroi Wazuh (ossec.conf)

Katso [Wazuhin konfigurointi](#wazuhin-konfigurointi).

### 6. Testaa dry-runilla

```bash
sudo -u wazuh-archiver wazuh-archiver --dry-run
```

### 7. Käynnistä ajastin

```bash
sudo systemctl enable --now wazuh-archiver.timer
sudo systemctl list-timers wazuh-archiver.timer
```

---

## Wazuhin konfigurointi

Lisää `ossec.conf`-tiedostoon (sisältö myös `ossec-conf-snippet.xml`-tiedostossa):

```xml
<global>
  <!-- Kirjoittaa kaikki tapahtumat JSON-muodossa archives.json-tiedostoon -->
  <logall_json>yes</logall_json>

  <!-- Rotaa lokit tunneittain (oletuksena vain päivittäin) -->
  <rotate_interval>1h</rotate_interval>
</global>
```

**Docker-asennus:**

```bash
# Muokkaa ossec.conf kontin sisällä
docker exec -it single-node-wazuh.manager-1 \
  sh -c "vi /var/ossec/etc/ossec.conf"

# Käynnistä uudelleen
docker compose restart wazuh.manager
```

**Bind mount (suositeltu):**

Vaihda `docker-compose.yml`:ssä nimetty volume bind mountiksi jotta polku on
selkeä hostilla:

```yaml
services:
  wazuh.manager:
    volumes:
      - /opt/wazuh/logs:/var/ossec/logs      # bind mount
      - /opt/wazuh/etc:/var/ossec/etc        # bind mount
```

Tämän jälkeen lokit löytyvät hostilla `/opt/wazuh/logs/archives/`.

---

## Konfiguraatiotiedosto

Täysi pohja: `archiver.conf.example`

```ini
[wazuh]
log_dirs  = /opt/wazuh/logs/archives, /opt/wazuh/logs/alerts
node_name = wazuh-node1

[sftp]
host             = sftp.example.com
port             = 22
username         = wazuh-archiver
ssh_key_path     = /etc/wazuh-archiver/sftp_key
remote_dir       = /archive/wazuh
known_hosts_file = /etc/wazuh-archiver/known_hosts

[gpg]
signing              = false
signing_key_id       =
encryption           = false
encryption_recipient =
gpg_binary           = /usr/bin/gpg
gpg_homedir          = /etc/wazuh-archiver/gnupg

[archiver]
state_file = /var/lib/wazuh-archiver/state.json
audit_log  = /var/log/wazuh-archiver/audit.log
temp_dir   = /tmp/wazuh-archiver
```

---

## GPG-avainten hallinta

### Allekirjoitusavain (signing)

```bash
# Luo avaintiedosto
cat > /etc/wazuh-archiver/gpg-keygen.conf << 'EOF'
%no-protection
Key-Type: EdDSA
Key-Curve: Ed25519
Key-Usage: sign
Name-Real: Wazuh Archiver Node1
Name-Email: wazuh-archiver@your-org.fi
Expire-Date: 2y
%commit
EOF

# Generoi avain
gpg --homedir /etc/wazuh-archiver/gnupg \
    --batch --gen-key /etc/wazuh-archiver/gpg-keygen.conf

# Tarkista avain
gpg --homedir /etc/wazuh-archiver/gnupg --list-secret-keys

# Aseta signing_key_id konfiguraatioon (fingerprint tai email)
# Aseta käyttöoikeudet
chown -R wazuh-archiver:wazuh-archiver /etc/wazuh-archiver/gnupg
chmod 700 /etc/wazuh-archiver/gnupg
```

**TÄRKEÄÄ — varmuuskopio:** Vie yksityinen avain fyysiseen kassakaappiin tai HSM:ään:

```bash
gpg --homedir /etc/wazuh-archiver/gnupg \
    --export-secret-keys --armor > /turvallinen/sijainti/wazuh-signing-key.asc
```

### Salausavain (encryption)

```bash
# Tuo vastaanottajan julkinen avain
gpg --homedir /etc/wazuh-archiver/gnupg \
    --import vastaanottaja-pubkey.asc

# Aseta encryption_recipient konfiguraatioon (sormenjälki tai email)
```

### Allekirjoituksen tarkistaminen (vastaanottajan päässä)

```bash
# Tuo Wazuh-palvelimen julkinen avain
gpg --import wazuh-node1-pubkey.asc

# Tarkista paketti
gpg --verify ossec-archive-20-14.json.gz.sig ossec-archive-20-14.json.gz

# Tarkista SHA-256
sha256sum -c ossec-archive-20-14.json.gz.sha256
```

---

## SFTP-yhteys

Työkalu käyttää järjestelmän `sftp`-binääriä batch-moodissa — ei ulkoisia
Python-kirjastoja. Tämä tarkoittaa, että se toimii kaikissa ympäristöissä
joissa OpenSSH on asennettuna, myös air-gap-verkkojen palvelimilla.

**Host key -verifiointi:**

| Tilanne | Käytös |
|---------|--------|
| `known_hosts_file` määritetty | `StrictHostKeyChecking=yes` — tiukka, suositeltu |
| Ei `known_hosts_file`:ä | `StrictHostKeyChecking=accept-new` — hyväksyy uuden, hylkää muutokset |

---

## Systemd-ajastus

```
:00  Wazuh rotaa lokit → ossec-archive-DD-HH.json.gz
:05  wazuh-archiver.timer käynnistää archiver.py
:05+ Siirto SFTP-palvelimelle
```

```bash
# Tila
systemctl status wazuh-archiver.timer
systemctl status wazuh-archiver.service

# Seuraava ajokerta
systemctl list-timers wazuh-archiver.timer

# Lokit
journalctl -u wazuh-archiver.service -f

# Audit-loki
tail -f /var/log/wazuh-archiver/audit.log
```

**Manuaalinen ajo:**

```bash
sudo systemctl start wazuh-archiver.service
```

---

## Testaus

```bash
# Dry-run: listaa löydetyt tiedostot ilman siirtoa
sudo -u wazuh-archiver wazuh-archiver --dry-run

# Normaalikäynnistys
sudo -u wazuh-archiver wazuh-archiver

# Eri konfiguraatio
sudo -u wazuh-archiver wazuh-archiver --config /tmp/test.conf --dry-run
```

---

## SFTP-säilöön päätyvät tiedostot

Jokaisesta tunnin rotaatiosta syntyy seuraavat tiedostot:

```
/archive/wazuh/
  ossec-archive-20-14.json.gz          ← pakattu lokidata
  ossec-archive-20-14.json.gz.sha256   ← aina — SHA-256 tarkistussumma
  ossec-archive-20-14.json.gz.sig      ← jos signing=true — GPG-allekirjoitus
  ossec-archive-20-14.json.gz.gpg      ← jos encryption=true — salattu kopio
```

`.sha256`-tiedoston formaatti on `sha256sum`-yhteensopiva:

```
a3f2c1... ossec-archive-20-14.json.gz
```

---

## KATAKRI 2020 -vaatimusten kattavuus

| Vaatimus | Mekanismi |
|----------|-----------|
| **Eheys** (integrity) | SHA-256 manifest jokaiselle tiedostolle |
| **Kiistämättömyys** (non-repudiation) | GPG detached signature — allekirjoittaja todennettavissa |
| **Luottamuksellisuus siirron aikana** | SFTP = SSH-suojattu siirto (HMAC-SHA2) |
| **Luottamuksellisuus säilössä** | GPG-salaus vastaanottajan julkisella avaimella (optio) |
| **Lokien muuttumattomuus lähteessä** | Wazuh kirjoittaa ja rotaa itse; skripti lukee read-only |
| **Audit trail** | Jokaisesta ajosta JSON-muotoinen AUDIT_RECORD audit-lokiin |
| **Avainten hallinta** | Yksityinen avain hostilla, varmuuskopio kassakaappiin/HSM |

---

## Vianetsintä

**"No new files found"**
- Onko `logall_json=yes` ossec.conf:issa?
- Onko `rotate_interval=1h` asetettu?
- Ovatko `log_dirs`-polut oikein (host-polut, ei kontin sisäisiä)?
- Tarkista state.json: `cat /var/lib/wazuh-archiver/state.json`

**"sftp failed"**
- Testaa yhteys manuaalisesti: `sftp -i /etc/wazuh-archiver/sftp_key -P 22 user@host`
- Onko known_hosts oikein? `ssh-keyscan -H host`
- Tarkista SSH-avaimen oikeudet: `chmod 440 /etc/wazuh-archiver/sftp_key`

**"GPG command failed"**
- Onko avain olemassa? `gpg --homedir /etc/wazuh-archiver/gnupg --list-keys`
- Onko gnupg-hakemiston omistaja `wazuh-archiver`? `ls -la /etc/wazuh-archiver/`

**Audit-lokin lukeminen**

```bash
# Hae vain AUDIT_RECORD-rivit JSON-muodossa
grep AUDIT_RECORD /var/log/wazuh-archiver/audit.log \
  | sed 's/.*AUDIT_RECORD //' \
  | python3 -m json.tool
```

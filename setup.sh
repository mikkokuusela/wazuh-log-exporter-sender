#!/usr/bin/env bash
# setup.sh — Install wazuh-archiver on the Wazuh host
#
# Supports: Debian/Ubuntu, Rocky Linux 8/9, RHEL 8/9, AlmaLinux 8/9
# Run as root: sudo bash setup.sh
#
# Jokainen vaihe kysyy käyttäjältä vahvistuksen (Y/n) ennen ajamistaan.
# Lokihakemistot kysytään interaktiivisesti — ei kovakoodattua oletuspolkua.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="wazuh-archiver"
DEFAULT_LOG_DIR="/var/lib/docker/volumes/single-node_wazuh_logs/_data"
INSTALL_DIR="/usr/local/lib/wazuh-archiver"
BIN_LINK="/usr/local/bin/wazuh-archiver"
CONFIG_DIR="/etc/wazuh-archiver"
STATE_DIR="/var/lib/wazuh-archiver"
LOG_DIR="/var/log/wazuh-archiver"
TEMP_DIR="/tmp/wazuh-archiver"

# Lopputulos-seuranta yhteenvetoa varten
SUMMARY=()

# ---------------------------------------------------------------------------
# Apufunktiot
# ---------------------------------------------------------------------------

# Tulosta vaiheen otsikko
STEP_NR=0
print_step() {
    STEP_NR=$((STEP_NR + 1))
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "  VAIHE %d: %s\n" "${STEP_NR}" "$1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Pyydä käyttäjältä Y/N-vahvistus.  Palauttaa 0 = kyllä, 1 = ei.
confirm() {
    local reply
    while true; do
        printf "\n  %s [Y/n]: " "$1"
        read -r reply </dev/tty
        case "${reply,,}" in
            ''|y|yes) return 0 ;;
            n|no)     return 1 ;;
            *) echo "  Anna Y tai N." ;;
        esac
    done
}

# Pyydä käyttäjältä Y/N — oletuksena EI.
confirm_default_no() {
    local reply
    while true; do
        printf "\n  %s [y/N]: " "$1"
        read -r reply </dev/tty
        case "${reply,,}" in
            ''|n|no)  return 1 ;;
            y|yes)    return 0 ;;
            *) echo "  Anna Y tai N." ;;
        esac
    done
}

# Aseta POSIX ACL -oikeudet kohteelle sekä kaikille sen välipolun hakemistoille.
# $1 = kohdehakemisto (täysi polku), $2 = käyttäjätunnus
apply_acl_with_parents() {
    local target="$1"
    local user="$2"

    # Kerää kaikki välipolut juuren ja kohteen väliltä
    local dir="${target}"
    local parents=()
    while true; do
        dir="$(dirname "${dir}")"
        [ "${dir}" = "/" ] && break
        parents=("${dir}" ${parents[@]+"${parents[@]}"})
    done

    # Anna execute-oikeus jokaiselle välipolun hakemistolle (läpikulku)
    for parent in ${parents[@]+"${parents[@]}"}; do
        [ -d "${parent}" ] || continue
        setfacl -m "u:${user}:x" "${parent}"
        echo "    ACL x   → ${parent}"
    done

    # Anna rekursiivinen luku+execute itse kohteelle
    setfacl -R  -m "u:${user}:rX" "${target}"
    setfacl -Rd -m "u:${user}:rX" "${target}"
    echo "    ACL rX  → ${target}  (rekursiivisesti, myös uudet tiedostot)"
}

# Tulosta komennot joilla ACL asetetaan myöhemmin kun hakemisto on olemassa
print_acl_commands() {
    local target="$1"
    local user="$2"

    echo "    Komennot kun hakemisto on luotu:"
    # Laske välipolut
    local dir="${target}"
    local parents=()
    while true; do
        dir="$(dirname "${dir}")"
        [ "${dir}" = "/" ] && break
        parents=("${dir}" ${parents[@]+"${parents[@]}"})
    done
    for parent in ${parents[@]+"${parents[@]}"}; do
        echo "      setfacl -m u:${user}:x ${parent}"
    done
    echo "      setfacl -R  -m u:${user}:rX ${target}"
    echo "      setfacl -Rd -m u:${user}:rX ${target}"
}

# ---------------------------------------------------------------------------
# Tarkistukset: täytyy ajaa rootina
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "VIRHE: Aja tämä skripti root-oikeuksilla: sudo bash setup.sh" >&2
    exit 1
fi

echo ""
echo "============================================================"
echo "  wazuh-archiver — Asennusohjelma"
echo "============================================================"
echo ""
echo "  Tämä skripti asentaa wazuh-archiverin vaihe vaiheelta."
echo "  Jokainen vaihe kertoo mitä se tekee ja odottaa vahvistuksesi"
echo "  ennen kuin mitään muutoksia tehdään järjestelmään."

# ---------------------------------------------------------------------------
# AUTO: OS-tunnistus
# ---------------------------------------------------------------------------
echo ""
echo "─── Järjestelmätiedot ──────────────────────────────────────"
OS_FAMILY="unknown"
OS_NAME="unknown"
if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    OS_NAME="${PRETTY_NAME:-unknown}"
    case "${ID:-}" in
        ubuntu|debian|linuxmint|pop)  OS_FAMILY="debian" ;;
        rhel|centos|rocky|almalinux|fedora) OS_FAMILY="rhel" ;;
    esac
fi
echo "  OS:       ${OS_NAME} (family: ${OS_FAMILY})"

# Paketinhallintakomennot OS-perheen mukaan
case "${OS_FAMILY}" in
    debian)
        PKG_MANAGER="apt-get install -y"
        PKG_PYTHON="python3"
        PKG_SFTP="openssh-client"
        PKG_GPG="gnupg"
        PKG_ACL="acl"
        PKG_SELINUX=""
        ;;
    rhel)
        PKG_MANAGER="dnf install -y"
        PKG_PYTHON="python39"
        PKG_SFTP="openssh-clients"
        PKG_GPG="gnupg2"
        PKG_ACL="acl"
        PKG_SELINUX="policycoreutils-python-utils"
        ;;
    *)
        PKG_MANAGER=""
        PKG_PYTHON="python3"
        PKG_SFTP="openssh-client"
        PKG_GPG="gnupg"
        PKG_ACL="acl"
        PKG_SELINUX=""
        ;;
esac

# ---------------------------------------------------------------------------
# AUTO: Python 3.8+ -etsintä
# ---------------------------------------------------------------------------
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "${candidate}" &>/dev/null; then
        if "${candidate}" -c \
            'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
            PYTHON_BIN="$(command -v "${candidate}")"
            break
        fi
    fi
done

if [ -z "${PYTHON_BIN}" ]; then
    echo ""
    echo "  VIRHE: Python 3.8+ ei löydy."
    case "${OS_FAMILY}" in
        rhel)    echo "  Asenna: dnf install -y ${PKG_PYTHON}" ;;
        debian)  echo "  Asenna: apt-get install -y ${PKG_PYTHON}" ;;
        *)       echo "  Asenna Python 3.8 tai uudempi." ;;
    esac
    exit 1
fi
PYTHON_VER="$(${PYTHON_BIN} -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"
echo "  Python:   ${PYTHON_BIN} (${PYTHON_VER})"

# ---------------------------------------------------------------------------
# AUTO: Riippuvuustarkistus
# ---------------------------------------------------------------------------
MISSING_HARD=0

check_bin() {
    local bin="$1" pkg="$2" required="$3"
    if command -v "${bin}" &>/dev/null; then
        echo "  ${bin}:$(printf '%*s' $((10 - ${#bin})) '')OK  ($(command -v "${bin}"))"
    else
        if [ "${required}" = "required" ]; then
            echo "  ${bin}:$(printf '%*s' $((10 - ${#bin})) '')PUUTTUU — asenna: ${PKG_MANAGER} ${pkg}"
            MISSING_HARD=$((MISSING_HARD + 1))
        else
            echo "  ${bin}:$(printf '%*s' $((10 - ${#bin})) '')ei löydy (valinnainen — tarvitaan vain GPG-toiminnoille)"
            echo "            Asenna: ${PKG_MANAGER} ${pkg}"
        fi
    fi
}

check_bin sftp    "${PKG_SFTP}"  required
check_bin setfacl "${PKG_ACL}"  required
check_bin gpg     "${PKG_GPG}"  optional

if [ "${MISSING_HARD}" -gt 0 ]; then
    echo ""
    echo "  VIRHE: ${MISSING_HARD} pakollinen riippuvuus puuttuu. Aborting."
    exit 1
fi

echo "─────────────────────────────────────────────────────────────"

# ---------------------------------------------------------------------------
# VAIHE 1: Järjestelmäkäyttäjä
# ---------------------------------------------------------------------------
print_step "Luo järjestelmäkäyttäjä"
echo ""
echo "  Luo käyttäjän '${SERVICE_USER}':"
echo "    - Ei kotihakemistoa"
echo "    - Ei kirjautumismahdollisuutta (shell: /usr/sbin/nologin)"
echo "    - Järjestelmäkäyttäjä (UID alle 1000)"
echo ""
echo "  Miksi: Tietoturvasyistä skripti ajaa tiedostonsiirrot"
echo "         pienimmillä mahdollisilla oikeuksilla."
echo ""

if id "${SERVICE_USER}" &>/dev/null; then
    echo "  Käyttäjä '${SERVICE_USER}' on jo olemassa — ohitetaan."
    SUMMARY+=("[✓] Järjestelmäkäyttäjä: jo olemassa"])
else
    echo "  Komento: useradd --system --no-create-home --shell /usr/sbin/nologin ${SERVICE_USER}"
    if confirm "Luodaanko käyttäjä '${SERVICE_USER}'?"; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
        echo "  Käyttäjä '${SERVICE_USER}' luotu."
        SUMMARY+=("[✓] Järjestelmäkäyttäjä '${SERVICE_USER}' luotu")
    else
        echo "  Ohitettu — käyttäjää ei luotu."
        echo "  HUOM: Seuraavat vaiheet saattavat epäonnistua ilman tätä käyttäjää."
        SUMMARY+=("[✗] Järjestelmäkäyttäjä: ohitettu")
    fi
fi

# ---------------------------------------------------------------------------
# VAIHE 2: Asenna skripti ja käynnistyskomento
# ---------------------------------------------------------------------------
print_step "Asenna skripti ja käynnistyskomento"
echo ""
echo "  Kopioi: ${SCRIPT_DIR}/archiver.py"
echo "      →   ${INSTALL_DIR}/archiver.py"
echo ""
echo "  Luo käynnistyskomento: ${BIN_LINK}"
echo "    (kutsuu: ${PYTHON_BIN} ${INSTALL_DIR}/archiver.py)"
echo ""
echo "  Miksi: Python-binääri kovakoodataan wrapperiin jotta Rocky 8:ssa"
echo "         käytetään oikeaa versiota (python3 saattaa olla 3.6)."
echo ""

if confirm "Asennetaanko skripti?"; then
    install -d "${INSTALL_DIR}"
    install -m 755 "${SCRIPT_DIR}/archiver.py" "${INSTALL_DIR}/archiver.py"
    cat > "${BIN_LINK}" << EOF
#!/usr/bin/env bash
exec ${PYTHON_BIN} ${INSTALL_DIR}/archiver.py "\$@"
EOF
    chmod 755 "${BIN_LINK}"
    echo "  Asennettu: ${BIN_LINK}"
    SUMMARY+=("[✓] Skripti asennettu: ${BIN_LINK}")
else
    echo "  Ohitettu."
    SUMMARY+=("[✗] Skripti: ohitettu")
fi

# ---------------------------------------------------------------------------
# VAIHE 3: Luo hakemistot
# ---------------------------------------------------------------------------
print_step "Luo hakemistot"
echo ""
echo "  Seuraavat hakemistot luodaan tarvittaessa:"
echo ""
printf "  %-55s %s\n" "Polku" "Omistaja / Oikeudet"
printf "  %-55s %s\n" "─────────────────────────────────────────────────────" "────────────────────"
printf "  %-55s %s\n" "${CONFIG_DIR}/"                       "root:${SERVICE_USER}  750"
printf "  %-55s %s\n" "${CONFIG_DIR}/signing/"               "root:${SERVICE_USER}  750"
printf "  %-55s %s\n" "${CONFIG_DIR}/signing/gnupg/"         "${SERVICE_USER}  700  (GPG-avainrengas)"
printf "  %-55s %s\n" "${CONFIG_DIR}/signing/MOVE_TO_SAFE/"  "root:${SERVICE_USER}  750"
printf "  %-55s %s\n" "${CONFIG_DIR}/encryption/"            "root:${SERVICE_USER}  750"
printf "  %-55s %s\n" "${CONFIG_DIR}/encryption/gnupg/"      "${SERVICE_USER}  700  (GPG-avainrengas)"
printf "  %-55s %s\n" "${CONFIG_DIR}/encryption/MOVE_TO_SAFE/" "root:${SERVICE_USER}  750"
printf "  %-55s %s\n" "${STATE_DIR}/"                        "${SERVICE_USER}  750  (tilamuisti)"
printf "  %-55s %s\n" "${LOG_DIR}/"                          "${SERVICE_USER}  750  (auditointiloki)"
printf "  %-55s %s\n" "${TEMP_DIR}/"                         "${SERVICE_USER}  750  (väliaikaistiedostot)"
echo ""

if confirm "Luodaanko hakemistot?"; then
    install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}"
    install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}/signing"
    install -d -m 700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${CONFIG_DIR}/signing/gnupg"
    install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}/signing/MOVE_TO_SAFE"
    install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}/encryption"
    install -d -m 700 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${CONFIG_DIR}/encryption/gnupg"
    install -d -m 750 -o root              -g "${SERVICE_USER}" "${CONFIG_DIR}/encryption/MOVE_TO_SAFE"
    install -d -m 750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${STATE_DIR}"
    install -d -m 750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${LOG_DIR}"
    install -d -m 750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${TEMP_DIR}"
    echo "  Hakemistot luotu."
    SUMMARY+=("[✓] Hakemistot luotu")
else
    echo "  Ohitettu."
    SUMMARY+=("[✗] Hakemistot: ohitettu")
fi

# ---------------------------------------------------------------------------
# VAIHE 4: Konfiguraatiotiedosto
# ---------------------------------------------------------------------------
print_step "Konfiguraatiotiedosto"
echo ""
echo "  Lähde:  ${SCRIPT_DIR}/archiver.conf.example"
echo "  Kohde:  ${CONFIG_DIR}/archiver.conf"
echo ""
echo "  TÄRKEÄÄ: Tiedosto on muokattava ennen käyttöönottoa."
echo "           Vähintään seuraavat kentät täytyy täyttää:"
echo "             [sftp]   host, username, ssh_key_path, remote_dir"
echo "             [wazuh]  log_dirs (tarkista että polku täsmää)"
echo ""

if [ -f "${CONFIG_DIR}/archiver.conf" ]; then
    echo "  Tiedosto ${CONFIG_DIR}/archiver.conf on jo olemassa."
    if confirm_default_no "Ylikirjoitetaanko olemassaoleva konfiguraatio?"; then
        install -m 640 -o root -g "${SERVICE_USER}" \
            "${SCRIPT_DIR}/archiver.conf.example" "${CONFIG_DIR}/archiver.conf"
        echo "  Ylikirjoitettu: ${CONFIG_DIR}/archiver.conf"
        SUMMARY+=("[✓] Konfiguraatio ylikirjoitettu ← MUOKKAA ENNEN KÄYTTÖÄ")
    else
        echo "  Ohitettu — olemassaoleva konfiguraatio säilytetty."
        SUMMARY+=("[~] Konfiguraatio: säilytetty olemassaoleva")
    fi
else
    if confirm "Kopioidaanko konfiguraatiomalli?"; then
        install -m 640 -o root -g "${SERVICE_USER}" \
            "${SCRIPT_DIR}/archiver.conf.example" "${CONFIG_DIR}/archiver.conf"
        echo "  Luotu: ${CONFIG_DIR}/archiver.conf"
        SUMMARY+=("[✓] Konfiguraatio luotu: ${CONFIG_DIR}/archiver.conf  ← MUOKKAA ENNEN KÄYTTÖÄ")
    else
        echo "  Ohitettu."
        SUMMARY+=("[✗] Konfiguraatio: ohitettu")
    fi
fi

# ---------------------------------------------------------------------------
# VAIHE 5: POSIX ACL — luku-oikeudet lokihakemistoihin
# ---------------------------------------------------------------------------
print_step "POSIX ACL — luku-oikeudet Wazuh-lokihakemistoihin"
echo ""
echo "  Antaa '${SERVICE_USER}'-käyttäjälle luku-oikeuden Wazuh-lokihakemistoihin."
echo "  Ilman tätä skripti ei pysty lukemaan eikä siirtämään lokitiedostoja."
echo ""
echo "  Mitä ACL:t tekevät:"
echo "    x  (execute) → Jokainen välipolun hakemisto saa läpikulkuoikeuden"
echo "    rX (read+ex) → Itse lokihakemisto saa rekursiivisen lukuoikeuden"
echo "    -d (default) → Uudet tiedostot perivät oikeudet automaattisesti"
echo ""
echo "  Lokihakemisto voi olla esim.:"
echo "    /var/lib/docker/volumes/single-node_wazuh_logs/_data  (Docker named volume)"
echo "    /opt/wazuh/logs                                       (bind mount)"
echo "    /var/ossec/logs                                       (natiivi Wazuh-asennus)"
echo "    /data/wazuh/logs,/data/wazuh/alerts                   (useita, pilkulla)"
echo ""
printf "  Lokihakemistot [%s]:\n  > " "${DEFAULT_LOG_DIR}"
read -r LOG_DIRS_INPUT </dev/tty
LOG_DIRS_INPUT="${LOG_DIRS_INPUT:-${DEFAULT_LOG_DIR}}"

# Muunna pilkulla eroteltu lista taulukoksi
IFS=',' read -ra LOG_DIRS_ARRAY <<< "${LOG_DIRS_INPUT}"
# Siivoa välilyönnit
for i in "${!LOG_DIRS_ARRAY[@]}"; do
    LOG_DIRS_ARRAY[$i]="${LOG_DIRS_ARRAY[$i]# }"
    LOG_DIRS_ARRAY[$i]="${LOG_DIRS_ARRAY[$i]% }"
done

echo ""
echo "  ACL asetetaan seuraaville hakemistoille:"
for d in "${LOG_DIRS_ARRAY[@]}"; do
    if [ -d "${d}" ]; then
        echo "    ${d}  ✓ (löytyy)"
    else
        echo "    ${d}  ✗ (ei löydy — komennot tulostetaan myöhemmin)"
    fi
done

if confirm "Asetetaanko ACL-oikeudet?"; then
    ACL_DIRS_DONE=()
    ACL_DIRS_MISSING=()
    for log_dir in "${LOG_DIRS_ARRAY[@]}"; do
        echo ""
        echo "  Käsitellään: ${log_dir}"
        if [ -d "${log_dir}" ]; then
            apply_acl_with_parents "${log_dir}" "${SERVICE_USER}"
            ACL_DIRS_DONE+=("${log_dir}")
        else
            echo "  VAROITUS: Hakemistoa ei löydy — tulostetaan komennot myöhempää käyttöä varten."
            print_acl_commands "${log_dir}" "${SERVICE_USER}"
            ACL_DIRS_MISSING+=("${log_dir}")
        fi
    done

    if [ ${#ACL_DIRS_DONE[@]} -gt 0 ]; then
        SUMMARY+=("[✓] ACL asetettu: ${ACL_DIRS_DONE[*]}")
    fi
    if [ ${#ACL_DIRS_MISSING[@]} -gt 0 ]; then
        SUMMARY+=("[!] ACL puuttuu (hakemisto ei olemassa): ${ACL_DIRS_MISSING[*]}")
    fi
else
    echo "  Ohitettu — muista asettaa luku-oikeudet myöhemmin käsin."
    SUMMARY+=("[✗] ACL: ohitettu")
fi

# ---------------------------------------------------------------------------
# VAIHE 6: SELinux (vain RHEL/Rocky)
# ---------------------------------------------------------------------------
if [ "${OS_FAMILY}" = "rhel" ]; then
    print_step "SELinux-konfiguraatio (Rocky/RHEL)"
    echo ""
    echo "  Rocky/RHEL:ssa SELinux on oletuksena Enforcing."
    echo "  Dockerin kirjoittamat tiedostot saavat containerin SELinux-leiman"
    echo "  (svirt_sandbox_file_t), jota normaalit palvelut eivät voi lukea."
    echo ""
    echo "  Toimenpide:"
    echo "    semanage fcontext  → merkitsee lokihakemistot var_log_t-tyypiksi"
    echo "    restorecon -Rv     → soveltaa leiman olemassaoleviin tiedostoihin"
    echo ""
    echo "  Käytetään samoja lokihakemistoja kuin vaiheessa 5:"
    for d in "${LOG_DIRS_ARRAY[@]}"; do
        echo "    ${d}"
    done
    echo ""

    if confirm "Konfiguroidaanko SELinux?"; then
        local_se_state="$(getenforce 2>/dev/null || echo "Unknown")"
        echo "  SELinux-tila: ${local_se_state}"

        if [ "${local_se_state}" = "Disabled" ]; then
            echo "  SELinux on pois käytöstä — ei toimenpiteitä."
            SUMMARY+=("[~] SELinux: pois käytöstä, ohitettu")
        else
            if ! command -v semanage &>/dev/null; then
                echo "  Asennetaan ${PKG_SELINUX}..."
                dnf install -y -q "${PKG_SELINUX}"
            fi

            for log_dir in "${LOG_DIRS_ARRAY[@]}"; do
                fcontext_pattern="${log_dir}(/.*)?"
                if semanage fcontext -a -t var_log_t "${fcontext_pattern}" 2>/dev/null; then
                    echo "  fcontext lisätty: ${fcontext_pattern} → var_log_t"
                else
                    semanage fcontext -m -t var_log_t "${fcontext_pattern}"
                    echo "  fcontext päivitetty: ${fcontext_pattern} → var_log_t"
                fi

                if [ -d "${log_dir}" ]; then
                    restorecon -Rv "${log_dir}" | grep -c 'Relabeled' \
                        | xargs -I{} echo "  restorecon: {} tiedostoa uudelleenleimattu"
                else
                    echo "  HUOM: ${log_dir} ei löydy — aja 'restorecon -Rv ${log_dir}' Wazuhin käynnistyksen jälkeen."
                fi
            done

            echo ""
            echo "  HUOM: Jos Docker-kontti luo uusia tiedostoja myöhemmin ja"
            echo "  oikeudet puuttuvat, aja tämä auditointiohjain:"
            echo "    sudo -u ${SERVICE_USER} ${BIN_LINK} --dry-run --config ${CONFIG_DIR}/archiver.conf"
            echo "    ausearch -m avc -c python3 --raw | audit2allow -M wazuh-archiver"
            echo "    semodule -i wazuh-archiver.pp"

            SUMMARY+=("[✓] SELinux konfiguroitu")
        fi
    else
        echo "  Ohitettu."
        SUMMARY+=("[✗] SELinux: ohitettu")
    fi
fi

# ---------------------------------------------------------------------------
# VAIHE 7: GPG-avainten generointi
# ---------------------------------------------------------------------------
print_step "GPG-avainten generointi (valinnainen)"
echo ""
echo "  Generoi GPG-avaimet allekirjoitusta ja salausta varten."
echo "  Tarvitaan vain jos configissa on: signing = true tai encryption = true"
echo ""
echo "  Luotavat avaimet:"
echo "    Allekirjoitusavain (yksityinen): ${CONFIG_DIR}/signing/gnupg/"
echo "    Allekirjoitusavain (julkinen):   ${CONFIG_DIR}/signing/MOVE_TO_SAFE/pubkey.asc"
echo "       → Jaa compliance-tiimille allekirjoitusten varmistamista varten"
echo ""
echo "    Salausavain (julkinen):          ${CONFIG_DIR}/encryption/gnupg/"
echo "    Salausavain (yksityinen):        ${CONFIG_DIR}/encryption/MOVE_TO_SAFE/private-key.asc"
echo "       → SIIRRÄ TURVALLISEEN PAIKKAAN (offline, fyysinen talloite)"
echo "       → Tämä on ainoa tapa purkaa arkistoitujen tiedostojen salaus"
echo ""

if ! command -v gpg &>/dev/null; then
    echo "  gpg ei löydy — ohitetaan automaattisesti."
    echo "  Asenna gpg ja aja myöhemmin:"
    echo "    bash ${SCRIPT_DIR}/create-signing-key.sh"
    echo "    bash ${SCRIPT_DIR}/create-encryption-key.sh"
    SUMMARY+=("[✗] GPG-avaimet: gpg ei asennettu")
else
    if confirm "Generoidaanko GPG-avaimet?"; then
        # Allekirjoitusavain
        if gpg --homedir "${CONFIG_DIR}/signing/gnupg" --list-secret-keys 2>/dev/null \
                | grep -q "^sec"; then
            echo "  Allekirjoitusavain on jo olemassa — ohitetaan."
        else
            echo "  Generoidaan allekirjoitusavain..."
            bash "${SCRIPT_DIR}/create-signing-key.sh"
        fi

        # Salausavain
        if gpg --homedir "${CONFIG_DIR}/encryption/gnupg" --list-keys 2>/dev/null \
                | grep -q "wazuh-archiver-enc"; then
            echo "  Salausavain on jo olemassa — ohitetaan."
        else
            echo "  Generoidaan salausavainpari..."
            bash "${SCRIPT_DIR}/create-encryption-key.sh"
        fi

        SUMMARY+=("[✓] GPG-avaimet generoitu")
    else
        echo "  Ohitettu — aja tarvittaessa myöhemmin:"
        echo "    bash ${SCRIPT_DIR}/create-signing-key.sh"
        echo "    bash ${SCRIPT_DIR}/create-encryption-key.sh"
        SUMMARY+=("[✗] GPG-avaimet: ohitettu")
    fi
fi

# ---------------------------------------------------------------------------
# VAIHE 8: Systemd-yksiköt
# ---------------------------------------------------------------------------
print_step "Asenna systemd-yksiköt"
echo ""
echo "  Kopioitavat tiedostot:"
echo "    ${SCRIPT_DIR}/systemd/wazuh-archiver.service → /etc/systemd/system/"
echo "    ${SCRIPT_DIR}/systemd/wazuh-archiver.timer   → /etc/systemd/system/"
echo ""
echo "  Ajaa sen jälkeen: systemctl daemon-reload"
echo ""
echo "  HUOM: Timer EI aktivoidu automaattisesti."
echo "        Ota käyttöön manuaalisesti kun konfiguraatio on valmis:"
echo "          systemctl enable --now wazuh-archiver.timer"
echo ""

if confirm "Asennetaanko systemd-yksiköt?"; then
    install -m 644 "${SCRIPT_DIR}/systemd/wazuh-archiver.service" \
        /etc/systemd/system/wazuh-archiver.service
    install -m 644 "${SCRIPT_DIR}/systemd/wazuh-archiver.timer" \
        /etc/systemd/system/wazuh-archiver.timer
    systemctl daemon-reload
    echo "  Systemd-yksiköt asennettu (ei vielä aktivoitu)."
    SUMMARY+=("[✓] Systemd-yksiköt asennettu (timer ei aktivoitu)")
else
    echo "  Ohitettu."
    SUMMARY+=("[✗] Systemd-yksiköt: ohitettu")
fi

# ---------------------------------------------------------------------------
# Yhteenveto ja seuraavat vaiheet
# ---------------------------------------------------------------------------
echo ""
echo ""
echo "============================================================"
echo "  Asennusyhteenveto"
echo "============================================================"
echo ""
for line in "${SUMMARY[@]}"; do
    echo "  ${line}"
done

echo ""
echo "============================================================"
echo "  Seuraavat vaiheet"
echo "============================================================"
echo ""
echo "1) Muokkaa konfiguraatiotiedostoa:"
echo "     nano ${CONFIG_DIR}/archiver.conf"
echo ""
echo "   Täytä vähintään:"
echo "     [wazuh]  log_dirs   — Wazuh-lokihakemiston polku"
echo "     [sftp]   host       — SFTP-palvelimen osoite"
echo "     [sftp]   username   — SFTP-käyttäjätunnus"
echo "     [sftp]   ssh_key_path"
echo "     [sftp]   remote_dir"
echo ""
echo "2) Luo SSH-avainpari SFTP-yhteyttä varten:"
echo "     ssh-keygen -t ed25519 -f ${CONFIG_DIR}/sftp_key -N \"\""
echo "     chown root:${SERVICE_USER} ${CONFIG_DIR}/sftp_key"
echo "     chmod 440 ${CONFIG_DIR}/sftp_key"
echo "     cat ${CONFIG_DIR}/sftp_key.pub   # kopioi SFTP-palvelimelle"
echo ""
echo "3) Tallenna SFTP-palvelimen host key:"
echo "     ssh-keyscan -H sftp.example.com | tee ${CONFIG_DIR}/known_hosts"
echo "     chown root:${SERVICE_USER} ${CONFIG_DIR}/known_hosts"
echo "     chmod 640 ${CONFIG_DIR}/known_hosts"
echo ""
echo "4) GPG-avainten sijainti (jos generoitiin):"
echo "     Allekirjoituksen julkinen avain: ${CONFIG_DIR}/signing/MOVE_TO_SAFE/pubkey.asc"
echo "     Salauksen yksityinen avain:      ${CONFIG_DIR}/encryption/MOVE_TO_SAFE/private-key.asc"
echo "     → SIIRRÄ YKSITYINEN AVAIN TURVALLISEEN PAIKKAAN"
echo ""
echo "5) Lisää ossec.conf-asetukset (katso ossec-conf-snippet.xml):"
echo "     docker exec -it single-node-wazuh.manager-1 vi /var/ossec/etc/ossec.conf"
echo "     docker compose restart wazuh.manager"
echo ""
echo "6) Testaa dry-runilla:"
echo "     sudo -u ${SERVICE_USER} ${BIN_LINK} --dry-run --config ${CONFIG_DIR}/archiver.conf"
echo ""
echo "7) Aktivoi timer:"
echo "     systemctl enable --now wazuh-archiver.timer"
echo "     systemctl list-timers wazuh-archiver.timer"
echo ""

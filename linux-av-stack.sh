#!/bin/bash

# Good luck! ~ LEXORA Cybersecutity & Development ~

# Use the following code to set the variables in the parent shell:
# export MAILGUN_SMTP_USER=[mailgun email address]
# export MAILGUN_SMTP_PASS=[mailgun smtp password]
# export ALERT_EMAIL=[mailgun email address]
# export SCAN_HOUR=[0-23]

function IS_VALID_EMAIL() {
    local email="$1"
    local local_part="${email%@*}"
    local domain_part="${email#*@}"
    if [[ "$email" != "$local_part@$domain_part" ]]; then return 1; fi # Check if the email is in the format local-part@domain
    if (( ${#local_part} > 64 )); then return 1; fi # Check if the local part is up to 64 octets long
    if (( ${#domain_part} > 255 )); then return 1; fi # Check if the domain part is up to 255 octets long
    if [[ ! "$local_part" =~ ^[a-zA-Z0-9\!\#$%\&\*+-/=?^_\`{|}~.]+$ ]]; then return 1; fi
#    if [[ ! "$local_part" =~ ^[a-zA-Z0-9!#$%&\'*+-/=?^_`{|}~.]+$ ]]; then return 1; fi
#    if [[ ! "$local_part" =~ ^[a-zA-Z0-9!#$%&\'*+-/=?^_`{|}~.]+$ ]]; then return 1; fi # Check if the local part contains only allowed characters
    if [[ "$local_part" == .* || "$local_part" == *. || "$local_part" == *..* ]]; then return 1; fi # Check if the local part starts or ends with a dot, or contains two consecutive dots
    if ! IS_VALID_DOMAIN "$domain_part" && ! IS_BRACKETED_IP_ADDRESS "$domain_part"; then return 1; fi # Check if the domain part is a valid domain name or IP address enclosed in brackets
    return 0
}
function IS_VALID_KEY() { # >4 characters and no spaces:
    if [[ ${#1} -lt 5 ]] || [[ $1 =~ [[:space:]] ]]; then return 1; fi
    return 0
}
function IS_VALID_DOMAIN() {
    if [[ -z "$1" ]]; then return 1; fi # Check if the domain is empty
    if [[ ! "$1" =~ ^[a-zA-Z0-9.-]+$ ]]; then return 1; fi # Check if the domain contains only allowed characters
    if [[ "$1" == -* || "$1" == *. || "$1" == *- ]]; then return 1; fi # Check if the domain starts or ends with a hyphen or dot
    if [[ "$1" == *..* ]]; then return 1; fi # Check if the domain contains two consecutive dots
    if [[ ! "$1" =~ .*\..* ]]; then return 1; fi # Check if the domain has at least two labels separated by a dot
    return 0 # it's valid (0 is "true" in bash)
}
function IS_IPV6_ADDRESS() {
    if [[ "$1" =~ ^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,4}){1,5}|:((:[0-9a-fA-F]{1,4}){1,6})|::[fF]{4}(:0{1,3}){1,3}|([0-9a-fA-F]{1,4}:){1,5}:[fF]{4}(:[0-9a-fA-F]{2}){2}|::[fF]{4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:[fF]{4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])))$ ]]; then return 0; fi
    return 1
}
function IS_IPV4_ADDRESS() {
    if [[ "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then return 0; fi
    return 1
}
function IS_BRACKETED_IP_ADDRESS() {
    if [[ "$1" =~ ^\[.*\]$ ]]; then {
        local ip=${1:1:-1}
        if IS_IPV4_ADDRESS "$ip" || IS_IPV6_ADDRESS "$ip"; then return 0; fi
        return 1
    } fi
    return 1
}

# Get the hostname of the machine or the public hostname from ec2metadata
PUBLIC_HOSTNAME=$(timeout 2 ec2metadata --public-hostname 2> /dev/null)
if [ -z "$PUBLIC_HOSTNAME" ]; then # fallback to nslookup and hostname
    PUBLIC_HOSTNAME=$(nslookup "$(hostname -I | awk '{print $1}')" | awk '/name/{print $NF}' | sed 's/\.$//')
fi
# Fallback if still empty; sanitize for safe use in generated script (no injection)
if [ -z "$PUBLIC_HOSTNAME" ]; then
    PUBLIC_HOSTNAME=$(hostname 2>/dev/null) || PUBLIC_HOSTNAME="unknown-host"
fi
if [[ ! "$PUBLIC_HOSTNAME" =~ ^[a-zA-Z0-9._-]+$ ]]; then
    PUBLIC_HOSTNAME="unknown-host"
fi

if ! command -v wget &> /dev/null; then sudo apt-get update && sudo apt install -y wget; fi # required for rkhunter updates

# Prompt for the email address where alerts will be sent
# while read -p "Enter the email address where alerts will be sent (default $ALERT_EMAIL): " -r ALERT_EMAIL && ! IS_VALID_EMAIL "$ALERT_EMAIL"; do
while read -p "Enter the email address where alerts will be sent (default $ALERT_EMAIL): " input && ALERT_EMAIL=${input:-$ALERT_EMAIL} && ! IS_VALID_EMAIL "$ALERT_EMAIL"; do
    echo "Invalid email address ($ALERT_EMAIL), please try again"
done

# Prompt for the full mailgun address used for SMTP authentication
while read -p "Enter your full mailgun address used for SMTP authentication (default $MAILGUN_SMTP_USER): " input && MAILGUN_SMTP_USER=${input:-$MAILGUN_SMTP_USER} && ! IS_VALID_EMAIL "$MAILGUN_SMTP_USER"; do
    echo "Invalid email address ($MAILGUN_SMTP_USER), please try again"
done

# Prompt for the Mailgun API key
while read -p "Enter your Mailgun SMTP Password (default $MAILGUN_SMTP_PASS): " input && MAILGUN_SMTP_PASS=${input:-$MAILGUN_SMTP_PASS} && ! IS_VALID_KEY "$MAILGUN_SMTP_PASS"; do
    echo "Invalid MailGun SMTP Password ($MAILGUN_SMTP_PASS), please try again"
done

# Prompt for the time of day (hour only) when the scans should be run in US Eastern time
# Validate that SCAN_HOUR is a number between 0 and 23
while read -p "Enter the time of day (hour only) when the scans should be run in US Eastern time: " input && SCAN_HOUR=${input:-$SCAN_HOUR} && { ! [[ "$SCAN_HOUR" =~ ^[0-9]+$ ]] || [ "$SCAN_HOUR" -lt 0 ] || [ "$SCAN_HOUR" -gt 23 ]; }; do
  echo "Invalid input. Please enter a number between 0 and 23."
done

# Update the system
sudo apt update && sudo apt upgrade -y

# Install Postfix
sudo debconf-set-selections <<< "postfix postfix/mailname string ${PUBLIC_HOSTNAME}"
sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
sudo apt install postfix -y

# Configure Postfix to use Mailgun as SMTP relay
sudo postconf -e 'relayhost = [smtp.mailgun.org]:587'
sudo postconf -e 'smtp_sasl_auth_enable = yes'
sudo postconf -e 'smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd'
sudo postconf -e 'smtp_sasl_security_options = noanonymous'
sudo postconf -e 'smtp_tls_security_level = encrypt'
sudo postconf -e 'header_size_limit = 4096000'

# Create the file /etc/postfix/sasl_passwd with your Mailgun credentials
echo "[smtp.mailgun.org]:587    $MAILGUN_SMTP_USER:$MAILGUN_SMTP_PASS" | sudo tee /etc/postfix/sasl_passwd

# Set the file permissions and create the hash db file
sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd

# Restart Postfix
sudo systemctl restart postfix

# Install ClamAV
sudo apt install -y clamav clamav-daemon clamtk

# Update ClamAV signature database
sudo freshclam

# Install chkrootkit & rkhunter
sudo apt install -y chkrootkit rkhunter

# Update rkhunter database and configuration
sudo bash -c 'cat > /var/lib/rkhunter/mirrors.dat << EOL
Version:2007060601
mirror=http://rkhunter.sourceforge.net
mirror=http://rkhunter.sourceforge.net
EOL'
sudo sed -i 's/UPDATE_MIRRORS=1/UPDATE_MIRRORS=0/' /etc/rkhunter.conf # Set UPDATE_MIRRORS = 0 in rkhunter.conf to prevent updating the mirrors list (security - this will keep just rkhunter.sourceforge.net as the mirror)
sudo sed -i "s|^WEB_CMD=.*|WEB_CMD=wget|" /etc/rkhunter.conf
sudo sed -i "s|^MIRRORS_MODE=.*|MIRRORS_MODE=0|" /etc/rkhunter.conf
sudo rkhunter --update
sudo rkhunter --propupd

# Install LMD
cd /tmp  || { echo "Directory not found /tmp"; exit 1; }
wget http://www.rfxn.com/downloads/maldetect-current.tar.gz
tar -xzf maldetect-current.tar.gz
dir=$(tar -tzf maldetect-current.tar.gz | head -1 | cut -f1 -d"/")
cd "$dir" || { echo "Directory not found $dir"; exit 1; }
sudo ./install.sh

# Configure LMD to use ClamAV as scan engine and enable email alerts and quarantine options
sudo sed -i 's/scan_clamscan="0"/scan_clamscan="1"/' /usr/local/maldetect/conf.maldet
sudo sed -i 's/email_alert="0"/email_alert="1"/' /usr/local/maldetect/conf.maldet
# Escape ALERT_EMAIL for sed replacement (& and \ are special)
ALERT_EMAIL_SED="${ALERT_EMAIL//\\/\\\\}"
ALERT_EMAIL_SED="${ALERT_EMAIL_SED//&/\\&}"
sudo sed -i "s/email_addr=\".*\"/email_addr=\"$ALERT_EMAIL_SED\"/" /usr/local/maldetect/conf.maldet
sudo sed -i 's/quarantine_hits="0"/quarantine_hits="1"/' /usr/local/maldetect/conf.maldet
sudo sed -i 's/quarantine_clean="0"/quarantine_clean="1"/' /usr/local/maldetect/conf.maldet

# Create the scan_jobs.sh file; RECIPIENT and HOSTNAME_DISPLAY set safely (no injection)
RECIPIENT_LINE="RECIPIENT='${ALERT_EMAIL//\'/\'\\\'\'}'"
HOSTNAME_LINE="HOSTNAME_DISPLAY='$PUBLIC_HOSTNAME'"
cat <<EOF | sudo tee /usr/local/bin/scan_jobs.sh
#!/bin/bash
$RECIPIENT_LINE
$HOSTNAME_LINE

# freshclam not needed because should be running daemon.
/usr/bin/clamscan -r --bell -i / > /tmp/clamav_scan_temp.log
cat /tmp/clamav_scan_temp.log >> /var/log/clamav_scan.log
if grep -q FOUND /tmp/clamav_scan_temp.log; then
  mail -s "ClamAV Scan Report for \$HOSTNAME_DISPLAY" "\$RECIPIENT" < /tmp/clamav_scan_temp.log
fi

DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y --only-upgrade chkrootkit
/usr/sbin/chkrootkit > /tmp/chkrootkit_scan_temp.log
cat /tmp/chkrootkit_scan_temp.log >> /var/log/chkrootkit_scan.log
if grep -q INFECTED /tmp/chkrootkit_scan_temp.log; then
  mail -s "chkrootkit Scan Report for \$HOSTNAME_DISPLAY" "\$RECIPIENT" < /tmp/chkrootkit_scan_temp.log
fi

/usr/bin/rkhunter --update
/usr/bin/rkhunter --cronjob --report-warnings-only > /tmp/rkhunter_scan_temp.log
cat /tmp/rkhunter_scan_temp.log >> /var/log/rkhunter_scan.log
if grep -q Warning /tmp/rkhunter_scan_temp.log; then
  mail -s "rkhunter Scan Report for \$HOSTNAME_DISPLAY" "\$RECIPIENT" < /tmp/rkhunter_scan_temp.log
fi

/usr/local/maldetect/maldet -u
/usr/local/maldetect/maldet -a / > /tmp/lmd_scan_temp.log
cat /tmp/lmd_scan_temp.log >> /var/log/lmd_scan.log
if grep -q '{scan,hit}:' /tmp/lmd_scan_temp.log; then
  mail -s "LMD Scan Report for \$HOSTNAME_DISPLAY" "\$RECIPIENT" < /tmp/lmd_scan_temp.log
fi
EOF

# Make the file executable
sudo chmod +x /usr/local/bin/scan_jobs.sh

# Create the cron job
echo "0 $SCAN_HOUR * * * root /usr/local/bin/scan_jobs.sh" | sudo tee /etc/cron.d/scan_jobs


# Good luck! ~ LEXORA Cybersecutity & Development ~

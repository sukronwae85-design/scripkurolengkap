#!/bin/bash

# =================================================================
# AUTO INSTALL SCRIPT VPS MANAGER - ULTIMATE COMPLETE EDITION
# Version: 12.0 - ALL MODULES COMPLETE
# Author: Sukron Wae
# GitHub: https://github.com/sukronwae85-design/scripkurolengkap
# =================================================================

# ===================== KONFIGURASI =====================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; NC='\033[0m'

# ===================== VARIABEL =====================
SCRIPT_DIR="/root/vps-manager"
CONFIG_DIR="$SCRIPT_DIR/config"
LOG_DIR="$SCRIPT_DIR/logs"
MODULE_DIR="$SCRIPT_DIR/modules"
BACKUP_DIR="/root/backup"
THEME_DIR="$SCRIPT_DIR/themes"
BANNER_DIR="$SCRIPT_DIR/banners"

# Database files
USER_DB="$CONFIG_DIR/users/user.db"
BANDWIDTH_DB="$CONFIG_DIR/users/bandwidth.db"
UDP_DB="$CONFIG_DIR/udp/accounts.db"
V2RAY_DB="$CONFIG_DIR/v2ray/accounts.db"
CONFIG_FILE="$CONFIG_DIR/vps_manager.conf"
LOG_FILE="$LOG_DIR/install.log"
SSH_BANNER_FILE="/etc/banner.txt"

# Port Configuration
SSH_PORT=22
SSH_PORT_80=80
SSH_PORT_443=443
SSH_GAME_PORT=7200
SSH_WA_PORT=7300
SSH_UDP_PORT=7100

# V2Ray Ports
V2RAY_WS_PORT=80      # WebSocket
V2RAY_TLS_PORT=443    # TLS/SSL
V2RAY_VMESS_PORT=8443 # VMESS Backup
V2RAY_VLESS_PORT=2083 # VLESS
TROJAN_PORT=2053      # Trojan

# System
PUBLIC_IP=$(curl -s ifconfig.me)
DOMAIN=""
EMAIL_ADMIN="admin@vps.com"
MAX_IP_PER_USER=2
DEFAULT_BANDWIDTH_GB=5
DEFAULT_EXPIRED_DAYS=30
TRIAL_EXPIRED_DAYS=1

# ===================== FUNGSI UTAMA INSTALL =====================

main_installation() {
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║   VPS MANAGER v12.0 - COMPLETE ALL MODULES              ║
║   SSH + V2Ray + UDP Custom + All Management Modules     ║
╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${CYAN}Starting complete installation...${NC}"
    
    # Step 1-3: Basic Setup
    check_root
    check_os
    check_internet
    
    # Step 4-6: System Setup
    create_directory_structure
    install_dependencies
    setup_timezone
    
    # Step 7-10: Service Setup
    setup_ssh_complete
    setup_udp_custom
    setup_xray_complete
    setup_nginx_complete
    
    # Step 11-13: Security & Database
    setup_firewall_complete
    setup_database_complete
    setup_cron_jobs
    
    # Step 14-16: Modules & Menu
    create_all_modules_complete
    create_main_menu_complete
    setup_backup_system
    
    # Step 17-18: Final
    final_configuration
    display_completion_message
}

# ===================== FUNGSI DASAR =====================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}✗ Error: Script must be run as root!${NC}"
        echo -e "${YELLOW}Use: sudo bash $0${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Root check passed${NC}"
}

check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        echo -e "${RED}✗ Cannot detect OS${NC}"
        exit 1
    fi
    
    case $OS in
        ubuntu)
            if [[ $VER == "18.04" || $VER == "20.04" || $VER == "22.04" || $VER == "24.04" ]]; then
                echo -e "${GREEN}✓ OS Supported: Ubuntu $VER${NC}"
            else
                echo -e "${YELLOW}⚠ OS Version $VER might need adjustments${NC}"
            fi
            ;;
        debian)
            if [[ $VER == "10" || $VER == "11" || $VER == "12" ]]; then
                echo -e "${GREEN}✓ OS Supported: Debian $VER${NC}"
            else
                echo -e "${YELLOW}⚠ OS Version $VER might need adjustments${NC}"
            fi
            ;;
        *)
            echo -e "${RED}✗ Unsupported OS: $OS${NC}"
            exit 1
            ;;
    esac
}

check_internet() {
    if ping -c 1 google.com &> /dev/null; then
        echo -e "${GREEN}✓ Internet connection OK${NC}"
    else
        echo -e "${RED}✗ No internet connection${NC}"
        exit 1
    fi
}

# ===================== SETUP DIRECTORY =====================

create_directory_structure() {
    echo -e "${CYAN}Creating directory structure...${NC}"
    
    mkdir -p $SCRIPT_DIR
    mkdir -p $CONFIG_DIR/{users,v2ray,trojan,udp,backup}
    mkdir -p $LOG_DIR
    mkdir -p $MODULE_DIR
    mkdir -p $THEME_DIR/{default,dark,colorful}
    mkdir -p $BANNER_DIR/{default,custom}
    mkdir -p $BACKUP_DIR/{daily,weekly,monthly}
    
    echo -e "${GREEN}✓ Directory structure created${NC}"
}

# ===================== INSTALL DEPENDENCIES =====================

install_dependencies() {
    echo -e "${CYAN}Installing dependencies...${NC}"
    
    apt update -y && apt upgrade -y
    
    # Basic tools
    apt install -y curl wget git nano htop net-tools ufw fail2ban cron \
    screen tmux zip unzip bc jq dos2unix
    
    # Monitoring
    apt install -y speedtest-cli iftop nload vnstat bmon slurm \
    tcptrack iptraf-ng netcat
    
    # Network
    apt install -y iptables iptables-persistent netfilter-persistent \
    resolvconf dnsutils whois socat udptunnel
    
    # Web & SSL
    apt install -y nginx certbot python3-certbot-nginx apache2-utils
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# ===================== SETUP TIMEZONE =====================

setup_timezone() {
    timedatectl set-timezone Asia/Jakarta
    echo -e "${GREEN}✓ Timezone set to Asia/Jakarta${NC}"
    echo -e "${CYAN}Current time: $(date)${NC}"
}

# ===================== SETUP SSH COMPLETE =====================

setup_ssh_complete() {
    echo -e "${CYAN}Setting up SSH Complete...${NC}"
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Create SSH banner dengan warning
    cat > "$SSH_BANNER_FILE" << EOF
╔══════════════════════════════════════════════════════════╗
║               🚀 VPN SERVER - SSH ACCESS 🚀             ║
╠══════════════════════════════════════════════════════════╣
║ Server: $(hostname)                                     ║
║ IP: $PUBLIC_IP                                          ║
║ Date: $(date '+%Y-%m-%d %H:%M:%S')                      ║
║ Timezone: Asia/Jakarta (GMT+7)                          ║
╠══════════════════════════════════════════════════════════╣
║                    OPEN PORTS                           ║
║ • SSH: 22, 80, 443, 7200, 7300                         ║
║ • UDP Custom: 7100 + Range 50000-60000                 ║
║ • V2Ray WS: 80 | V2Ray TLS: 443                        ║
║ • VMESS: 8443 | VLESS: 2083 | Trojan: 2053             ║
╠══════════════════════════════════════════════════════════╣
║                 ⚠️  STRICT POLICY ⚠️                    ║
║   NO ILLEGAL ACTIVITIES • NO HACKING • NO SPAMMING     ║
║   NO TORRENT • NO MULTI-LOGIN (Max 2 IP)               ║
║   NO ACCOUNT SHARING • NO CARDING                      ║
╠══════════════════════════════════════════════════════════╣
║   🚫 VIOLATION = PERMANENT BAN + IP BLOCKLIST 🚫       ║
╚══════════════════════════════════════════════════════════╝
EOF
    
    # Configure SSH untuk semua port
    cat > /etc/ssh/sshd_config << EOF
# SSH Complete Configuration
Port $SSH_PORT
Port $SSH_PORT_80
Port $SSH_PORT_443
Port $SSH_GAME_PORT
Port $SSH_WA_PORT

# Security Settings
Protocol 2
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Performance
X11Forwarding yes
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
ClientAliveInterval 300
ClientAliveCountMax 2

# Banner
Banner $SSH_BANNER_FILE

# Other Settings
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 60
AllowTcpForwarding yes
GatewayPorts yes
AllowAgentForwarding yes
Compression delayed
ClientAliveCountMax 2
EOF
    
    # Restart SSH service
    systemctl restart ssh
    systemctl enable ssh
    
    echo -e "${GREEN}✓ SSH Complete configured${NC}"
    echo -e "${BLUE}Ports: 22, 80, 443, 7200, 7300${NC}"
}

# ===================== SETUP UDP CUSTOM =====================

setup_udp_custom() {
    echo -e "${CYAN}Setting up UDP Custom Support...${NC}"
    
    # Install UDP tools
    apt install -y udptunnel socat
    
    # Create UDP tunnel manager
    cat > /usr/local/bin/udp-manager << 'EOF'
#!/bin/bash
case "$1" in
    start)
        PORT=${2:-7100}
        socat UDP4-LISTEN:$PORT,fork TCP4:127.0.0.1:22 &
        echo $! > /var/run/udp-$PORT.pid
        echo "UDP tunnel started on port $PORT"
        ;;
    start-range)
        START=${2:-50000}
        END=${3:-60000}
        for port in $(seq $START $END); do
            socat UDP4-LISTEN:$port,fork TCP4:127.0.0.1:22 &
            echo $! > /var/run/udp-$port.pid
        done
        echo "Started UDP tunnels from $START to $END"
        ;;
    stop)
        pkill -f "socat.*UDP4-LISTEN"
        rm -f /var/run/udp-*.pid
        echo "All UDP tunnels stopped"
        ;;
    status)
        ps aux | grep -E "socat.*UDP4-LISTEN" | grep -v grep
        ;;
    *)
        echo "Usage: $0 {start PORT|start-range START END|stop|status}"
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/udp-manager
    
    # Start UDP tunnels
    /usr/local/bin/udp-manager start 7100
    /usr/local/bin/udp-manager start-range 50000 60000
    
    echo -e "${GREEN}✓ UDP Custom configured${NC}"
    echo -e "${BLUE}UDP Ports: 7100 + 50000-60000 range${NC}"
}

# ===================== SETUP XRAY COMPLETE =====================

setup_xray_complete() {
    echo -e "${CYAN}Installing XRay Complete...${NC}"
    
    # Install XRay
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Generate UUIDs
    UUID_VMESS=$(cat /proc/sys/kernel/random/uuid)
    UUID_VLESS=$(cat /proc/sys/kernel/random/uuid)
    TROJAN_PASSWORD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
    
    # Create XRay config
    cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": $V2RAY_WS_PORT,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VMESS",
            "alterId": 0,
            "email": "user@vps.com",
            "level": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess",
          "headers": {
            "Host": "\$domain"
          }
        },
        "security": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "tag": "vmess-ws"
    },
    {
      "port": $V2RAY_TLS_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VLESS",
            "email": "user@vps.com",
            "level": 0,
            "flow": "xtls-rprx-direct"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/certs/ssl-cert-snakeoil.pem",
              "keyFile": "/etc/ssl/private/ssl-cert-snakeoil.key"
            }
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      },
      "tag": "vless-tls"
    },
    {
      "port": $TROJAN_PORT,
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "$TROJAN_PASSWORD",
            "email": "user@vps.com",
            "level": 0
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/ssl/certs/ssl-cert-snakeoil.pem",
              "keyFile": "/etc/ssl/private/ssl-cert-snakeoil.key"
            }
          ]
        }
      },
      "tag": "trojan"
    },
    {
      "port": $V2RAY_VMESS_PORT,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      },
      "tag": "vmess-backup"
    },
    {
      "port": $V2RAY_VLESS_PORT,
      "protocol": "vless",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none"
      },
      "tag": "vless-backup"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF
    
    # Create XRay service
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable xray
    systemctl start xray
    
    echo -e "${GREEN}✓ XRay Complete installed${NC}"
    echo -e "${BLUE}VMESS WS: port $V2RAY_WS_PORT${NC}"
    echo -e "${BLUE}VLESS TLS: port $V2RAY_TLS_PORT${NC}"
    echo -e "${BLUE}Trojan: port $TROJAN_PORT${NC}"
}

# ===================== SETUP NGINX COMPLETE =====================

setup_nginx_complete() {
    echo -e "${CYAN}Setting up Nginx Complete...${NC}"
    
    # Stop Apache if exists
    systemctl stop apache2 2>/dev/null
    systemctl disable apache2 2>/dev/null
    
    # Create Nginx config
    cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 1024;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml+rss text/javascript;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    # Create V2Ray site configuration
    cat > /etc/nginx/sites-available/v2ray << EOF
server {
    listen 80;
    listen [::]:80;
    server_name _;
    
    # VMESS WebSocket Path
    location /vmess {
        proxy_pass http://127.0.0.1:$V2RAY_WS_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Web Interface
    location / {
        root /var/www/html;
        index index.html index.htm;
    }
    
    # Status page
    location /status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }
    
    # Nginx info
    location /nginx-info {
        access_log off;
        return 200 "Nginx is working with V2Ray proxy\\n";
    }
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/v2ray /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Create web directory
    mkdir -p /var/www/html
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>VPS Manager Server</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        h1 { color: #333; }
        .status { color: green; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
    </style>
</head>
<body>
    <h1>🚀 VPS Manager Server</h1>
    <p class="status">✅ Server is running properly</p>
    <p>Server Time: <span id="time"></span></p>
    <p class="warning">⚠️ Authorized Access Only</p>
    <script>document.getElementById('time').textContent = new Date().toLocaleString();</script>
</body>
</html>
EOF
    
    # Test and restart Nginx
    nginx -t
    systemctl restart nginx
    systemctl enable nginx
    
    echo -e "${GREEN}✓ Nginx Complete configured${NC}"
}

# ===================== SETUP FIREWALL COMPLETE =====================

setup_firewall_complete() {
    echo -e "${CYAN}Setting up Firewall Complete...${NC}"
    
    # Reset firewall
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH ports
    ufw allow $SSH_PORT/tcp comment 'SSH Default'
    ufw allow $SSH_PORT_80/tcp comment 'SSH Port 80'
    ufw allow $SSH_PORT_443/tcp comment 'SSH Port 443'
    ufw allow $SSH_GAME_PORT/tcp comment 'SSH Game Port'
    ufw allow $SSH_WA_PORT/tcp comment 'SSH WhatsApp Port'
    
    # Allow UDP ports
    ufw allow $SSH_UDP_PORT/udp comment 'UDP Base Port'
    ufw allow 50000:60000/udp comment 'UDP Custom Range'
    
    # Allow V2Ray ports
    ufw allow $V2RAY_WS_PORT/tcp comment 'V2Ray WebSocket'
    ufw allow $V2RAY_TLS_PORT/tcp comment 'V2Ray TLS/SSL'
    ufw allow $V2RAY_VMESS_PORT/tcp comment 'VMESS Backup'
    ufw allow $V2RAY_VLESS_PORT/tcp comment 'VLESS'
    ufw allow $TROJAN_PORT/tcp comment 'Trojan'
    
    # Allow Nginx
    ufw allow 'Nginx Full' comment 'Nginx HTTP/HTTPS'
    
    # Enable firewall
    ufw --force enable
    
    # Enable IP forwarding
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    
    echo -e "${GREEN}✓ Firewall Complete configured${NC}"
}

# ===================== SETUP DATABASE COMPLETE =====================

setup_database_complete() {
    echo -e "${CYAN}Setting up databases...${NC}"
    
    # Create main user database
    cat > "$USER_DB" << EOF
# VPS Manager User Database
# Format: username|password|expire_date|limit_ip|bandwidth_limit|status|created|last_login|udp_port|v2ray_uuid
# Status: active, expired, locked, trial
EOF
    
    # Create bandwidth database
    cat > "$BANDWIDTH_DB" << EOF
# Bandwidth Usage Database
# Format: username|used_mb|total_mb|last_reset|daily_used|monthly_used
EOF
    
    # Create UDP accounts database
    cat > "$UDP_DB" << EOF
# UDP Custom Accounts Database
# Format: username|password|udp_port|expire_date|limit_ip|status|created|notes
EOF
    
    # Create V2Ray accounts database
    cat > "$V2RAY_DB" << EOF
# V2Ray Accounts Database
# Format: username|protocol|uuid|port|path|security|expire_date|status
EOF
    
    # Create configuration file
    cat > "$CONFIG_FILE" << EOF
# VPS Manager Configuration File
PUBLIC_IP=$PUBLIC_IP
DOMAIN=$DOMAIN
EMAIL=$EMAIL_ADMIN

# SSH Ports
SSH_PORT=$SSH_PORT
SSH_PORT_80=$SSH_PORT_80
SSH_PORT_443=$SSH_PORT_443
SSH_GAME_PORT=$SSH_GAME_PORT
SSH_WA_PORT=$SSH_WA_PORT
SSH_UDP_PORT=$SSH_UDP_PORT

# V2Ray Ports
V2RAY_WS_PORT=$V2RAY_WS_PORT
V2RAY_TLS_PORT=$V2RAY_TLS_PORT
V2RAY_VMESS_PORT=$V2RAY_VMESS_PORT
V2RAY_VLESS_PORT=$V2RAY_VLESS_PORT
TROJAN_PORT=$TROJAN_PORT

# Limits
MAX_IP_PER_USER=$MAX_IP_PER_USER
DEFAULT_BANDWIDTH_GB=$DEFAULT_BANDWIDTH_GB
DEFAULT_EXPIRED_DAYS=$DEFAULT_EXPIRED_DAYS
TRIAL_EXPIRED_DAYS=$TRIAL_EXPIRED_DAYS

# Directories
SCRIPT_DIR=$SCRIPT_DIR
CONFIG_DIR=$CONFIG_DIR
LOG_DIR=$LOG_DIR
BACKUP_DIR=$BACKUP_DIR

# Timezone
TIMEZONE=Asia/Jakarta

# Version
VERSION=12.0
INSTALL_DATE=$(date)
EOF
    
    echo -e "${GREEN}✓ Databases created${NC}"
}

# ===================== SETUP CRON JOBS =====================

setup_cron_jobs() {
    echo -e "${CYAN}Setting up cron jobs...${NC}"
    
    # Clear existing cron
    crontab -r 2>/dev/null
    
    # Add new cron jobs
    (crontab -l 2>/dev/null; echo "@daily /root/vps-manager/modules/backup.sh daily") | crontab -
    (crontab -l 2>/dev/null; echo "0 0 * * * /root/vps-manager/modules/user_manager.sh check_expired") | crontab -
    (crontab -l 2>/dev/null; echo "0 */6 * * * /root/vps-manager/modules/monitor.sh bandwidth_log") | crontab -
    (crontab -l 2>/dev/null; echo "@reboot /usr/local/bin/udp-manager start-range 50000 60000") | crontab -
    (crontab -l 2>/dev/null; echo "0 3 * * * apt update && apt upgrade -y") | crontab -
    
    echo -e "${GREEN}✓ Cron jobs configured${NC}"
}

# ===================== CREATE ALL MODULES COMPLETE =====================

create_all_modules_complete() {
    echo -e "${CYAN}Creating all management modules...${NC}"
    
    # Create modules directory
    mkdir -p $MODULE_DIR
    
    # ===================== MODULE 1: USER MANAGER =====================
    cat > "$MODULE_DIR/user_manager.sh" << 'EOF'
#!/bin/bash
. /root/vps-manager/config/vps_manager.conf

add_user() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         CREATE USER ACCOUNT          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
    
    read -p "Username: " username
    [ -z "$username" ] && { echo -e "${RED}Username required!${NC}"; return; }
    
    if grep -q "^$username|" "$USER_DB"; then
        echo -e "${RED}User already exists!${NC}"
        return
    fi
    
    read -sp "Password: " password
    echo
    [ -z "$password" ] && password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
    
    read -p "Expire days [$DEFAULT_EXPIRED_DAYS]: " expire_days
    expire_days=${expire_days:-$DEFAULT_EXPIRED_DAYS}
    expire_date=$(date -d "+$expire_days days" "+%Y-%m-%d")
    created_date=$(date "+%Y-%m-%d")
    
    # Add to database
    echo "$username|$password|$expire_date|$MAX_IP_PER_USER|$DEFAULT_BANDWIDTH_GB|active|$created_date|||" >> "$USER_DB"
    
    # Create system user
    useradd -m -s /bin/false "$username"
    echo "$username:$password" | chpasswd
    
    echo -e "${GREEN}✓ User created successfully!${NC}"
    
    # Show details
    show_user_details "$username" "$password" "$expire_date"
}

show_user_details() {
    local user=$1
    local pass=$2
    local expire=$3
    
    echo -e "${CYAN}════════════ ACCOUNT DETAILS ════════════${NC}"
    echo -e "${GREEN}✅ ACCOUNT CREATED SUCCESSFULLY${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${BLUE}Username:${NC} $user"
    echo -e "${BLUE}Password:${NC} $pass"
    echo -e "${BLUE}Expired:${NC} $expire"
    echo -e "${BLUE}Max IP:${NC} $MAX_IP_PER_USER"
    echo -e "${BLUE}Bandwidth:${NC} ${DEFAULT_BANDWIDTH_GB}GB"
    echo -e "${CYAN}════════════ SSH CONNECTION ════════════${NC}"
    echo -e "Host: $PUBLIC_IP"
    echo -e "Ports: 22, 80, 443, 7200, 7300"
    echo -e "Command: ssh $user@$PUBLIC_IP -p 22"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
}

# MODULE 2: TRIAL ACCOUNT
trial_account() {
    local user="trial-$(date +%Y%m%d-%H%M%S)"
    local pass="trial123"
    local expire_date=$(date -d "+$TRIAL_EXPIRED_DAYS days" "+%Y-%m-%d")
    
    echo "$user|$pass|$expire_date|1|1|trial|$(date "+%Y-%m-%d")|||" >> "$USER_DB"
    useradd -m -s /bin/false "$user"
    echo "$user:$pass" | chpasswd
    
    echo -e "${GREEN}✓ Trial account created!${NC}"
    echo -e "User: $user"
    echo -e "Pass: $pass"
    echo -e "Expired: $expire_date"
    echo -e "Note: Trial account has limited features"
}

# MODULE 3: DELETE USER
delete_user() {
    read -p "Username to delete: " username
    if grep -q "^$username|" "$USER_DB"; then
        sed -i "/^$username|/d" "$USER_DB"
        userdel -r "$username" 2>/dev/null
        echo -e "${GREEN}✓ User deleted${NC}"
    else
        echo -e "${RED}User not found${NC}"
    fi
}

# MODULE 4: RENEW USER
renew_user() {
    read -p "Username: " username
    read -p "Add days: " days
    if grep -q "^$username|" "$USER_DB"; then
        local old_date=$(grep "^$username|" "$USER_DB" | cut -d'|' -f3)
        local new_date=$(date -d "$old_date + $days days" "+%Y-%m-%d")
        sed -i "s/^$username|.*|$old_date|/$username|.*|$new_date|/" "$USER_DB"
        echo -e "${GREEN}✓ Renewed to $new_date${NC}"
    else
        echo -e "${RED}User not found${NC}"
    fi
}

# MODULE 5: UNLOCK USER
unlock_user() {
    read -p "Username: " username
    if grep -q "^$username|" "$USER_DB"; then
        sed -i "s/^$username|.*|locked|/$username|.*|active|/" "$USER_DB"
        passwd -u "$username" 2>/dev/null
        echo -e "${GREEN}✓ User unlocked${NC}"
    else
        echo -e "${RED}User not found${NC}"
    fi
}

# MODULE 6: LOCK USER
lock_user() {
    read -p "Username: " username
    if grep -q "^$username|" "$USER_DB"; then
        sed -i "s/^$username|.*|active|/$username|.*|locked|/" "$USER_DB"
        passwd -l "$username" 2>/dev/null
        echo -e "${RED}✓ User locked${NC}"
    else
        echo -e "${RED}User not found${NC}"
    fi
}

# MODULE 7: CHECK MULTI LOGIN
check_multi_login() {
    echo -e "${CYAN}Checking multi login...${NC}"
    echo -e "${YELLOW}Current SSH Connections:${NC}"
    echo "IP Address        Username        Process"
    echo "----------------------------------------"
    netstat -tnpa | grep 'ESTABLISHED.*sshd' | awk '{print $5,$7}' | sed 's/:/ /' | \
    awk '{print $1,$3}' | sort | uniq -c | sort -nr
}

# MODULE 8: CHECK ALL MEMBERS
check_all_members() {
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           ALL USER ACCOUNTS              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    
    if [ ! -s "$USER_DB" ]; then
        echo -e "${YELLOW}No users found${NC}"
        return
    fi
    
    printf "%-15s %-10s %-12s %-8s %-10s\n" "Username" "Status" "Expired" "IP Limit" "Bandwidth"
    echo "------------------------------------------------------------"
    
    while IFS='|' read -r user pass exp limit bw status created last_login udp v2ray; do
        printf "%-15s %-10s %-12s %-8s %-10s\n" \
            "$user" "$status" "$exp" "$limit" "${bw}GB"
    done < "$USER_DB"
}

# MODULE 9: LIMIT BANDWIDTH
limit_bandwidth() {
    read -p "Username: " username
    read -p "Bandwidth (GB): " gb
    
    if grep -q "^$username|" "$USER_DB"; then
        sed -i "s/^$username|.*|$gb|/$username|.*|$gb|/" "$USER_DB"
        echo -e "${GREEN}✓ Bandwidth limited to ${gb}GB${NC}"
    else
        echo -e "${RED}User not found${NC}"
    fi
}

# MODULE 10: KICK USER BY IP
kick_user() {
    read -p "IP Address to kick: " ip
    if [ -n "$ip" ]; then
        # Kill SSH sessions from this IP
        pkill -9 -f "sshd:.*$ip"
        # Kill any other connections
        ss -K dst $ip
        echo -e "${GREEN}✓ Kicked all connections from $ip${NC}"
    fi
}

# Main function
case "$1" in
    add) add_user ;;
    trial) trial_account ;;
    delete) delete_user ;;
    renew) renew_user ;;
    unlock) unlock_user ;;
    lock) lock_user ;;
    multilogin) check_multi_login ;;
    list) check_all_members ;;
    limit) limit_bandwidth ;;
    kick) kick_user ;;
    *)
        echo "Usage: $0 {add|trial|delete|renew|unlock|lock|multilogin|list|limit|kick}"
        ;;
esac
EOF

    # ===================== MODULE 2: V2RAY MANAGER =====================
    cat > "$MODULE_DIR/v2ray_manager.sh" << 'EOF'
#!/bin/bash
. /root/vps-manager/config/vps_manager.conf

# Generate V2Ray config
generate_v2ray_config() {
    local user=$1
    local protocol=$2
    
    case $protocol in
        vmess)
            local uuid=$(cat /proc/sys/kernel/random/uuid)
            echo "{
  \"v\": \"2\",
  \"ps\": \"$user-VMESS-WS\",
  \"add\": \"$PUBLIC_IP\",
  \"port\": \"$V2RAY_WS_PORT\",
  \"id\": \"$uuid\",
  \"aid\": \"0\",
  \"net\": \"ws\",
  \"type\": \"none\",
  \"host\": \"\",
  \"path\": \"/vmess\",
  \"tls\": \"none\"
}" > "$CONFIG_DIR/v2ray/$user-vmess.json"
            echo "$user|vmess|$uuid|$V2RAY_WS_PORT|/vmess|none|$(date -d '+30 days' '+%Y-%m-%d')|active" >> "$V2RAY_DB"
            echo -e "${GREEN}✓ VMESS config created${NC}"
            ;;
        vless)
            local uuid=$(cat /proc/sys/kernel/random/uuid)
            echo "vless://$uuid@$PUBLIC_IP:$V2RAY_TLS_PORT?type=tcp&security=tls#VLess-$user" > "$CONFIG_DIR/v2ray/$user-vless.txt"
            echo "$user|vless|$uuid|$V2RAY_TLS_PORT||tls|$(date -d '+30 days' '+%Y-%m-%d')|active" >> "$V2RAY_DB"
            echo -e "${GREEN}✓ VLESS config created${NC}"
            ;;
        trojan)
            local password=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
            echo "trojan://$password@$PUBLIC_IP:$TROJAN_PORT?security=tls#Trojan-$user" > "$CONFIG_DIR/v2ray/$user-trojan.txt"
            echo "$user|trojan|$password|$TROJAN_PORT||tls|$(date -d '+30 days' '+%Y-%m-%d')|active" >> "$V2RAY_DB"
            echo -e "${GREEN}✓ Trojan config created${NC}"
            ;;
    esac
}

# List V2Ray accounts
list_v2ray_accounts() {
    echo -e "${CYAN}V2Ray Accounts:${NC}"
    if [ -f "$V2RAY_DB" ]; then
        cat "$V2RAY_DB" | while IFS='|' read -r user protocol uuid port path security exp status; do
            echo -e "${BLUE}$user${NC} - $protocol ($status)"
            echo "  Expire: $exp"
        done
    fi
}

case "$1" in
    add)
        read -p "Username: " user
        echo "Select protocol:"
        echo "1. VMESS (WebSocket)"
        echo "2. VLESS (TLS)"
        echo "3. Trojan"
        read -p "Choice: " choice
        case $choice in
            1) generate_v2ray_config "$user" "vmess" ;;
            2) generate_v2ray_config "$user" "vless" ;;
            3) generate_v2ray_config "$user" "trojan" ;;
        esac
        ;;
    list) list_v2ray_accounts ;;
    *) echo "Usage: $0 {add|list}" ;;
esac
EOF

    # ===================== MODULE 3: UDP MANAGER =====================
    cat > "$MODULE_DIR/udp_manager.sh" << 'EOF'
#!/bin/bash
. /root/vps-manager/config/vps_manager.conf

add_udp_account() {
    read -p "Username: " user
    read -p "UDP Port (50000-60000): " port
    
    # Generate password
    pass=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8)
    
    # Start UDP tunnel
    /usr/local/bin/udp-manager start $port
    
    # Save to database
    echo "$user|$pass|$port|$(date -d '+30 days' '+%Y-%m-%d')|2|active|$(date)|UDP Account" >> "$UDP_DB"
    
    echo -e "${GREEN}✓ UDP Account Created${NC}"
    echo "Username: udp-$user"
    echo "Password: $pass"
    echo "UDP Port: $port"
}

list_udp_accounts() {
    echo -e "${CYAN}UDP Accounts:${NC}"
    if [ -f "$UDP_DB" ]; then
        cat "$UDP_DB" | while IFS='|' read -r user pass port exp limit status created notes; do
            echo -e "${BLUE}$user${NC} - Port: $port ($status)"
        done
    fi
}

case "$1" in
    add) add_udp_account ;;
    list) list_udp_accounts ;;
    *) echo "Usage: $0 {add|list}" ;;
esac
EOF

    # ===================== MODULE 4: BACKUP MANAGER =====================
    cat > "$MODULE_DIR/backup.sh" << 'EOF'
#!/bin/bash
. /root/vps-manager/config/vps_manager.conf

backup_daily() {
    local date=$(date +%Y%m%d)
    local file="backup-$date.tar.gz"
    
    echo -e "${CYAN}Creating daily backup...${NC}"
    tar -czf "$BACKUP_DIR/daily/$file" \
        /etc/ssh/ \
        /usr/local/etc/xray/ \
        /etc/nginx/ \
        /root/vps-manager/config/ \
        /var/log/ 2>/dev/null
    
    echo -e "${GREEN}✓ Backup created: $file${NC}"
}

case "$1" in
    daily) backup_daily ;;
    *) echo "Usage: $0 {daily}" ;;
esac
EOF

    # ===================== MODULE 5: MONITOR MANAGER =====================
    cat > "$MODULE_DIR/monitor.sh" << 'EOF'
#!/bin/bash

monitor_bandwidth() {
    echo -e "${CYAN}Bandwidth Monitoring:${NC}"
    vnstat -d
    echo ""
    echo -e "${YELLOW}Current Usage:${NC}"
    iftop -P -N -n -t -s 5
}

monitor_system() {
    echo -e "${CYAN}System Monitoring:${NC}"
    echo "Uptime: $(uptime -p)"
    echo "Load: $(cat /proc/loadavg | awk '{print $1,$2,$3}')"
    echo "Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
    echo "Disk: $(df -h / | tail -1 | awk '{print $3"/"$2}')"
}

case "$1" in
    bandwidth) monitor_bandwidth ;;
    system) monitor_system ;;
    *) echo "Usage: $0 {bandwidth|system}" ;;
esac
EOF

    # ===================== MODULE 6: FIX MANAGER =====================
    cat > "$MODULE_DIR/fix.sh" << 'EOF'
#!/bin/bash

fix_ssl() {
    echo -e "${CYAN}Fixing SSL...${NC}"
    if [ -z "$DOMAIN" ]; then
        read -p "Enter domain: " DOMAIN
    fi
    certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email $EMAIL
    systemctl restart nginx
    echo -e "${GREEN}✓ SSL fixed${NC}"
}

fix_services() {
    echo -e "${CYAN}Fixing services...${NC}"
    systemctl restart ssh xray nginx
    echo -e "${GREEN}✓ Services restarted${NC}"
}

case "$1" in
    ssl) fix_ssl ;;
    services) fix_services ;;
    *) echo "Usage: $0 {ssl|services}" ;;
esac
EOF

    # Make all modules executable
    chmod +x $MODULE_DIR/*.sh
    
    echo -e "${GREEN}✓ All modules created${NC}"
}

# ===================== CREATE MAIN MENU COMPLETE =====================

create_main_menu_complete() {
    echo -e "${CYAN}Creating main menu...${NC}"
    
    cat > /usr/local/bin/menu << 'EOF'
#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'
WHITE='\033[1;37m'; NC='\033[0m'

show_header() {
    clear
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║         VPS MANAGER v12.0 - COMPLETE MENU               ║${NC}"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${PURPLE}║ Server: $(hostname)${NC}"
    echo -e "${PURPLE}║ IP: $(curl -s ifconfig.me)${NC}"
    echo -e "${PURPLE}║ Date: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${PURPLE}║ Timezone: Asia/Jakarta (GMT+7)${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_menu() {
    show_header
    echo -e "${CYAN}══════════ USER MANAGEMENT ═══════════${NC}"
    echo -e "${GREEN}[1]${NC}  Create User Account"
    echo -e "${GREEN}[2]${NC}  Create Trial Account"
    echo -e "${GREEN}[3]${NC}  Delete User Account"
    echo -e "${GREEN}[4]${NC}  Renew User Account"
    echo -e "${GREEN}[5]${NC}  Unlock User Account"
    echo -e "${GREEN}[6]${NC}  Lock User Account"
    echo -e "${GREEN}[7]${NC}  Check Multi Login"
    echo -e "${GREEN}[8]${NC}  Check All Members"
    echo -e "${GREEN}[9]${NC}  Limit Bandwidth"
    echo -e "${GREEN}[10]${NC} Kick User by IP"
    
    echo -e "${CYAN}══════════ V2Ray MANAGEMENT ═══════════${NC}"
    echo -e "${GREEN}[11]${NC} Create V2Ray Account"
    echo -e "${GREEN}[12]${NC} List V2Ray Accounts"
    
    echo -e "${CYAN}══════════ UDP MANAGEMENT ═══════════${NC}"
    echo -e "${GREEN}[13]${NC} Create UDP Account"
    echo -e "${GREEN}[14]${NC} List UDP Accounts"
    
    echo -e "${CYAN}══════════ SYSTEM TOOLS ═══════════${NC}"
    echo -e "${GREEN}[15]${NC} Backup System"
    echo -e "${GREEN}[16]${NC} Speed Test"
    echo -e "${GREEN}[17]${NC} Monitor Bandwidth"
    echo -e "${GREEN}[18]${NC} System Info"
    echo -e "${GREEN}[19]${NC} Fix SSL/Nginx"
    echo -e "${GREEN}[20]${NC} Restart Services"
    
    echo -e "${CYAN}════════════════════════════════════${NC}"
    echo -e "${RED}[0]${NC}  Exit to Shell"
    echo ""
    echo -e "${YELLOW}Type 'menu' to return to this menu${NC}"
    echo ""
}

while true; do
    show_menu
    read -p "Select option [0-20]: " choice
    
    case $choice in
        1) /root/vps-manager/modules/user_manager.sh add ;;
        2) /root/vps-manager/modules/user_manager.sh trial ;;
        3) /root/vps-manager/modules/user_manager.sh delete ;;
        4) /root/vps-manager/modules/user_manager.sh renew ;;
        5) /root/vps-manager/modules/user_manager.sh unlock ;;
        6) /root/vps-manager/modules/user_manager.sh lock ;;
        7) /root/vps-manager/modules/user_manager.sh multilogin ;;
        8) /root/vps-manager/modules/user_manager.sh list ;;
        9) /root/vps-manager/modules/user_manager.sh limit ;;
        10) /root/vps-manager/modules/user_manager.sh kick ;;
        11) /root/vps-manager/modules/v2ray_manager.sh add ;;
        12) /root/vps-manager/modules/v2ray_manager.sh list ;;
        13) /root/vps-manager/modules/udp_manager.sh add ;;
        14) /root/vps-manager/modules/udp_manager.sh list ;;
        15) /root/vps-manager/modules/backup.sh daily ;;
        16) speedtest-cli ;;
        17) /root/vps-manager/modules/monitor.sh bandwidth ;;
        18) /root/vps-manager/modules/monitor.sh system ;;
        19) /root/vps-manager/modules/fix.sh ssl ;;
        20) /root/vps-manager/modules/fix.sh services ;;
        0)
            echo -e "${YELLOW}Exiting to shell...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
done
EOF
    
    chmod +x /usr/local/bin/menu
    
    # Create alias
    echo "alias menu='/usr/local/bin/menu'" >> /root/.bashrc
    
    echo -e "${GREEN}✓ Main menu created${NC}"
}

# ===================== SETUP BACKUP SYSTEM =====================

setup_backup_system() {
    echo -e "${CYAN}Setting up backup system...${NC}"
    
    # Create backup script
    cat > /usr/local/bin/backup-vps << 'EOF'
#!/bin/bash
BACKUP_DIR="/root/backup"
DATE=$(date +%Y%m%d_%H%M%S)

echo "Backing up VPS configuration..."
tar -czf "$BACKUP_DIR/full-backup-$DATE.tar.gz" \
    /etc/ssh/ \
    /usr/local/etc/xray/ \
    /etc/nginx/ \
    /root/vps-manager/ \
    /etc/iptables/ \
    /var/log/ 2>/dev/null

echo "Backup completed: $BACKUP_DIR/full-backup-$DATE.tar.gz"
EOF
    
    chmod +x /usr/local/bin/backup-vps
    
    echo -e "${GREEN}✓ Backup system configured${NC}"
}

# ===================== FINAL CONFIGURATION =====================

final_configuration() {
    echo -e "${CYAN}Finalizing configuration...${NC}"
    
    # Set permissions
    chmod 600 $USER_DB $BANDWIDTH_DB $UDP_DB $V2RAY_DB
    chmod 700 $SCRIPT_DIR
    chmod 755 $MODULE_DIR/*.sh
    
    # Create log rotation
    cat > /etc/logrotate.d/vps-manager << EOF
/var/log/xray/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 root root
}
/root/vps-manager/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 root root
}
EOF
    
    # Enable services
    systemctl enable ssh xray nginx fail2ban
    
    echo -e "${GREEN}✓ Final configuration completed${NC}"
}

# ===================== DISPLAY COMPLETION MESSAGE =====================

display_completion_message() {
    clear
    echo -e "${GREEN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════╗
║           INSTALLATION COMPLETED SUCCESSFULLY!          ║
╚══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    echo -e "${CYAN}════════════ SERVER INFORMATION ═════════════${NC}"
    echo -e "${BLUE}Public IP:${NC} $PUBLIC_IP"
    echo -e "${BLUE}SSH Ports:${NC} 22, 80, 443, 7200, 7300"
    echo -e "${BLUE}UDP Ports:${NC} 7100 + 50000-60000"
    echo -e "${BLUE}V2Ray Ports:${NC}"
    echo -e "  • VMESS WebSocket: port 80"
    echo -e "  • VLESS TLS: port 443"
    echo -e "  • Trojan: port 2053"
    echo -e "  • Backup: ports 8443, 2083"
    
    echo -e "${CYAN}════════════ MANAGEMENT TOOLS ═════════════${NC}"
    echo -e "${YELLOW}Type 'menu' to access management panel${NC}"
    echo -e "Available modules:"
    echo -e "  1-10: User Management"
    echo -e "  11-12: V2Ray Management"
    echo -e "  13-14: UDP Management"
    echo -e "  15-20: System Tools"
    
    echo -e "${CYAN}════════════ EXAMPLE ACCOUNT CREATION ═════════════${NC}"
    echo -e "${GREEN}Example SSH Account:${NC}"
    echo -e "Username: testuser"
    echo -e "Password: testpass123"
    echo -e "Expired: $(date -d '+30 days' '+%Y-%m-%d')"
    echo -e "SSH Command: ssh testuser@$PUBLIC_IP -p 22"
    echo ""
    echo -e "${GREEN}Example V2Ray VMESS:${NC}"
    echo -e "Port: 80 (WebSocket)"
    echo -e "Path: /vmess"
    echo -e "UUID: auto-generated"
    echo ""
    echo -e "${GREEN}Example UDP Account:${NC}"
    echo -e "UDP Port: 51000"
    echo -e "Command: socat UDP4-RECVFROM:51000,fork EXEC:'ssh udp-user@$PUBLIC_IP -p 22'"
    
    echo -e "${CYAN}════════════ IMPORTANT NOTES ═════════════${NC}"
    echo -e "${RED}1. Change default passwords immediately!${NC}"
    echo -e "${RED}2. Configure domain and SSL in menu option 19${NC}"
    echo -e "${RED}3. Regular backups via menu option 15${NC}"
    echo -e "${RED}4. Monitor bandwidth usage regularly${NC}"
    
    echo -e "${CYAN}════════════ SUPPORT INFORMATION ═════════════${NC}"
    echo -e "Script Version: 12.0 Complete"
    echo -e "Install Date: $(date)"
    echo -e "Log File: $LOG_FILE"
    echo -e "Config Directory: $CONFIG_DIR"
    echo -e "${CYAN}══════════════════════════════════════════════${NC}"
    
    echo -e "${GREEN}✅ Installation completed at: $(date)${NC}"
    echo -e "${YELLOW}🚀 Type 'menu' to start managing your VPS!${NC}"
}

# ===================== RUN INSTALLATION =====================

# Start installation
main_installation

# Save script to file
cat > /root/install-vps.sh << SCRIPT
$(cat $0)
SCRIPT

chmod +x /root/install-vps.sh
echo -e "${GREEN}✓ Installation script saved to /root/install-vps.sh${NC}"
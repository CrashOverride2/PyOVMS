#!/bin/bash
#
# PyOVMS Server Installation Script for Ubuntu 24.04
#
# This script automates the installation of the PyOVMS server,
# including the FlashMQ MQTT broker and systemd services.
#
# USAGE:
# 1. Download this script.
# 2. Make it executable: chmod +x install.sh
# 3. Run with sudo: sudo ./install.sh
#

# --- Configuration ---
# Repository the installer clones from. Override without editing this file:
#   sudo PYOVMS_REPO_URL=https://github.com/you/PyOVMS.git ./install.sh
# check_repo_url below rejects a placeholder URL, so a fork that forgets to update this
# fails immediately with an explanation instead of halfway through on a git error.
PYOVMS_REPO_URL="${PYOVMS_REPO_URL:-https://github.com/CrashOverride2/PyOVMS.git}"

PYOVMS_DIR="/opt/PyOVMS"
VENV_DIR="/opt/PyOVMS-venv"
PYOVMS_USER="ovms"
PYOVMS_GROUP="ovms"
MQTT_CONFIG_GROUP="mqtt-config"
FLASHMQ_CONF_DIR="/etc/flashmq"
FLASHMQ_PASSWD_FILE="${FLASHMQ_CONF_DIR}/passwd"
FLASHMQ_ACL_FILE="${FLASHMQ_CONF_DIR}/acl"
DOC_INSTALL_DIR="${PYOVMS_DIR}/doc/install"

# --- Helper Functions ---
log_info() {
    echo -e "\e[34m[INFO]\e[0m $1"
}

log_success() {
    echo -e "\e[32m[SUCCESS]\e[0m $1"
}

log_warning() {
    echo -e "\e[33m[WARNING]\e[0m $1"
}

log_error() {
    echo -e "\e[31m[ERROR]\e[0m $1" >&2
    exit 1
}

check_repo_url() {
    case "$PYOVMS_REPO_URL" in
        *example.com*|"")
            log_error "PYOVMS_REPO_URL is still the placeholder (${PYOVMS_REPO_URL}). Set it to the repository you publish PyOVMS from, either by editing this script or by running: sudo PYOVMS_REPO_URL=<url> ./install.sh"
            ;;
    esac
    log_info "Installing from ${PYOVMS_REPO_URL}"
}

# --- Script Start ---
# 1. Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root. Please use sudo."
fi

log_info "Starting PyOVMS server installation..."

# 2. Install System Dependencies
install_system_deps() {
    log_info "Updating package lists and installing system dependencies..."
    apt-get update
    apt-get install -y python3.12 python3.12-venv git curl socat nginx-full || log_error "Failed to install system dependencies."
    log_success "System dependencies installed."
}

# 3. Create PyOVMS System User and Groups
setup_pyovms_user() {
    log_info "Setting up system user and groups..."
    if ! getent group "$PYOVMS_GROUP" >/dev/null; then
        groupadd --system "$PYOVMS_GROUP" || log_error "Failed to create group '$PYOVMS_GROUP'."
    fi

    if ! id "$PYOVMS_USER" >/dev/null 2>&1; then
        useradd --system -g "$PYOVMS_GROUP" -d "$PYOVMS_DIR" --shell /bin/false "$PYOVMS_USER" || log_error "Failed to create user '$PYOVMS_USER'."
    fi

    if ! getent group "$MQTT_CONFIG_GROUP" >/dev/null; then
        groupadd --system "$MQTT_CONFIG_GROUP" || log_error "Failed to create group '$MQTT_CONFIG_GROUP'."
    fi

    usermod -a -G "$MQTT_CONFIG_GROUP" "$PYOVMS_USER" || log_error "Failed to add user '$PYOVMS_USER' to group '$MQTT_CONFIG_GROUP'."
    log_success "System user '$PYOVMS_USER' and group '$MQTT_CONFIG_GROUP' are configured."
}

# 4. Clone PyOVMS Repository and Set Up Venv
clone_and_setup_venv() {
    # Check if the target directory exists
    if [ -d "$PYOVMS_DIR" ]; then
        # Check if it's a git repo. If .git exists, we assume it's correct.
        if [ -d "${PYOVMS_DIR}/.git" ]; then
            log_info "PyOVMS directory already exists at ${PYOVMS_DIR}. Skipping clone."
        else
            # Directory exists but isn't a git repo. Check if it's empty.
            if [ -z "$(ls -A "$PYOVMS_DIR")" ]; then
                log_info "Directory is empty. Proceeding to clone into it."
                git clone "$PYOVMS_REPO_URL" "$PYOVMS_DIR" || log_error "Failed to clone repository into existing empty directory."
            else
                log_error "Directory ${PYOVMS_DIR} exists but is not a valid PyOVMS repository and is not empty. Please remove or backup this directory and run the script again."
            fi
        fi
    else
        # Directory does not exist, so we clone it.
        log_info "Cloning PyOVMS repository into ${PYOVMS_DIR}..."
        git clone "$PYOVMS_REPO_URL" "$PYOVMS_DIR" || log_error "Failed to clone repository."
    fi

    log_info "Setting up Python virtual environment at ${VENV_DIR}..."
    # As root, create the venv directory and set its ownership
    mkdir -p "$VENV_DIR" || log_error "Failed to create venv directory ${VENV_DIR}."
    chown "$PYOVMS_USER:$PYOVMS_GROUP" "$VENV_DIR" || log_error "Failed to set ownership on venv directory."
    
    # Now, as the ovms user, create the venv content inside the prepared directory
    sudo -u "$PYOVMS_USER" python3.12 -m venv "$VENV_DIR" || log_error "Failed to create virtual environment."
    
    # Set ownership of the project directory itself
    chown -R "$PYOVMS_USER:$PYOVMS_GROUP" "$PYOVMS_DIR"
    
    log_info "Installing Python dependencies from requirements.txt..."
    sudo -u "$PYOVMS_USER" "$VENV_DIR/bin/python3" -m pip install --upgrade pip || log_error "Failed to upgrade pip."
    sudo -u "$PYOVMS_USER" "$VENV_DIR/bin/python3" -m pip install -r "${PYOVMS_DIR}/requirements.txt" || log_error "Failed to install Python requirements."

    log_success "PyOVMS application and virtual environment are set up."
}


# 5. Install FlashMQ
install_flashmq() {
    log_info "Installing FlashMQ MQTT broker..."
    # Add FlashMQ repository and GPG key
    curl https://www.flashmq.org/wp-content/uploads/2021/10/flashmq-repo.gpg > /usr/share/keyrings/flashmq-repo.gpg
    echo "deb [signed-by=/usr/share/keyrings/flashmq-repo.gpg] http://repo.flashmq.org/apt noble main" > /etc/apt/sources.list.d/flashmq.list
    
    apt-get update
    apt-get install -y flashmq || log_error "Failed to install FlashMQ."
    
    #log_info "Configuring FlashMQ user permissions..."
    #usermod -a -G "$MQTT_CONFIG_GROUP" flashmq || log_error "Failed to add user 'flashmq' to group '$MQTT_CONFIG_GROUP'."
    log_success "FlashMQ installed successfully."
}

# 6. Create Configuration and Service Templates
create_templates() {
    log_info "Creating installation templates in ${DOC_INSTALL_DIR}..."
    mkdir -p "$DOC_INSTALL_DIR" || log_error "Failed to create directory ${DOC_INSTALL_DIR}"

    # FlashMQ Config Template
    cat << EOF > "${DOC_INSTALL_DIR}/flashmq.conf"
# FlashMQ configuration for PyOVMS
# This file is managed by the PyOVMS installation script.

log_file    /var/log/flashmq/flashmq.log
storage_dir /var/lib/flashmq
log_level info

listen {
  port 1883
  protocol mqtt
  inet_protocol ip4_ip6
  tcp_nodelay true
}

# Optional: TLS listener for MQTT
#listen {
#  port 8883
#  protocol mqtt
#  inet_protocol ip4_ip6
#  tcp_nodelay true
#  fullchain /path/to/your/fullchain.pem
#  privkey /path/to/your/key.pem
#}

# Optional: WebSocket listener for external MQTT clients
#  port 9001
#  protocol websockets
#  inet_protocol ip4_ip6
#  tcp_nodelay true
#}

allow_anonymous false
mosquitto_acl_file ${FLASHMQ_ACL_FILE}
mosquitto_password_file ${FLASHMQ_PASSWD_FILE}

expire_sessions_after_seconds 60
EOF

    # PyOVMS Service Template
    cat << EOF > "${DOC_INSTALL_DIR}/pyovms.service"
[Unit]
Description=PyOVMS - Python-based OVMS Server
After=network.target flashmq.service
Wants=flashmq.service

[Service]
Type=simple
Restart=always
WorkingDirectory=${PYOVMS_DIR}
ExecStart=${VENV_DIR}/bin/python ${PYOVMS_DIR}/run.py
User=${PYOVMS_USER}
Group=${PYOVMS_GROUP}
KillSignal=SIGINT
TimeoutStopSec=3
SendSIGKILL=yes
KillMode=control-group
StandardOutput=journal
StandardError=journal

# Sandboxing. The unit dropped privileges via User=/Group= but was otherwise
# unconfined, so a compromise of the process could read /home, write anywhere the
# service user owned, and reach the rest of the filesystem. The service needs
# nothing beyond its own directory and the broker's credential files.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
# IPv4/IPv6 for HTTP, the V2 TCP listeners and MQTT; AF_UNIX for logging.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
# ProtectSystem=strict makes everything read-only, so the paths the server really
# writes have to be named. MQTT_PASSWD_FILE/MQTT_ACL_FILE live under /etc/mosquitto
# on a default install — adjust both here and in .env if you moved them.
ReadWritePaths=${PYOVMS_DIR}
ReadWritePaths=-/etc/mosquitto

[Install]
WantedBy=multi-user.target
EOF
    log_success "Template files created."
}


# 7. Configure FlashMQ
configure_flashmq() {
    log_info "Configuring FlashMQ..."
    
    # Stop the service to prevent issues while changing configs
    systemctl stop flashmq

    # Backup original config if it exists
    [ -f "/etc/flashmq/flashmq.conf" ] && mv /etc/flashmq/flashmq.conf /etc/flashmq/flashmq.conf.bak

    cp "${DOC_INSTALL_DIR}/flashmq.conf" "${FLASHMQ_CONF_DIR}/flashmq.conf" || log_error "Failed to copy FlashMQ config."
    
    # Create empty password and acl files
    touch "$FLASHMQ_PASSWD_FILE" "$FLASHMQ_ACL_FILE"
    
    # Set permissions for PyOVMS to manage the files
    chown -R "$PYOVMS_USER:$MQTT_CONFIG_GROUP" "$FLASHMQ_CONF_DIR" || log_error "Failed to set ownership on ${FLASHMQ_CONF_DIR}."
    chmod -R 770 "$FLASHMQ_CONF_DIR" || log_error "Failed to set permissions on ${FLASHMQ_CONF_DIR}."

    log_success "FlashMQ configured."
}

# 8. Configure PyOVMS .env file
configure_pyovms_env() {
    log_info "Configuring PyOVMS .env file..."
    local env_file="${PYOVMS_DIR}/.env"

    if [ ! -f "${PYOVMS_DIR}/.env-template" ]; then
        log_error ".env-template not found in ${PYOVMS_DIR}. The git clone may have failed."
    fi

    # Check if generate_secrets.py exists
    if [ ! -f "${PYOVMS_DIR}/doc/security/generate_secrets.py" ]; then
        log_error "generate_secrets.py not found in ${PYOVMS_DIR}/doc/security/. The git clone may have failed."
    fi

    # Use generate_secrets.py to create secure .env file with all secrets
    log_info "Generating secure secrets using generate_secrets.py..."
    sudo -u "$PYOVMS_USER" "$VENV_DIR/bin/python3" "${PYOVMS_DIR}/doc/security/generate_secrets.py" \
        --output "$env_file" --force || log_error "Failed to generate secure secrets."

    # Now customize MQTT broker settings for FlashMQ
    log_info "Configuring MQTT broker settings..."
    sed -i "s|^#MQTT_PASSWD_FILE=.*|MQTT_PASSWD_FILE=\"${FLASHMQ_PASSWD_FILE}\"|" "$env_file"
    sed -i "s|^#MQTT_ACL_FILE=.*|MQTT_ACL_FILE=\"${FLASHMQ_ACL_FILE}\"|" "$env_file"

    # Ensure proper ownership and permissions
    chown "$PYOVMS_USER:$PYOVMS_GROUP" "$env_file"
    chmod 640 "$env_file"

    log_success ".env file configured with secure secrets and MQTT settings."
}

# 9. Setup Systemd Services
setup_systemd_services() {
    log_info "Installing systemd services..."

    cp "${DOC_INSTALL_DIR}/pyovms.service" /etc/systemd/system/pyovms.service || log_error "Failed to copy pyovms service file."
    
    systemctl daemon-reload
    
    log_info "Enabling services to start on boot..."
    systemctl enable flashmq || log_warning "Could not enable flashmq service."
    systemctl enable pyovms || log_warning "Could not enable pyovms service."

    log_success "Systemd services installed and enabled."
}


# --- Main Execution ---
check_repo_url
install_system_deps
setup_pyovms_user
clone_and_setup_venv
install_flashmq
create_templates
configure_flashmq
configure_pyovms_env
setup_systemd_services

# Final start of services
log_info "Starting services..."
systemctl start flashmq
systemctl start pyovms

echo
log_success "Installation Complete!"
echo
echo "=========================================================================="
echo " NEXT STEPS"
echo "=========================================================================="
echo "1. The PyOVMS and FlashMQ services have been started."
echo
echo "2. Check their status with:"
echo "   sudo systemctl status pyovms"
echo "   sudo systemctl status flashmq"
echo
echo "3. View live logs with:"
echo "   sudo journalctl -u pyovms -f"
echo "   sudo journalctl -u flashmq -f"
echo
echo "4. On the first run, PyOVMS created a secure admin user."
log_warning "Find the one-time username and password in the PyOVMS log:"
echo "   sudo journalctl -u pyovms | grep CRITICAL"
echo
echo "5. Access the web interface at http://<your_server_ip>:8000"
echo
log_warning "Not yet reachable over HTTPS. Nginx was installed but NOT configured:"
echo "   Continue with 'Step 3 - Reverse Proxy' in Readme.md, using the ready-made"
echo "   configs in ${PYOVMS_DIR}/doc/reverse proxy/ (Nginx or Caddy)."
echo
echo "=========================================================================="
echo " SECURITY NOTES"
echo "=========================================================================="
log_success "✓ All security secrets have been automatically generated:"
echo "  - Session signing key pair (JWT_PRIVATE_KEY / JWT_PUBLIC_KEY, Ed25519)"
echo "  - CSRF signing key (SECRET_KEY_JWT)"
echo "  - TOTP encryption key (TOTP_ENCRYPTION_KEY)"
echo "  - MQTT backend service passwords"
echo "  - Karto service MQTT password"
echo
echo "✓ Configuration file: ${PYOVMS_DIR}/.env"
echo "  Permissions: 640 (read-only for ovms user)"
echo
log_warning "⚠  IMPORTANT: Backup your .env file securely!"
echo "   This file contains critical secrets needed to access your system."
echo
echo "✓ Available security tools:"
echo "  - Check security:  cd ${PYOVMS_DIR} && bash doc/security/check_security.sh"
echo "  - Test security:   cd ${PYOVMS_DIR} && python doc/security/test_security_features.py"
echo "  - WebAuthn setup:  See doc/security/WEBAUTHN_SETUP.md"
echo
echo "=========================================================================="

exit 0
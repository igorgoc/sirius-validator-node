#!/usr/bin/env bash
# ==============================================================================
# Sirius Validator Node — 1-Line Ubuntu / Debian VPS Installer
# Installs Docker, Docker Compose, sets up firewall rules, and starts the node.
# ==============================================================================

set -e

echo "================================================================================"
echo "🚀 Installing ProximaX Sirius SuperContract Validator Node"
echo "================================================================================"

# Check root privileges
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (or use sudo)."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "📦 1. Updating system packages and installing prerequisites..."
apt-get update -y
apt-get install -y curl git ufw jq openssl ca-certificates gnupg lsb-release

# Install Docker if missing
if ! command -v docker &> /dev/null; then
  echo "🐳 2. Installing Docker Engine..."
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable docker
  systemctl start docker
  echo "✅ Docker installed successfully."
else
  echo "✅ Docker already installed."
fi

# Clone or update validator repo
INSTALL_DIR="/opt/sirius-validator-node"
echo "📂 3. Setting up validator directory at ${INSTALL_DIR}..."

if [ ! -d "${INSTALL_DIR}" ]; then
  mkdir -p "${INSTALL_DIR}"
  cp -r . "${INSTALL_DIR}/" 2>/dev/null || true
fi

cd "${INSTALL_DIR}"
mkdir -p data/drives data/logs config contracts

# Setup node.env if not present
if [ ! -f "config/node.env" ]; then
  echo "⚙️  4. Generating config/node.env..."
  RAND_TOKEN=$(openssl rand -hex 32 2>/dev/null || node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  if [ -f "config/node.env.example" ]; then
    cp config/node.env.example config/node.env
    sed -i.bak "s/^SIRIUS_VM_AUTH_TOKEN=.*/SIRIUS_VM_AUTH_TOKEN=${RAND_TOKEN}/" config/node.env && rm -f config/node.env.bak
  else
    cat <<EOF > config/node.env
NODE_NAME="node-$(hostname)"
NODE_PORT=5051
SIRIUS_VM_BIND_HOST=0.0.0.0
SIRIUS_VM_AUTH_TOKEN=${RAND_TOKEN}
SIRIUS_NETWORK=testnet2
SIRIUS_RPC_URL=https://api-2.testnet2.xpxsirius.io
DRIVE_KEY_HEX=bd1d100a98c34f62e170a8395b4498dc1e730286f5a12c489b37d01562f0cb23
EOF
  fi
  chmod 600 config/node.env
  echo "🔑 Generated random node authentication token in config/node.env."
fi

# Configure firewall
echo "🛡️  5. Configuring UFW firewall (allowing gRPC port 5051)..."
ufw allow 5051/tcp comment "Sirius SuperContract Validator gRPC" 2>/dev/null || true

# Start container
echo "🚀 6. Starting Sirius Validator container with Docker Compose..."
if command -v docker-compose &> /dev/null; then
  docker-compose up -d --build
else
  docker compose up -d --build
fi

echo ""
echo "================================================================================"
echo "🎉 SUCCESS: Sirius SuperContract Validator Node is ONLINE!"
echo "================================================================================"
echo "📍 Directory:  ${INSTALL_DIR}"
echo "📍 Config:     ${INSTALL_DIR}/config/node.env"
echo "📍 Check logs: docker compose logs -f"
echo "📍 Status:     docker compose ps"
echo "================================================================================"

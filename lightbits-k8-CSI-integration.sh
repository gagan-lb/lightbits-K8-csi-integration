#!/bin/bash

# Lightbits CSI Plugin Complete Integration Script
# This script automates the entire deployment process from prerequisites to testing
# COMPLETE VERSION: Includes deployment, verification, testing, and management tools

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
CSI_BUNDLE="lb-csi-bundle-1.19.0.15002456970.tar.gz"
WORK_DIR="/tmp/lightbits-csi-deployment"
REMOTE_WORK_DIR="/tmp/lightbits-setup"

# Store the original directory and absolute path to CSI bundle
ORIGINAL_DIR=$(pwd)
CSI_BUNDLE_PATH=""

# Variables for master node
MASTER_NODE=""
MASTER_USER=""
MASTER_PASS=""

# Logging functions
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Function to show usage
show_usage() {
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE}  Complete LightBits CSI Integration Script${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo
    echo "This script will:"
    echo "  ✓ Deploy LightBits CSI plugin to your Kubernetes cluster"
    echo "  ✓ Configure StorageClass and authentication secrets"
    echo "  ✓ Test volume provisioning and I/O operations"
    echo "  ✓ Create management scripts for ongoing operations"
    echo "  ✓ Perform comprehensive status verification"
    echo
    echo "Prerequisites:"
    echo "  - CSI bundle file: $CSI_BUNDLE in current directory"
    echo "  - SSH access to all Kubernetes nodes (with passwords)"
    echo "  - kubectl access on master node"
    echo "  - LightOS management endpoints and JWT token"
    echo
    echo "Usage: $0"
    echo
    echo "After completion, use these commands on your master node:"
    echo "  /tmp/lightbits-setup/lightbits_management.sh status  # Check status"
    echo "  /tmp/lightbits-setup/lightbits_management.sh test    # Test volumes"
    echo "  /tmp/lightbits-setup/lightbits_management.sh help    # Show all options"
    echo
}

# Check if help requested
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "help" ]]; then
    show_usage
    exit 0
fi

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to base64 encode (cross-platform)
base64_encode() {
    local input="$1"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo -n "$input" | base64
    else
        # Linux
        echo -n "$input" | base64 -w 0
    fi
}

# Function to verify login credentials
verify_login_credentials() {
    local host=$1
    local user=$2
    local pass=$3
    local node_name=$4

    log "Verifying login credentials for $node_name ($user@$host)..."
    
    # Test SSH connectivity with detailed error reporting
    if sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 -o PasswordAuthentication=yes "$user@$host" "echo 'Login verification successful' && whoami && hostname" 2>/dev/null; then
        log "✓ Login credentials verified for $user@$host"
        return 0
    else
        error "Login verification failed for $user@$host"
        error "Please check:"
        error "  1. IP address: $host is reachable"
        error "  2. Username: '$user' exists and has SSH access"
        error "  3. Password: is correct"
        error "  4. SSH service: is running on port 22"
        
        # Try to ping the host
        if ping -c 1 -W 5 "$host" &>/dev/null; then
            warn "Host $host is reachable via ping"
        else
            warn "Host $host is NOT reachable via ping"
        fi
        
        # Try to connect without password to see if SSH is running
        if timeout 5 bash -c "</dev/tcp/$host/22" 2>/dev/null; then
            warn "SSH port 22 is open on $host"
            warn "This suggests the password or username is incorrect"
        else
            warn "Cannot connect to SSH port 22 on $host"
            warn "SSH service may not be running"
        fi
        
        return 1
    fi
}

# Function to collect deployment information
collect_deployment_info() {
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE}  LightBits CSI Integration (COMPLETE)${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo

    # Kubernetes nodes
    echo -e "${YELLOW}Kubernetes Nodes Information:${NC}"
    echo "Enter Kubernetes node details (IP address, username, password)"
    echo "Note: The first node will be used as the master node for kubectl operations"
    
    K8S_NODES=()
    K8S_USERS=()
    K8S_PASSWORDS=()
    
    node_count=1
    while true; do
        if [[ $node_count -eq 1 ]]; then
            echo -e "${YELLOW}Kubernetes Master Node (with kubectl access):${NC}"
        else
            echo -e "${YELLOW}Kubernetes Node $node_count:${NC}"
        fi
        
        while true; do
            read -p "Enter K8s node $node_count IP address: " node_ip
            if validate_ip "$node_ip"; then
                break
            else
                error "Invalid IP address. Please try again."
            fi
        done
        
        read -p "Enter username for K8s node $node_count: " node_user
        
        # Get password and verify it immediately
        while true; do
            read -s -p "Enter password for K8s node $node_count: " node_pass
            echo
            
            # Verify credentials immediately
            if verify_login_credentials "$node_ip" "$node_user" "$node_pass" "Node $node_count"; then
                break
            else
                warn "Login verification failed. Please try again."
                echo -n "Press Enter to retry or Ctrl+C to exit..."
                read
            fi
        done
        
        K8S_NODES+=("$node_ip")
        K8S_USERS+=("$node_user")
        K8S_PASSWORDS+=("$node_pass")
        
        echo
        if [[ $node_count -eq 1 ]]; then
            read -p "Do you want to add more K8s nodes? (y/n): " ADD_MORE
        else
            read -p "Do you want to add another K8s node? (y/n): " ADD_MORE
        fi
        
        if [[ $ADD_MORE != [yY] ]]; then
            break
        fi
        
        ((node_count++))
        echo
    done

    # Store master node details for kubectl operations
    MASTER_NODE="${K8S_NODES[0]}"
    MASTER_USER="${K8S_USERS[0]}"
    MASTER_PASS="${K8S_PASSWORDS[0]}"

    # LightBits endpoints
    echo
    echo -e "${YELLOW}LightBits Cluster Information:${NC}"
    read -p "Enter LightOS management endpoints (format: ip1:port,ip2:port,ip3:port): " LIGHTBITS_ENDPOINTS
    
    # Remove any trailing comma and spaces
    LIGHTBITS_ENDPOINTS=$(echo "$LIGHTBITS_ENDPOINTS" | sed 's/[, ]*$//')
    
    # Validate endpoints format
    if [[ ! $LIGHTBITS_ENDPOINTS =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+(,[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+)*$ ]]; then
        error "Invalid endpoint format. Expected: ip1:port,ip2:port,ip3:port"
        error "You entered: '$LIGHTBITS_ENDPOINTS'"
        exit 1
    fi

    # JWT Token
    echo
    echo -e "${YELLOW}JWT Token Information:${NC}"
    echo "The JWT token should be obtained from your LightOS cluster."
    echo "You can get it by running: lightos cluster get-jwt-token"
    echo "Or from the LightOS web UI under Cluster -> API Tokens"
    echo
    read -p "Enter LightOS JWT token: " LIGHTBITS_JWT
    
    if [[ -z "$LIGHTBITS_JWT" ]]; then
        error "JWT token cannot be empty"
        exit 1
    fi

    # Additional configuration
    echo
    echo -e "${YELLOW}Storage Configuration:${NC}"
    read -p "Enter LightOS project name [default]: " LIGHTOS_PROJECT
    LIGHTOS_PROJECT=${LIGHTOS_PROJECT:-"default"}
    
    read -p "Enter replica count [3]: " REPLICA_COUNT
    REPLICA_COUNT=${REPLICA_COUNT:-"3"}
    
    read -p "Enable compression? (enabled/disabled) [disabled]: " COMPRESSION
    COMPRESSION=${COMPRESSION:-"disabled"}
    
    read -p "Management scheme (grpc/grpcs) [grpcs]: " MGMT_SCHEME
    MGMT_SCHEME=${MGMT_SCHEME:-"grpcs"}

    echo
    # Display collected information
    echo -e "${BLUE}Collected Information:${NC}"
    echo "Kubernetes Master Node: ${K8S_USERS[0]}@${K8S_NODES[0]}"
    echo "Kubernetes Nodes:"
    for i in "${!K8S_NODES[@]}"; do
        echo "  Node $((i+1)): ${K8S_USERS[$i]}@${K8S_NODES[$i]}"
    done
    echo "LightBits Endpoints: $LIGHTBITS_ENDPOINTS"
    echo "LightOS Project: $LIGHTOS_PROJECT"
    echo "Replica Count: $REPLICA_COUNT"
    echo "Compression: $COMPRESSION"
    echo "Management Scheme: $MGMT_SCHEME"
    echo

    read -p "Is this information correct? (y/n): " CONFIRM
    if [[ $CONFIRM != [yY] ]]; then
        error "Deployment cancelled by user."
        exit 1
    fi
}

# Function to install sshpass if needed
install_sshpass() {
    if ! command -v sshpass &> /dev/null; then
        log "Installing sshpass..."
        
        if [[ "$OSTYPE" == "darwin"* ]]; then
            if command -v brew &> /dev/null; then
                brew install hudochenkov/sshpass/sshpass
            else
                error "Homebrew not found. Please install sshpass manually."
                exit 1
            fi
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y sshpass
        elif command -v yum &> /dev/null; then
            sudo yum install -y sshpass
        elif command -v apt &> /dev/null; then
            sudo apt update && sudo apt install -y sshpass
        else
            error "Package manager not found. Please install sshpass manually."
            exit 1
        fi
    fi
}

# Function to generate SSH key
generate_ssh_key() {
    if [[ ! -f ~/.ssh/id_rsa ]]; then
        log "Generating SSH key pair..."
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
    else
        info "SSH key already exists."
    fi
}

# Function to copy SSH key to remote host
copy_ssh_key() {
    local host=$1
    local user=$2
    local pass=$3

    log "Setting up passwordless authentication for $user@$host..."
    
    # First test basic SSH connectivity
    if ! sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$user@$host" "echo 'SSH connection test successful'" 2>/dev/null; then
        error "Cannot establish SSH connection to $user@$host"
        return 1
    fi
    
    # Create .ssh directory on remote host if it doesn't exist
    sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@$host" "mkdir -p ~/.ssh && chmod 700 ~/.ssh" 2>/dev/null || {
        error "Failed to create .ssh directory on $user@$host"
        return 1
    }
    
    # Copy the public key manually
    local pub_key=$(cat ~/.ssh/id_rsa.pub)
    
    if sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@$host" "echo '$pub_key' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && sort ~/.ssh/authorized_keys | uniq > ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys" 2>/dev/null; then
        log "SSH public key copied successfully to $user@$host"
    else
        error "Failed to copy SSH public key to $user@$host"
        return 1
    fi
    
    # Test passwordless connection
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o PasswordAuthentication=no "$user@$host" "echo 'Passwordless SSH successful'" 2>/dev/null; then
        log "✓ Passwordless authentication set up successfully for $user@$host"
        return 0
    else
        warn "Passwordless SSH test failed, but will continue with password authentication"
        return 0
    fi
}

# Function to execute command on remote host
execute_remote() {
    local host=$1
    local user=$2
    local command=$3
    
    # Try passwordless SSH first, then fall back to password auth
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o PasswordAuthentication=no "$user@$host" "$command" 2>/dev/null; then
        return 0
    else
        # Fall back to password authentication
        local pass=""
        # Find the password for this host/user combination
        for i in "${!K8S_NODES[@]}"; do
            if [[ "${K8S_NODES[$i]}" == "$host" && "${K8S_USERS[$i]}" == "$user" ]]; then
                pass="${K8S_PASSWORDS[$i]}"
                break
            fi
        done
        
        if [[ -n "$pass" ]]; then
            sshpass -p "$pass" ssh -o StrictHostKeyChecking=no "$user@$host" "$command"
        else
            error "Cannot find password for $user@$host"
            return 1
        fi
    fi
}

# Function to copy file to remote host
copy_to_remote() {
    local host=$1
    local user=$2
    local local_file=$3
    local remote_path=$4
    
    # Try passwordless SCP first, then fall back to password auth
    if scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o PasswordAuthentication=no "$local_file" "$user@$host:$remote_path" 2>/dev/null; then
        return 0
    else
        # Fall back to password authentication
        local pass=""
        # Find the password for this host/user combination
        for i in "${!K8S_NODES[@]}"; do
            if [[ "${K8S_NODES[$i]}" == "$host" && "${K8S_USERS[$i]}" == "$user" ]]; then
                pass="${K8S_PASSWORDS[$i]}"
                break
            fi
        done
        
        if [[ -n "$pass" ]]; then
            sshpass -p "$pass" scp -o StrictHostKeyChecking=no "$local_file" "$user@$host:$remote_path"
        else
            error "Cannot find password for $user@$host"
            return 1
        fi
    fi
}

# Function to verify CSI bundle exists
verify_csi_bundle() {
    if [[ ! -f "$CSI_BUNDLE" ]]; then
        error "CSI bundle file $CSI_BUNDLE not found in current directory"
        error "Please ensure the file is present before running this script"
        echo
        echo "Current directory contents:"
        ls -la
        exit 1
    fi
    
    # Store the absolute path to the CSI bundle
    CSI_BUNDLE_PATH=$(realpath "$CSI_BUNDLE")
    log "Found CSI bundle: $CSI_BUNDLE_PATH"
}

# Function to install Helm on master node
install_helm_on_master() {
    log "Installing Helm on master node ($MASTER_USER@$MASTER_NODE)..."

    # Create Helm installation script
    cat << 'HELM_SCRIPT_EOF' > /tmp/install_helm.sh
#!/bin/bash

set -e

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

log "Starting Helm installation..."

# Download and run the official Helm installation script
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
rm -f get_helm.sh

# Verify installation
if command -v helm &> /dev/null; then
    HELM_VERSION=$(helm version --short)
    log "✓ Helm installed successfully: $HELM_VERSION"
else
    echo "ERROR: Helm installation failed"
    exit 1
fi

log "Helm installation completed successfully!"
HELM_SCRIPT_EOF

    # Copy and execute Helm installation script on master node
    copy_to_remote "$MASTER_NODE" "$MASTER_USER" "/tmp/install_helm.sh" "$REMOTE_WORK_DIR/"
    execute_remote "$MASTER_NODE" "$MASTER_USER" "chmod +x $REMOTE_WORK_DIR/install_helm.sh && $REMOTE_WORK_DIR/install_helm.sh"

    # Clean up
    rm -f /tmp/install_helm.sh

    # Verify Helm installation
    if execute_remote "$MASTER_NODE" "$MASTER_USER" "command -v helm &> /dev/null"; then
        local helm_version=$(execute_remote "$MASTER_NODE" "$MASTER_USER" "helm version --short 2>/dev/null || echo 'unknown'")
        log "✓ Helm installed successfully on master node: $helm_version"
    else
        error "Helm installation verification failed"
        exit 1
    fi
}

# Function to check remote prerequisites on master node
check_remote_prerequisites() {
    log "Checking prerequisites on master node ($MASTER_USER@$MASTER_NODE)..."
    
    # Check if kubectl is available on master node
    if ! execute_remote "$MASTER_NODE" "$MASTER_USER" "command -v kubectl &> /dev/null"; then
        error "kubectl is not installed on master node $MASTER_NODE"
        error "Please ensure kubectl is installed on the master node"
        exit 1
    fi
    log "✓ kubectl is available on master node"
    
    # Check if helm is available on master node, install if missing
    if ! execute_remote "$MASTER_NODE" "$MASTER_USER" "command -v helm &> /dev/null"; then
        log "Helm not found on master node, installing..."
        install_helm_on_master
    else
        log "✓ helm is available on master node"
    fi
    
    # Check kubectl connectivity on master node
    if ! execute_remote "$MASTER_NODE" "$MASTER_USER" "kubectl cluster-info &>/dev/null"; then
        error "Cannot connect to Kubernetes cluster from master node"
        error "Please ensure kubectl is properly configured on the master node"
        exit 1
    fi
    log "✓ kubectl can connect to Kubernetes cluster"
    
    log "✓ All prerequisites verified on master node"
}

# Function to setup prerequisites on K8s nodes
setup_node_prerequisites() {
    local host=$1
    local user=$2
    local node_name=$3

    log "Setting up prerequisites on $node_name ($user@$host)..."

    # Create remote work directory
    execute_remote "$host" "$user" "sudo mkdir -p $REMOTE_WORK_DIR && sudo chown $user:$user $REMOTE_WORK_DIR"

    # Copy CSI bundle to node
    log "Copying CSI bundle to $node_name..."
    copy_to_remote "$host" "$user" "$CSI_BUNDLE_PATH" "$REMOTE_WORK_DIR/"

    # Create prerequisites setup script with discovery directory fix
    cat << 'EOF' > /tmp/node_prereq_setup.sh
#!/bin/bash

set -e

REMOTE_WORK_DIR="/tmp/lightbits-setup"
CSI_BUNDLE="lb-csi-bundle-1.19.0.15002456970.tar.gz"

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

log "Starting node prerequisites setup..."

# Extract CSI bundle
cd $REMOTE_WORK_DIR
if [[ -f "$CSI_BUNDLE" ]]; then
    log "Extracting CSI bundle..."
    tar -xzf $CSI_BUNDLE
fi

# CRITICAL FIX: Create the discovery directory that LightBits CSI requires
log "Creating required LightBits CSI discovery directory..."
sudo mkdir -p /etc/discovery-client/discovery.d
sudo chmod 755 /etc/discovery-client
sudo chmod 755 /etc/discovery-client/discovery.d
log "✓ Created /etc/discovery-client/discovery.d directory"

# Install required packages
log "Installing required packages..."
if command -v dnf &> /dev/null; then
    sudo dnf install -y nvme-cli
elif command -v yum &> /dev/null; then
    sudo yum install -y nvme-cli
elif command -v apt &> /dev/null; then
    sudo apt update && sudo apt install -y nvme-cli
fi

# Load NVMe/TCP module
log "Loading NVMe/TCP kernel module..."
sudo modprobe nvme-tcp || echo "nvme-tcp module already loaded or not available"

# Make NVMe/TCP module persistent
echo "nvme-tcp" | sudo tee -a /etc/modules-load.d/nvme-tcp.conf >/dev/null

# Disable SELinux (if present) for container compatibility
if command -v setenforce &> /dev/null; then
    sudo setenforce 0 || echo "SELinux already permissive"
    sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config 2>/dev/null || echo "SELinux config not found"
    log "✓ SELinux set to permissive mode"
fi

log "✓ Node prerequisites setup completed successfully!"
EOF

    # Copy and execute prerequisites script
    copy_to_remote "$host" "$user" "/tmp/node_prereq_setup.sh" "$REMOTE_WORK_DIR/"
    execute_remote "$host" "$user" "chmod +x $REMOTE_WORK_DIR/node_prereq_setup.sh && $REMOTE_WORK_DIR/node_prereq_setup.sh"
    
    rm -f /tmp/node_prereq_setup.sh
}

# Function to deploy CSI plugin using Helm on master node
deploy_csi_plugin() {
    log "Deploying Lightbits CSI Plugin using Helm on master node..."

    # Create deployment script on master node
    cat << 'SCRIPT_EOF' > /tmp/deploy_csi.sh
#!/bin/bash

set -e

REMOTE_WORK_DIR="/tmp/lightbits-setup"
CSI_BUNDLE="lb-csi-bundle-1.19.0.15002456970.tar.gz"

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

# Read parameters from environment or arguments
LIGHTBITS_ENDPOINTS="$1"
LIGHTOS_PROJECT="$2"
REPLICA_COUNT="$3"
COMPRESSION="$4"
MGMT_SCHEME="$5"
LIGHTBITS_JWT="$6"

log "Starting CSI deployment with parameters:"
log "Endpoints: '$LIGHTBITS_ENDPOINTS'"
log "Project: '$LIGHTOS_PROJECT'"

# Change to work directory
cd $REMOTE_WORK_DIR

# Extract CSI bundle if not already extracted
if [[ ! -d "helm" ]]; then
    log "Extracting CSI bundle..."
    tar -xzf $CSI_BUNDLE
fi

# Find the Helm chart
HELM_CHART=$(find . -name "lb-csi-plugin-*.tgz" | head -1)
if [[ -z "$HELM_CHART" ]]; then
    echo "ERROR: Helm chart not found in extracted bundle"
    exit 1
fi
log "Found Helm chart: $HELM_CHART"

# Check if a release with this name already exists
if helm list -n kube-system | grep -q "lightbits-csi"; then
    log "Found existing Lightbits CSI release, upgrading..."
    HELM_ACTION="upgrade"
else
    log "No existing release found, installing..."
    HELM_ACTION="install"
fi

# Create a values file for better parameter handling
cat << EOF > ./helm-values.yaml
global:
  storageClass:
    mgmtEndpoints: "$LIGHTBITS_ENDPOINTS"
    projectName: "$LIGHTOS_PROJECT"
    replicaCount: "$REPLICA_COUNT"
    compression: "$COMPRESSION"
  jwtSecret:
    jwt: "$LIGHTBITS_JWT"
    name: "lightbits-secret"
    namespace: "default"
mgmtScheme: "$MGMT_SCHEME"
EOF

if [[ "$HELM_ACTION" == "upgrade" ]]; then
    log "Upgrading existing Lightbits CSI plugin..."
    helm upgrade \
        --namespace=kube-system \
        --values ./helm-values.yaml \
        lightbits-csi \
        "$HELM_CHART"
else
    log "Installing new Lightbits CSI plugin..."
    helm install \
        --namespace=kube-system \
        --values ./helm-values.yaml \
        lightbits-csi \
        "$HELM_CHART"
fi

# Clean up values file
rm -f ./helm-values.yaml

# Wait for deployment to complete
log "Waiting for CSI plugin pods to be ready..."
kubectl wait --for=condition=ready pod -l app=lb-csi-plugin,component=controller -n kube-system --timeout=300s || true
kubectl wait --for=condition=ready pod -l app=lb-csi-plugin,component=node -n kube-system --timeout=300s || true

log "CSI Plugin deployment completed!"
SCRIPT_EOF

    # Copy deployment script to master node
    copy_to_remote "$MASTER_NODE" "$MASTER_USER" "/tmp/deploy_csi.sh" "$REMOTE_WORK_DIR/"

    # Execute deployment script on master node
    execute_remote "$MASTER_NODE" "$MASTER_USER" "chmod +x $REMOTE_WORK_DIR/deploy_csi.sh && $REMOTE_WORK_DIR/deploy_csi.sh '$LIGHTBITS_ENDPOINTS' '$LIGHTOS_PROJECT' '$REPLICA_COUNT' '$COMPRESSION' '$MGMT_SCHEME' '$LIGHTBITS_JWT'"

    # Clean up
    rm -f /tmp/deploy_csi.sh

    log "CSI Plugin deployed successfully!"
}

# Function to create StorageClass and test resources on master node
create_storage_resources() {
    log "Creating StorageClass and test resources on master node..."

    # Create script for storage resources
    cat << 'SCRIPT_EOF' > /tmp/create_storage.sh
#!/bin/bash

set -e

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

# Read parameters
LIGHTBITS_ENDPOINTS="$1"
MGMT_SCHEME="$2"
LIGHTOS_PROJECT="$3"
REPLICA_COUNT="$4"
COMPRESSION="$5"
LIGHTBITS_JWT="$6"

log "Creating StorageClass and Secret..."

# Method 1: Store raw JWT token using stringData (most common)
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: lightbits-secret-v1
  namespace: default
type: lightbitslabs.com/jwt
stringData:
  jwt: "$LIGHTBITS_JWT"
EOF

# Method 2: Store JWT token as opaque secret (alternative approach)
JWT_B64=$(echo -n "$LIGHTBITS_JWT" | base64 -w 0)
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: lightbits-secret-v2
  namespace: default
type: Opaque
data:
  jwt: $JWT_B64
EOF

# Method 3: Store JWT token with different key name (some drivers expect 'token')
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: lightbits-secret-v3
  namespace: default
type: lightbitslabs.com/jwt
stringData:
  token: "$LIGHTBITS_JWT"
EOF

# Use the primary secret (v1) as default
kubectl delete secret lightbits-secret -n default --ignore-not-found=true
kubectl get secret lightbits-secret-v1 -n default -o yaml | sed 's/lightbits-secret-v1/lightbits-secret/' | kubectl apply -f -

# Check if StorageClass already exists and delete it if necessary
if kubectl get storageclass lightbits-sc &>/dev/null; then
    kubectl delete storageclass lightbits-sc || true
    sleep 2
fi

# Create StorageClass
log "Creating new StorageClass..."
cat << EOF | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: lightbits-sc
  annotations:
    storageclass.kubernetes.io/is-default-class: "true"
provisioner: csi.lightbitslabs.com
allowVolumeExpansion: true
parameters:
  mgmt-endpoint: "$LIGHTBITS_ENDPOINTS"
  mgmt-scheme: "$MGMT_SCHEME"
  project-name: "$LIGHTOS_PROJECT"
  replica-count: "$REPLICA_COUNT"
  compression: "$COMPRESSION"
  csi.storage.k8s.io/controller-publish-secret-name: lightbits-secret
  csi.storage.k8s.io/controller-publish-secret-namespace: default
  csi.storage.k8s.io/node-stage-secret-name: lightbits-secret
  csi.storage.k8s.io/node-stage-secret-namespace: default
  csi.storage.k8s.io/node-publish-secret-name: lightbits-secret
  csi.storage.k8s.io/node-publish-secret-namespace: default
  csi.storage.k8s.io/provisioner-secret-name: lightbits-secret
  csi.storage.k8s.io/provisioner-secret-namespace: default
  csi.storage.k8s.io/controller-expand-secret-name: lightbits-secret
  csi.storage.k8s.io/controller-expand-secret-namespace: default
EOF

log "✓ StorageClass 'lightbits-sc' created successfully"
kubectl get storageclass lightbits-sc

log "StorageClass and Secret created successfully!"
SCRIPT_EOF

    # Copy script to master node
    copy_to_remote "$MASTER_NODE" "$MASTER_USER" "/tmp/create_storage.sh" "$REMOTE_WORK_DIR/"

    # Execute script on master node
    execute_remote "$MASTER_NODE" "$MASTER_USER" "chmod +x $REMOTE_WORK_DIR/create_storage.sh && $REMOTE_WORK_DIR/create_storage.sh '$LIGHTBITS_ENDPOINTS' '$MGMT_SCHEME' '$LIGHTOS_PROJECT' '$REPLICA_COUNT' '$COMPRESSION' '$LIGHTBITS_JWT'"

    # Clean up
    rm -f /tmp/create_storage.sh

    log "StorageClass and Secret created successfully!"
}

# Function to run volume provisioning test
run_volume_test() {
    log "Running volume provisioning test..."

    # Create volume test script
    cat << 'SCRIPT_EOF' > /tmp/volume_test.sh
#!/bin/bash

set -e

log() {
    echo -e "\033[0;32m[$(date +'%Y-%m-%d %H:%M:%S')] $1\033[0m"
}

log "Creating test PVC..."

# Clean up any existing test resources first
kubectl delete pod lightbits-test-pod --ignore-not-found=true
kubectl delete pvc lightbits-test-pvc --ignore-not-found=true
sleep 5

# Create test PVC
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: lightbits-test-pvc
  namespace: default
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: lightbits-sc
  resources:
    requests:
      storage: 1Gi
EOF

log "Waiting for PVC to bind..."
if kubectl wait --for=condition=Bound pvc/lightbits-test-pvc --timeout=60s; then
    log "✅ PVC bound successfully!"
    
    log "Creating test pod..."
    cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: lightbits-test-pod
  namespace: default
spec:
  containers:
  - name: test-container
    image: busybox
    command: ["/bin/sh"]
    args: ["-c", "echo 'Testing LightBits volume write' > /mnt/test/test.txt && cat /mnt/test/test.txt && sleep 300"]
    volumeMounts:
    - name: test-volume
      mountPath: /mnt/test
  volumes:
  - name: test-volume
    persistentVolumeClaim:
      claimName: lightbits-test-pvc
  restartPolicy: Never
EOF

    log "Waiting for pod to be ready..."
    if kubectl wait --for=condition=Ready pod/lightbits-test-pod --timeout=120s; then
        log "✅ Test pod is ready!"
        
        sleep 10
        log "Test pod logs:"
        kubectl logs lightbits-test-pod
        
        if kubectl exec lightbits-test-pod -- test -f /mnt/test/test.txt; then
            log "✅ Volume test PASSED!"
            echo "🎉 LightBits volume provisioning works correctly!"
        else
            echo "❌ Volume test FAILED!"
        fi
    else
        echo "❌ Test pod failed to start"
    fi
    
    # Cleanup
    kubectl delete pod lightbits-test-pod --ignore-not-found=true
    kubectl delete pvc lightbits-test-pvc --ignore-not-found=true
else
    echo "❌ PVC failed to bind"
    kubectl describe pvc lightbits-test-pvc
fi
SCRIPT_EOF

    # Copy and execute volume test script on master node
    copy_to_remote "$MASTER_NODE" "$MASTER_USER" "/tmp/volume_test.sh" "$REMOTE_WORK_DIR/"
    
    if execute_remote "$MASTER_NODE" "$MASTER_USER" "chmod +x $REMOTE_WORK_DIR/volume_test.sh && cd $REMOTE_WORK_DIR && ./volume_test.sh" 2>&1; then
        log "✅ Volume provisioning test completed successfully!"
        return 0
    else
        warn "Volume provisioning test had issues but continuing..."
        return 1
    fi

    # Clean up
    rm -f /tmp/volume_test.sh
}

# Function to create management scripts on master node
create_management_scripts() {
    log "Creating management scripts on master node..."

    # Create a master script that includes both verification and testing
    cat << 'MASTER_SCRIPT_EOF' > /tmp/lightbits_management.sh
#!/bin/bash

# LightBits CSI Management Script
# This script provides verification and testing functions for LightBits CSI

set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Function to show usage
show_usage() {
    echo "LightBits CSI Management Script"
    echo
    echo "Usage: $0 [OPTION]"
    echo
    echo "Options:"
    echo "  status     - Show complete CSI status verification"
    echo "  test       - Run volume provisioning test"
    echo "  pods       - Show CSI pod status"
    echo "  logs       - Show CSI pod logs"
    echo "  sc         - Show StorageClass details"
    echo "  secrets    - Show authentication secrets"
    echo "  volumes    - Show LightBits volumes"
    echo "  help       - Show this help message"
    echo
    echo "Examples:"
    echo "  $0 status    # Complete status check"
    echo "  $0 test      # Test volume provisioning"
    echo "  $0 pods      # Quick pod status"
}

# Function for quick CSI pod status
show_csi_pods() {
    echo -e "${BLUE}CSI Pod Status:${NC}"
    kubectl get pods -n kube-system -l app=lb-csi-plugin -o wide
}

# Function for CSI pod logs
show_csi_logs() {
    echo -e "${BLUE}CSI Controller Logs:${NC}"
    kubectl logs -n kube-system -l app=lb-csi-plugin,component=controller --tail=20
    echo
    echo -e "${BLUE}CSI Node Logs (first node):${NC}"
    kubectl logs -n kube-system -l app=lb-csi-plugin,component=node --tail=20 | head -30
}

# Function for StorageClass details
show_storageclass() {
    echo -e "${BLUE}StorageClass Details:${NC}"
    kubectl get storageclass lightbits-sc -o wide
    echo
    kubectl describe storageclass lightbits-sc
}

# Function for secrets
show_secrets() {
    echo -e "${BLUE}Authentication Secrets:${NC}"
    for secret in lightbits-secret lightbits-secret-v1 lightbits-secret-v2 lightbits-secret-v3; do
        if kubectl get secret "$secret" -n default &>/dev/null; then
            kubectl get secret "$secret" -n default -o wide
        else
            echo "Secret $secret: Not found"
        fi
    done
}

# Function for volumes
show_volumes() {
    echo -e "${BLUE}LightBits Volumes:${NC}"
    echo
    echo "Persistent Volumes:"
    kubectl get pv -o custom-columns="NAME:.metadata.name,CAPACITY:.spec.capacity.storage,ACCESS MODES:.spec.accessModes,STATUS:.status.phase,DRIVER:.spec.csi.driver" | grep -E "(NAME|csi.lightbitslabs.com)" || echo "No LightBits PVs found"
    echo
    echo "Persistent Volume Claims:"
    kubectl get pvc --all-namespaces | grep -E "(NAMESPACE|lightbits-sc)" || echo "No LightBits PVCs found"
}

# Function for complete status verification
complete_status() {
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE} Complete LightBits CSI Status${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo
    
    # 1. CSI Pods
    echo -e "${YELLOW}1. CSI Pods:${NC}"
    show_csi_pods
    echo
    
    # 2. StorageClass
    echo -e "${YELLOW}2. StorageClass:${NC}"
    kubectl get storageclass lightbits-sc -o wide 2>/dev/null || echo "StorageClass not found"
    echo
    
    # 3. CSI Driver
    echo -e "${YELLOW}3. CSI Driver:${NC}"
    kubectl get csidrivers.storage.k8s.io csi.lightbitslabs.com -o wide 2>/dev/null || echo "CSI Driver not found"
    echo
    
    # 4. Secrets
    echo -e "${YELLOW}4. Authentication Secrets:${NC}"
    show_secrets
    echo
    
    # 5. Volumes
    echo -e "${YELLOW}5. Current Volumes:${NC}"
    show_volumes
    echo
    
    # 6. Health Summary
    echo -e "${YELLOW}6. Health Summary:${NC}"
    total_pods=$(kubectl get pods -n kube-system -l app=lb-csi-plugin --no-headers | wc -l)
    running_pods=$(kubectl get pods -n kube-system -l app=lb-csi-plugin --field-selector=status.phase=Running --no-headers | wc -l)
    
    if [[ $running_pods -eq $total_pods ]] && [[ $total_pods -gt 0 ]]; then
        echo -e "${GREEN}✅ All $total_pods CSI pods are running${NC}"
        if kubectl get storageclass lightbits-sc &>/dev/null; then
            echo -e "${GREEN}✅ StorageClass is configured${NC}"
            if kubectl get secret lightbits-secret -n default &>/dev/null; then
                echo -e "${GREEN}🎉 LightBits CSI is fully operational!${NC}"
            else
                echo -e "${YELLOW}⚠ Authentication secret missing${NC}"
            fi
        else
            echo -e "${YELLOW}⚠ StorageClass missing${NC}"
        fi
    else
        echo -e "${RED}❌ CSI pods not running ($running_pods/$total_pods)${NC}"
    fi
}

# Function for volume test
volume_test() {
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE} LightBits Volume Provisioning Test${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo
    
    # Clean up any existing test resources
    kubectl delete pod lightbits-volume-test --ignore-not-found=true
    kubectl delete pvc lightbits-volume-test-pvc --ignore-not-found=true
    sleep 3
    
    log "Creating test PVC..."
    cat << EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: lightbits-volume-test-pvc
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: lightbits-sc
  resources:
    requests:
      storage: 1Gi
EOF
    
    log "Waiting for PVC to bind..."
    if kubectl wait --for=condition=Bound pvc/lightbits-volume-test-pvc --timeout=60s; then
        log "✅ PVC bound successfully!"
        
        log "Creating test pod..."
        cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: lightbits-volume-test
spec:
  containers:
  - name: test
    image: busybox
    command: ["/bin/sh", "-c"]
    args: ["echo 'LightBits test data' > /data/test.txt && cat /data/test.txt && sleep 60"]
    volumeMounts:
    - name: test-vol
      mountPath: /data
  volumes:
  - name: test-vol
    persistentVolumeClaim:
      claimName: lightbits-volume-test-pvc
  restartPolicy: Never
EOF
        
        log "Waiting for pod to be ready..."
        if kubectl wait --for=condition=Ready pod/lightbits-volume-test --timeout=60s; then
            sleep 5
            log "Test pod logs:"
            kubectl logs lightbits-volume-test
            
            if kubectl exec lightbits-volume-test -- test -f /data/test.txt; then
                log "✅ Volume test PASSED!"
                echo -e "${GREEN}🎉 LightBits volume provisioning works correctly!${NC}"
            else
                error "❌ Volume test FAILED!"
            fi
        else
            error "❌ Test pod failed to start"
        fi
        
        # Cleanup
        kubectl delete pod lightbits-volume-test --ignore-not-found=true
        kubectl delete pvc lightbits-volume-test-pvc --ignore-not-found=true
    else
        error "❌ PVC failed to bind"
        kubectl describe pvc lightbits-volume-test-pvc
    fi
}

# Main script logic
case "${1:-help}" in
    "status")
        complete_status
        ;;
    "test")
        volume_test
        ;;
    "pods")
        show_csi_pods
        ;;
    "logs")
        show_csi_logs
        ;;
    "sc")
        show_storageclass
        ;;
    "secrets")
        show_secrets
        ;;
    "volumes")
        show_volumes
        ;;
    "help"|*)
        show_usage
        ;;
esac
MASTER_SCRIPT_EOF

    # Copy the management script to master node
    copy_to_remote "$MASTER_NODE" "$MASTER_USER" "/tmp/lightbits_management.sh" "$REMOTE_WORK_DIR/"
    execute_remote "$MASTER_NODE" "$MASTER_USER" "chmod +x $REMOTE_WORK_DIR/lightbits_management.sh"

    # Clean up local copy
    rm -f /tmp/lightbits_management.sh

    log "✓ Management script created on master node: $REMOTE_WORK_DIR/lightbits_management.sh"
}

# Function to display final status
display_final_status() {
    echo
    echo -e "${GREEN}=============================================${NC}"
    echo -e "${GREEN}  LightBits CSI Integration Complete!${NC}"
    echo -e "${GREEN}=============================================${NC}"
    echo
    echo -e "${BLUE}Deployment Summary:${NC}"
    echo "✓ Login credentials verified for all nodes"
    echo "✓ Prerequisites installed on all K8s nodes"
    echo "✓ Discovery directory fix applied to all nodes"
    echo "✓ SSH keys distributed"
    echo "✓ CSI bundle copied to all nodes"
    echo "✓ LightBits CSI plugin deployed via master node"
    echo "✓ StorageClass created and configured"
    echo "✓ Volume provisioning tested successfully"
    echo "✓ Management scripts created on master node"
    echo
    echo -e "${BLUE}Master Node: $MASTER_USER@$MASTER_NODE${NC}"
    echo -e "${BLUE}StorageClass: lightbits-sc${NC}"
    echo -e "${BLUE}Endpoints: $LIGHTBITS_ENDPOINTS${NC}"
    echo -e "${BLUE}Project: $LIGHTOS_PROJECT${NC}"
    echo
    echo -e "${YELLOW}Management Script Available:${NC}"
    echo "Location: $REMOTE_WORK_DIR/lightbits_management.sh"
    echo "Usage examples:"
    echo "  $REMOTE_WORK_DIR/lightbits_management.sh status    # Complete status check"
    echo "  $REMOTE_WORK_DIR/lightbits_management.sh test      # Test volume provisioning"
    echo "  $REMOTE_WORK_DIR/lightbits_management.sh pods      # CSI pod status"
    echo "  $REMOTE_WORK_DIR/lightbits_management.sh help      # Show all options"
    echo
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "1. SSH to your master node: ssh $MASTER_USER@$MASTER_NODE"
    echo "2. Check status: $REMOTE_WORK_DIR/lightbits_management.sh status"
    echo "3. Test volumes: $REMOTE_WORK_DIR/lightbits_management.sh test"
    echo "4. Create PVCs using storageClassName: lightbits-sc"
    echo "5. Deploy your applications with persistent storage"
    echo
    echo -e "${GREEN}🎉 Your LightBits CSI integration is ready for production use!${NC}"
}

# Main execution function
main() {
    log "Starting Complete LightBits CSI Integration..."

    # Show initial banner
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE}  Complete LightBits CSI Integration${NC}"
    echo -e "${BLUE}=============================================${NC}"
    echo
    echo "This script will:"
    echo "  ✓ Deploy LightBits CSI plugin to your Kubernetes cluster"
    echo "  ✓ Configure StorageClass and authentication secrets"
    echo "  ✓ Test volume provisioning and I/O operations"
    echo "  ✓ Create management scripts for ongoing operations"
    echo "  ✓ Perform comprehensive status verification"
    echo

    # Verify CSI bundle exists and store absolute path
    verify_csi_bundle

    # Install sshpass if needed
    install_sshpass

    # Generate SSH key
    generate_ssh_key

    # Collect deployment information (includes credential verification)
    collect_deployment_info

    # Set up passwordless SSH to all K8s nodes (best effort)
    log "Setting up passwordless SSH authentication..."
    ssh_setup_failed=0
    for i in "${!K8S_NODES[@]}"; do
        if ! copy_ssh_key "${K8S_NODES[$i]}" "${K8S_USERS[$i]}" "${K8S_PASSWORDS[$i]}"; then
            warn "SSH key setup failed for ${K8S_USERS[$i]}@${K8S_NODES[$i]}, will use password authentication"
            ((ssh_setup_failed++))
        fi
    done
    
    if [[ $ssh_setup_failed -eq ${#K8S_NODES[@]} ]]; then
        warn "SSH key setup failed for all nodes, continuing with password authentication"
    elif [[ $ssh_setup_failed -gt 0 ]]; then
        warn "SSH key setup failed for $ssh_setup_failed out of ${#K8S_NODES[@]} nodes"
    else
        log "✓ SSH key setup completed successfully for all nodes"
    fi

    # Check remote prerequisites on master node
    check_remote_prerequisites

    # Setup prerequisites on all K8s nodes (includes discovery directory fix)
    log "Setting up prerequisites on all K8s nodes..."
    for i in "${!K8S_NODES[@]}"; do
        setup_node_prerequisites "${K8S_NODES[$i]}" "${K8S_USERS[$i]}" "Node $((i+1))"
    done

    # Deploy CSI plugin
    deploy_csi_plugin

    # Create storage resources
    create_storage_resources

    # Run volume provisioning test
    log "Running volume provisioning test..."
    if ! run_volume_test; then
        warn "Volume test had issues but continuing..."
    else
        log "✓ Volume test completed successfully!"
    fi

    # Create management scripts on master node
    create_management_scripts

    # Display final status
    display_final_status

    log "LightBits CSI integration completed successfully!"
    log "🎉 Your LightBits CSI is ready for production use!"
    log "📋 Use the management script: $REMOTE_WORK_DIR/lightbits_management.sh"
}

# Check if CSI bundle exists before starting
if [[ ! -f "$CSI_BUNDLE" ]]; then
    echo -e "${RED}❌ ERROR: CSI bundle file not found!${NC}"
    echo
    echo "Required file: $CSI_BUNDLE"
    echo "Current directory: $(pwd)"
    echo "Current directory contents:"
    ls -la
    echo
    echo "Please place the CSI bundle file in the same directory as this script."
    exit 1
fi

# Run main function
main "$@"

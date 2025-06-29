# LightBits Kubernetes CSI Integration

Complete automated deployment script for LightBits CSI plugin in Kubernetes.

## Prerequisites

- Kubernetes cluster with kubectl access
- SSH access to all Kubernetes nodes (with passwords)
- LightBits CSI bundle: `lb-csi-bundle-1.19.0.15002456970.tar.gz`
- Lightbits cluster with management endpoints and JWT token

## Installation

### 1. Download Script

```bash
git clone https://github.com/gagan-lb/lightbits-K8-csi-integration.git
cd lightbits-K8-csi-integration
chmod +x lightbits-k8-CSI-integration.sh
```

### 2. Add CSI Bundle

```bash
# Place your CSI bundle in the same directory
cp /path/to/lb-csi-bundle-1.19.0.15002456970.tar.gz .
```

### 3. Run Script

```bash
./lightbits-k8-CSI-integration.sh
```

The script will prompt you for:
- Kubernetes node IPs, usernames, and passwords
- Lightbits management endpoints (format: `ip1:port,ip2:port,ip3:port`)
- JWT token
- Storage configuration

## After Installation

### Check Status
```bash
# SSH to your master node
ssh user@master-node

# Check CSI status
/tmp/lightbits-setup/lightbits_management.sh status

# Test volume provisioning
/tmp/lightbits-setup/lightbits_management.sh test
```

### Create Storage
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: my-storage
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: lightbits-sc
  resources:
    requests:
      storage: 10Gi
```

## Management Commands

```bash
# Available on master node at /tmp/lightbits-setup/lightbits_management.sh
./lightbits_management.sh status    # Complete status check
./lightbits_management.sh test      # Test volume provisioning  
./lightbits_management.sh pods      # Show CSI pods
./lightbits_management.sh help      # Show all options
```

## Troubleshooting

```bash
# Check CSI pods
kubectl get pods -n kube-system -l app=lb-csi-plugin

# Check storage class
kubectl get storageclass lightbits-sc

# View CSI logs
kubectl logs -n kube-system -l app=lb-csi-plugin,component=controller
```



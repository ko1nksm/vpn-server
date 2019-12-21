# VPN Server

Easily deploy OpenVPN Server on Google Cloud Platform

## Usage

### 1. Create your gcs bucket and configuration

```
gsutil mb -c standard -l us-central1 gs://YOUR-CONFIGURATION-BUCKT-NAME
```

Directory structure (This is example. **Please create those files.**)

```
gs://YOUR-CONFIGURATION-BUCKT-NAME
├── ddclient/
│     └── ddclient.conf
└── openvpn/
       ├── server.conf, ca.crt, dh.pem, openvpn.crt, openvpn.key, ta.key
       └── ccd/
              └── network1, network2, macbook, iphone
```


### 2. Create a configuration file for deployment manager

**vpn-server.yaml** (without health check)

```yaml
imports:
- path: startup-script.sh
- path: vpn-server.yaml.jinja # or vpn-server-hc.yaml.jinja (with healthcheck)
  name: vpn-server.jinja

resources:
- name: vpn-server
  type: vpn-server.jinja
  properties:
    machineType: f1-micro
    zone: us-central1-f
    networkTier: PREMIUM

    configurationBucket: YOUR-CONFIGURATION-BUCKT-NAME
    editMode: false # If true, mount gcs bucket with gcsfuse
    allowSSH: true
    allowStatusPage: true # OpenVPN status page: http://ddns.example.com
    antiRobotAuth: user:password # Basic Authentication for OpenVPN status page
    ddclient: # Default: https://github.com/ddclient/ddclient/archive/v3.9.0.tar.gz
    ddns-update-interval: # Default: none (e.g. 1week)
```

### 3. Deploy VPN Server

```
gcloud deployment-manager deployments create vpn-server --config vpn-server.yaml
```

### 4. Delete VPN Server

```
gcloud deployment-manager deployments delete vpn-deployment
```

## Example

### Network

```
+---------- VPN Server on GCP (ddns.example.com, 172.16.0.1) ----------+
| VPN Network: 172.16.0.0/24                                           |
|                                                                      |
|    +-- network1 (172.16.0.A) --+    +-- network2 (172.16.0.B) --+    |
|    | 192.168.1.0/24            |    | 192.168.2.0/24            |    |
|    |                           |    |                           |    |
|    +---------------------------+    +---------------------------+    |
|                                                                      |
|    macbook (172.16.0.C)    iphone (172.16.0.D)                       |
|                                                                      |
+----------------------------------------------------------------------+
```

### server.conf

```conf
# Service
verb 4
passtos

# Networking
dev tun
persist-key
persist-tun
topology subnet
keepalive 10 30
route 192.168.1.0 255.255.255.0 # network1
route 192.168.2.0 255.255.255.0 # network2

# VPN
proto udp4
server 172.16.0.0 255.255.255.0
compress lz4-v2
push "compress lz4-v2"
client-to-client
client-config-dir /etc/openvpn/server/ccd

# Cryptography
auth SHA512
cipher AES-256-GCM
ncp-ciphers AES-256-GCM
tls-server
tls-version-min 1.2
tls-auth /etc/openvpn/server/ta.key 0
ca /etc/openvpn/server/ca.crt
dh /etc/openvpn/server/dh.pem
cert /etc/openvpn/server/openvpn.crt
key /etc/openvpn/server/openvpn.key

script-security 2
up /usr/local/share/openvpn/up.sh
down /usr/local/share/openvpn/down.sh
```

### ccd

network1

```conf
iroute 192.168.1.0 255.255.255.0
push "route 192.168.2.0 255.255.255.0"
```


network2

```conf
iroute 192.168.2.0 255.255.255.0
push "route 192.168.1.0 255.255.255.0"
```

macbook, iphone

```conf
push "route 192.168.1.0 255.255.255.0"
push "route 192.168.2.0 255.255.255.0"
push "dhcp-option DNS 192.168.1.0"
push "dhcp-option DOMAIN home"
```

### ddclient.conf

See https://github.com/ddclient/ddclient

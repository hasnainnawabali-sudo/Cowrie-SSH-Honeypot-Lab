
# Cowrie SSH Honeypot Lab & Telemetry Analysis

A full-stack cybersecurity lab environment deploying an emulated **Cowrie SSH Honeypot** on Ubuntu Server to capture, log, and analyze automated SSH brute-force attacks originating from Kali Linux.

---

## Architecture & Network Design

To safely isolate administrative SSH access while baiting automated scanners, native management access was relocated from standard port `22` to `22222`. Standard port `22` was then funneled down to Cowrie via kernel-level `iptables` NAT redirection rules.

[ Attacker: Kali Linux ]
│
├──► SSH Port 22 ──► [ IPTables NAT Redirection ] ──► [ Cowrie Honeypot (Port 2222) ]
│
[ Admin: Local Host ]
│
└──► SSH Port 22222 ─────────────────────────────► [ Native Ubuntu SSHD ]

---

## Port Mapping & Hardening

| Service | Port | Description |
| :--- | :--- | :--- |
| **Native SSHD** | `22222/TCP` | Protected administrative SSH login bound via custom drop-in configuration (`/etc/ssh/sshd_config.d/99-custom-port.conf`). |
| **Honeypot Trap** | `22/TCP` | Exposed entry point forwarding incoming connection attempts directly into Cowrie. |
| **Cowrie Daemon** | `2222/TCP` | Internal non-privileged Python environment running Cowrie under system user `cowrie`. |

---

## Deployment Steps

### 1. Hardening Native SSH Access
Relocated administrative SSH access to prevent lockouts during honeypot deployment:
```bash
echo "Port 22222" | sudo tee /etc/ssh/sshd_config.d/99-custom-port.conf
sudo systemctl restart ssh

2. Installing Cowrie Dependencies & Environment
Created a dedicated service user and isolated virtual environment:

Bash
sudo adduser --disabled-password cowrie
sudo su - cowrie
git clone [https://github.com/cowrie/cowrie.git](https://github.com/cowrie/cowrie.git)
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip && pip install -e .
cp src/cowrie/data/etc/cowrie.cfg.dist etc/cowrie.cfg
cowrie start

3. IPTables NAT Redirection Rules
Applied packet redirection to route port 22 traffic into Cowrie's unprivileged port 2222:

Bash
# External traffic redirection
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Local loopback redirection
sudo iptables -t nat -A OUTPUT -p tcp -o lo --dport 22 -j REDIRECT --to-port 2222

Attack Simulation & Telemetry Analysis
Attack Execution (Kali Linux)
Simulated an automated credential stuffing attack using Hydra targeting default port 22:

Bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP> -s 22 -t 4 -V
Telemetry Analysis
Parsed structured events from cowrie.json using custom Python automation scripts:

Bash
python3 parse_cowrie.py
Key Security Takeaways
Port Obfuscation: Relocating administrative SSH to port 22222 drastically reduced baseline log noise from internet-wide scanning bots.

Telemetry Value: Cowrie provides high-fidelity attack telemetry, capturing full session keystrokes, downloaded malware payloads, and password dictionaries.

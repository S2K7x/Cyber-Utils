## Multi-Protocol Auth Scanner 

A high-performance Bash script designed for automated credential testing across multiple protocols (SMB, SSH, RDP). It features multi-threading and automatic "post-success" actions to gather immediate intelligence from compromised hosts.


---

### Key Features

* **Multi-Threaded Performance**: Scans up to 30 hosts simultaneously for rapid network coverage.
* **Automatic Post-Exploitation**:
* **SMB**: Automatically lists accessible shares.
* **SSH**: Instantly retrieves machine hostname and user ID.
* **RDP**: Validates access for GUI sessions.


* **Intelligent Port Checking**: Performs a quick TCP handshake before attempting heavy authentication to save time.
* **Ready-to-Use Commands**: On success, the script generates the exact command needed to connect (e.g., `xfreerdp` or `smbclient` strings).

---

### Quick Start

#### 1. Basic Scan

Run the scanner against a specific IP or a CIDR range:

```bash
./auth_scanner.sh 192.168.1.0/24 admin Password123

```

#### 2. Prerequisites

The script relies on common security tools. Ensure they are installed:

```bash
sudo apt install nmap smbclient sshpass freerdp2-x11

```

---

### How It Works

| Component | Logic |
| --- | --- |
| **Targeting** | Uses `nmap` for host discovery or falls back to a ping sweep. |
| **Concurrency** | Manages a background worker pool to ensure high throughput. |
| **Validation** | Uses `timeout` to prevent hung connections on unresponsive ports. |
| **Reporting** | Provides a clean summary of "Pwned" hosts and ready-to-copy connection commands. |

---

### Workflow Example

1. **Launch**: `./auth_scanner.sh 10.10.10.0/24 user1 secretPass`
2. **Detection**: The script identifies port 22 is open on `10.10.10.5`.
3. **Authentication**: Attempts SSH login.
4. **Auto-Action**: Login succeeds! The script immediately runs `id` and `hostname` on the target and displays the result in the console.
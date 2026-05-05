# LureGuard.ai — Wazuh Setup Guide

How to get Wazuh Manager + Agent running from scratch on your machine.

---

## What you need

| Machine | Role | OS |
|---|---|---|
| Your laptop/desktop | Runs Docker (Wazuh Manager) | Mac / Linux / Windows (WSL2) |
| Ubuntu VM | Target being monitored (Wazuh Agent) | Ubuntu 22.04 or 24.04 |

Both machines must be on the same local network.

---

## Part 1 — Mac/Host: Start Wazuh Manager

### Step 1 — Start the manager

```bash
docker compose up -d
```

Wait 30 seconds then verify:

```bash
docker exec -it wazuh-manager /var/ossec/bin/wazuh-control status
```

These must be running:
```
wazuh-remoted is running...
wazuh-analysisd is running...
wazuh-db is running...
wazuh-integratord is running...
```

If anything is not running:
```bash
docker logs wazuh-manager --tail 30
```

---

## Part 2 — Ubuntu VM: Install Wazuh Agent

SSH into your Ubuntu VM, then:

### Step 3 — Install the agent (version must match manager)

```bash
sudo apt-get install -y wazuh-agent=4.14.5-1
```

---

## Part 3 — Connect Agent to Manager

### Step 4 — Register the agent on the Manager

On your host machine:

```bash
docker exec -it wazuh-manager /var/ossec/bin/manage_agents
```

```
Choose: A
Agent name: ubuntu-target
Agent IP: any
Agent ID: 001
Confirm: y

Choose: E
Agent ID: 001
→ copy the entire base64 key string that appears
Q
```

### Step 5 — Import the key on the Ubuntu VM

```bash
sudo /var/ossec/bin/manage_agents
```

```
Choose: I
Paste the full key from Step 4
Confirm: y
Q
```

### Step 6 — Deploy the agent config

Find your host machine's IP:
```bash
ip a
```

update the IP address inside agent-ossec.conf to use your host IP at : 
```xml
    <server>
      <address>192.168.1.107</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
```

Copy the config from the repo to the VM:
```bash
# run this from repo root on your host machine
scp wazuh/agent-ossec.conf ubuntu@<VM-IP>:/tmp/ossec.conf
```

On the Ubuntu VM:
```bash
sudo cp /tmp/ossec.conf /var/ossec/etc/ossec.conf
sudo chmod 640 /var/ossec/etc/ossec.conf
sudo chown root:wazuh /var/ossec/etc/ossec.conf

# Verify
sudo grep -A3 "<server>" /var/ossec/etc/ossec.conf
```

### Step 7 — Start the agent

```bash
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent
sudo systemctl status wazuh-agent
```

Must show `Active: active (running)`.

---

## Part 4 — integratord

integratord runs inside the Manager and forwards every matching alert to LureGuard Core via HTTP POST to `http://lureguard-core:8080/wazuh/event`.

It forwards alerts from these groups: `authentication_failed`, `authentication_success`, `sshd`, `syscheck`, `rootcheck`, `lureguard_custom`.

### Verify it is running

```bash
docker exec -it wazuh-manager /var/ossec/bin/wazuh-control status | grep integratord
# wazuh-integratord is running...
```

### Watch its activity

```bash
docker exec -it wazuh-manager tail -f /var/ossec/logs/ossec.log | grep integrat
```

Right now it will show connection errors to `lureguard-core:8080` — that is expected, LureGuard Core is not built yet (Sprint 2). It retries automatically until Core is up.

---

## Part 5 — Verify Everything Works

### Step 8 — Check agent is Active

On your host machine, wait 30 seconds after starting the agent:

```bash
docker exec -it wazuh-manager /var/ossec/bin/agent_control -l
```

Expected:
```
ID: 000, Name: <manager>, IP: 127.0.0.1, Active/Local
ID: 001, Name: ubuntu-target, IP: any, Active
```

`Unknown` means the agent has not connected yet — wait 30 more seconds and retry.

### Step 9 — Test SSH events

From your Mac:
```bash
ssh wronguser@<VM-IP>
# type any wrong password a few times
```

Watch alerts in real time:
```bash
docker exec -it wazuh-manager \
    tail -f /var/ossec/logs/alerts/alerts.json | grep -E "sshd|authentication"
```

Rule `5710` should appear within 2 seconds. Rule `5712` (brute force) fires after several attempts.

### Step 10 — Test FIM events

On the Ubuntu VM:
```bash
sudo touch /etc/lureguard-test
```

On your host machine:
```bash
docker exec -it wazuh-manager \
    tail -f /var/ossec/logs/alerts/alerts.json | grep syscheck
```

---

## Common errors

| Error | Cause | Fix |
|---|---|---|
| `wazuh-remoted: CRITICAL: Remoted connection is not configured` | Missing `<remote>` block in manager `ossec.conf` | Check `wazuh/ossec.conf` has the `<remote>` block |
| `No valid server IP found` | Wrong or empty `<address>` in agent `ossec.conf` | Redo Step 6 with the correct Mac IP |
| `ossec.conf` is empty on VM | Pipe to `tee` failed silently | Use `scp` as shown in Step 6 |
| Agent shows `Unknown` | Key not imported yet or agent just started | Wait 60s, re-import key (Step 5) if still Unknown |
| `Cannot find queue/db/wdb` | `wazuh-db` not running | `docker compose down && docker compose up -d` |
| `sudo: a terminal is required` | sudo without `-S` flag | `echo 'pass' \| sudo -S <command>` |

---

## Useful commands

```bash
# Real-time alerts
docker exec -it wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json

# Manager internal logs
docker exec -it wazuh-manager tail -f /var/ossec/logs/ossec.log

# integratord activity
docker exec -it wazuh-manager tail -f /var/ossec/logs/ossec.log | grep integrat

# Agent logs (on VM)
sudo tail -f /var/ossec/logs/ossec.log

# List connected agents
docker exec -it wazuh-manager /var/ossec/bin/agent_control -l

# All manager processes status
docker exec -it wazuh-manager /var/ossec/bin/wazuh-control status
```
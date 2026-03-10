ให้ รัน ไฟล์ cosvinte.py  จะไปเรียกไฟล์ช่องโหว่ต่างๆ

โปรเจคนี้เป็น script ตรวจสอบ cve ของ linux  โดยเปรียบเทียบเวอร์ชั่น และมีการให้คะแนนCVSS และสร้าง Report เป็นไฟล์ PDF


## Installation
```
python3 -m pip install venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run
```
python3 cosvinte.py
```


## Installation
```
python3 -m pip install venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run
```
python3 cosvinte.py
```

# COSVINTE — Docker Test Suite

ทดสอบ scanner ใน 2 environments เพื่อวัด **True Positive** และ **False Positive**

---

## โครงสร้างไฟล์

```
COSVINTE/
├── docker-compose.yml
├── Dockerfile.clean          ← Container 1: Ubuntu 24.04 (hardened)
├── Dockerfile.vuln           ← Container 2: Ubuntu 20.04 (vulnerable)
├── docker/
│   ├── entrypoint_clean.sh
│   └── entrypoint_vuln.sh
├── reports/
│   ├── clean/                ← PDF จาก container 1
│   └── vuln/                 ← PDF จาก container 2
├── cosvinte.py
├── core/
└── scanners/
```

---

## วิธีใช้งาน

### รันทั้งสองพร้อมกัน (แนะนำ)
```bash
docker compose up --build
```

### รัน container เดียว
```bash
# False Positive test เท่านั้น
docker compose up --build cosvinte-clean

# True Positive test เท่านั้น
docker compose up --build cosvinte-vuln
```

### เปิด shell เข้าไปทดสอบเอง
```bash
# Shell แบบ interactive
docker compose run cosvinte-vuln bash
docker compose run cosvinte-clean bash

# รัน scanner ด้วยตัวเอง
python3 cosvinte.py --analyze
python3 cosvinte.py --caps
python3 cosvinte.py --kernel
```

### ดู PDF reports
```bash
# Windows path (WSL)
ls reports/clean/
ls reports/vuln/

# เปิดด้วย explorer (Windows)
explorer.exe reports\\vuln
```

---

## ช่องโหว่ที่ปลูกไว้ใน Container 2 (Vulnerable)

| ID | ช่องโหว่ | Scanner ที่ต้องจับได้ | Expected Chain |
|----|---------|----------------------|----------------|
| W1 | `/etc/passwd` world-writable (chmod 666) | Writable Paths | CHAIN-004 |
| W2 | `/var/log/cron` world-writable | Cron CVE | CHAIN-001 |
| W3 | `/tmp/backup.sh` world-writable + cron root job | Cron + Writable | CHAIN-001 |
| C2 | `/tmp` อยู่ใน `$PATH` ก่อน `/usr/bin` | PATH Hijack | CHAIN-002 |
| P1 | `cap_setuid` บน python3-cap | Capabilities | CHAIN-003 |
| S1 | `testuser ALL=(ALL) NOPASSWD:ALL` | PATH Hijack | — |
| K1 | ASLR disabled (`randomize_va_space=0`) | Risk Scoring | CHAIN-005 |

---

## สิ่งที่คาดหวัง

### Container 1 (Clean) — False Positive = 0
```
✔  /etc/passwd — ไม่ flag (chmod 644)
✔  /var/log/cron.log — ไม่ flag (chmod 640)
✔  capabilities — ไม่มี cap_setuid
✔  cron scripts — ไม่ world-writable
✔  PDF — generate ได้สำเร็จ
```

### Container 2 (Vulnerable) — True Positive = 7/7
```
✖  CRITICAL: /etc/passwd world-writable
✖  HIGH:     /var/log/cron world-writable
✖  CRITICAL: /tmp/backup.sh writable cron script
✖  HIGH:     /tmp in PATH
✖  CRITICAL: cap_setuid on interpreter
✖  HIGH:     sudo ALL NOPASSWD
✖  HIGH:     ASLR disabled (score boost)

⚡  Attack Chains: CHAIN-001, CHAIN-003, CHAIN-004
🛡  Remediation: IMMEDIATE actions generated
📄  PDF: saved to reports/vuln/
```

---

## Troubleshooting

### PDF ไม่ถูกสร้าง
```bash
# ตรวจสอบ reportlab
python3 -c "import reportlab; print(reportlab.Version)"

# ติดตั้งใหม่ถ้าไม่มี
pip3 install reportlab --break-system-packages
```

### cap_setuid ไม่ทำงาน
```bash
# ตรวจสอบว่า libcap2-bin ติดตั้งอยู่
getcap /usr/local/bin/python3-cap

# ถ้าไม่มี ต้อง rebuild
docker compose build --no-cache cosvinte-vuln
```

### ASLR disable ไม่ได้ (sysctl: Permission denied)
เพิ่ม `privileged: true` ใน `docker-compose.yml` ใต้ `cosvinte-vuln` (มีอยู่แล้ว)
หรือรัน:
```bash
docker compose run --privileged cosvinte-vuln bash
```

### attack_chain / risk_scoring disabled
ตรวจสอบ folder structure:
```
core/attack_chain.py    ← ต้องมีไฟล์นี้
core/risk_scoring.py    ← ต้องมีไฟล์นี้
scanners/remediation.py ← ต้องมีไฟล์นี้
```


```
docker compose down --remove-orphans
```
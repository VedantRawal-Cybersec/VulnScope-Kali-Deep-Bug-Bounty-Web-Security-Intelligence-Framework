# Quickstart

## 1. Clone the repository

```bash
git clone https://github.com/VedantRawal-Cybersec/VulnScope-Kali-Deep-Bug-Bounty-Web-Security-Intelligence-Framework.git
cd VulnScope-Kali-Deep-Bug-Bounty-Web-Security-Intelligence-Framework
```

## 2. Install dependencies

```bash
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install -r requirements.txt
```

## 3. Run interactive mode

```bash
python3 vulnscope.py
```

## 4. Run direct target mode

Use only authorized targets.

```bash
python3 vulnscope.py --url https://example.com --mode passive --max-pages 20
```

## 5. Read reports

```bash
cat reports/output/target-report.md
cat reports/output/evidence.json
```

## Recommended legal test targets

Use local or intentionally vulnerable labs:

- OWASP Juice Shop
- DVWA
- PortSwigger Web Security Academy labs
- Your own test website
- Localhost applications

Do not scan third-party targets unless the asset is clearly in scope and the program policy allows automated testing.

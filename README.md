# VirusTotalTotal (VTTotal)
[![SecHack365](https://img.shields.io/badge/SecHack365-2020-ffd700.svg)](https://sechack365.nict.go.jp/)

- An hash-based obserbation tool of VirusTotal
  ![VTTotal](documents/images/vttotal_image.png)

# Installation
- requires **python3**, **pipenv** and **SQLite>=3.8.3**
- Recommend to use **pyenv**
```shell
# Install dependencies
$ pipenv sync

# Setting VT API Key
$ cp .env.example .env
# Add your API Key on .env file

# Create cron jobs
$ python manage.py crontab add

# launch server
$ pipenv shell
(VTTotal)$ python manage.py migrate
(VTTotal)$ python manage.py runserver 0.0.0.0:8000

# access localhost:8000 :-)
```

# Features of VTTotal
- Register malicious hash.
- Automatic rescan and gather reports on VirusTotal.
    - Recommend to use Enterprise API key due to request rate limit.
- Gather information and automatic tagging via [AVClass2](https://github.com/malicialab/avclass/).
- Show dynamics of detections by av-vendors and available engines.
- Entropy based suggestions of raw detection reports calculated from past family tagging.

# Why VTTotal?
## Background
- VirusTotal is an online malware detection tool which include about 70 antivirus engines.
- But [current research](https://www.usenix.org/conference/usenixsecurity20/presentation/zhu) shows that VirusTotal detection will "flips" over time.
- And if new malware has been detected, We should trigger rescan on several occasions.
- Ofcourse AV-vendors have no common rules to naming malware families, types and so on.

## Ambiguousness of VirusTotal
- We define 2 types of ambiguousness of VirusTotal reports.
    - **Detection Count** (Eg: 10/70, 1/70/, 15/30, ...)
    - **Reports by AV-vendors** (Eg: Trojan:Generic, Malware Ai Score=85,...)
- Our tool features  keep you from these ambiguousness.

# References
1. Zhu, S., Shi, J., Yang, L., Qin, B., Zhang, Z., Song, L., & Wang, G. (2020). Measuring and modeling the label dynamics of online anti-malware engines. In Proceedings of the 29th USENIX Security Symposium (pp. 2361-2378). (Proceedings of the 29th USE NIX Security Symposium). USENIX Association.

2. Silvia Sebastián, Juan Caballero. AVClass2: Massive Malware Tag Extraction from AV Labels. In proceedings of the Annual Computer Security Applications Conference, December 2020.

# License
This repository contains another repository which licensed by MIT LICENSE. So, [this repository is too](LICENSE).

# Acknowledgement
This software is one of deliverables of [SecHack365](https://sechack365.nict.go.jp/) program by NICT.
Thanks for trainers and trainees of SecHack365 2020.

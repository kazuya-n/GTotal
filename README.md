# VirusTotalTotal (VTTotal)
- An total obserbation tool of VirusTotal

## Why VTTotal?
- VirusTotal is an online malware detection tool which include about 70 antivirus engines
- But [current research](https://www.usenix.org/conference/usenixsecurity20/presentation/zhu) shows that VirusTotal detection will "flips" over time.
- And if new malware has been detected, We should trigger rescan on several occasions.

## Installation
- requires *python3* and *pipenv*
```
# Install dependencies
$ pipenv install --python 3
$ pipenv install

# Setting VT API Key
$ cp .env.example .env
# Add your API Key on .env file

# launch server
$ pipenv shell
$ python manage.py runserver

# access localhost:8000 :-)
```

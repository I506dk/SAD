# SAD - Splunk Automated Deployments

![Splunk](https://1.bp.blogspot.com/-wVC3ywgx27Q/X-3fGV_5vQI/AAAAAAAACNs/XrYlHc14D90YunEt6BPzn-prPuPcPxxtwCLcBGAsYHQ/s16000/Splunk_Enterprise_Security_Integration_Hero_Image.png)

#### A Python script to automate splunk deployments and make configurations as simple and straight forward as possible.

## Features
- Automatically scrapes Splunk's website so that all versions of Splunk are 
	avaliable for download.
- Provides SSH capabilities so that script only needs to be run from
	one machine.
- Sets up a deployment server to push apps to all other machines.
- Points all machines back to the deployment server.
- Python packages required can be installed by the script 
	if they are missing. No need to manually install packages.
- Supports Windows and Linux operating systems 
 
## Dependencies
[![Known Vulnerabilities](https://snyk.io/test/github/I506dk/SAD/badge.svg)](https://snyk.io/test/github/I506dk/SAD/)
- [BeautifulSoup](https://pypi.org/project/beautifulsoup4/) - Web page scraping library
- [Requests](https://pypi.org/project/requests/) - HTTP Library
- [Paramiko](https://www.paramiko.org/) - A pure python implementation of SSH
	
## Installation
**Download the latest release of python below:**

[![Python Latest](https://img.shields.io/badge/python-latest-blue.svg)](https://www.python.org/downloads/windows/)

**Download and install Pip using the following commands:**
```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```
**Dependencies can manually be installed using requirements.txt:**
```
pip install -r requirements.txt
```
**Or individually installed via Pip:**
```
pip install beautifulsoup4
pip install requests
pip install paramiko
```

## To Do:

- [x] Fetch all versions of Splunk Enterprise for download
- [x] Fetch all versions of the Splunk Forwarder
- [x] Download and install Splunk with respect to the OS
- [ ] Get a list of all apps on the Splunkbase site so that the user can install those as well
- [x] Add SSH to access all other machines in the deployment
- [ ] Configure best practices on each machine (Disable THP, etc.)
- [ ] Create directories and apps on the deployment server
- [ ] Point all other machines back to the deployment server
- [ ] Create output file of configuration created
- [ ] Allow loading of configuration files for reusability
- [ ] Add support for OSX

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
- [BeautifulSoup](https://pypi.org/project/beautifulsoup4/) - Web page scraping library
- [Requests](https://pypi.org/project/requests/) - HTTP Library
- [Paramiko](https://www.paramiko.org/) - A pure python implementation of SSH

	
## Installation
**Download the latest release of python below:**

[![Python](https://www.python.org/static/community_logos/python-powered-w-100x40.png)](https://www.python.org/downloads/)

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

- [x] Fetch all versions of Splunk for download
- [x] Download and install Splunk with respect to the OS
- [ ] Add SSH to access all other machines in the deployment
- [ ] Create directories and apps on the deployment server
- [ ] Point all other machines back to the deployment server
- [ ] Create output file of configuration created
- [ ] Allow loading of configuration files for reuseability
- [ ] Add support for OSX

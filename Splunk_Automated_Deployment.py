# Python script to autmatomate splunk deployments

# TO-DO:
# Setup deployment server(s) - This got messy quick. Windows 10 and Server need to be treated as two different OS's

# Download/install splunk on the other machines
# Teach all machines to phone home to deployment server
# Machines need to know what their purpose it (indexer, forwarder, heavyforwarder, etc.)
# Deployment server will issue necessary files and apps, so the templates need to be right

# Cheat and install pip packages if not already installed (Don't recommend this, but it is an option)
# The lazy way of setting up things, and it only assumes that python and pip are installed
# Possibly check to see if pip is installed as well. 

# These are part of the standard library
import os
import socket
import platform
import subprocess


# Function to instal packages via pip (aka Pip Cheat)
def install_library(package):
    # Run pip as a subprocess
    subprocess.call(['pip', 'install', package])

# Install missing packages
while True:
    try:
        # Import packages here
        import bs4
        import requests
        import paramiko
        break
    except Exception as e:
        Missing_Library = str(e).strip('No module named ')
        Missing_Library = Missing_Library.strip("'")
        install_library(Missing_Library)


# These must be manually installed, as they are not part of the standard library
import requests
import paramiko
from bs4 import BeautifulSoup


# Beginning of function declarations
# Function to scrape previous download links for splunk
def fetch_previous_links():
    # Site link to older downloads, if previous version(s) is/are needed
    Previous_Version_Link = 'https://www.splunk.com/en_us/download/previous-releases.html'
    
    # Get page and parse with beautifulsoup 
    Get_Page = requests.get(Previous_Version_Link)
    Page_Repsonse = Get_Page.text
    soup = BeautifulSoup(Page_Repsonse, 'html.parser')

    # Lists to keep up with links and versions
    link_list = []
    Previous_Versions = []
    
    # Look through all html for download links
    for link in soup.find_all("a"):
        # If download button is found, pull the link
        # For each link, get the os and the version
        if 'Download Now' in link.text:
            Download_Link = link['data-link']
            Start_Index = Download_Link.find('releases/') + len('releases/')
            
            if 'windows' in Download_Link:
                Stop_Index = Download_Link.find('/windows')
                Previous_Version = Download_Link[Start_Index:Stop_Index]
                link_list.append(Download_Link)
                if ['Windows', Previous_Version] not in Previous_Versions:
                    Previous_Versions.append(['Windows', Previous_Version])

            elif 'linux' in Download_Link:
                Stop_Index = Download_Link.find('/linux')
                Previous_Version = Download_Link[Start_Index:Stop_Index]
                link_list.append(Download_Link)
                if ['Linux', Previous_Version] not in Previous_Versions:
                    Previous_Versions.append(['Linux', Previous_Version])

            elif 'osx' in Download_Link:
                Stop_Index = Download_Link.find('/osx')
                Previous_Version = Download_Link[Start_Index:Stop_Index]
                link_list.append(Download_Link)
                if ['Osx', Previous_Version] not in Previous_Versions:
                    Previous_Versions.append(['Osx', Previous_Version])

            else:
                # Silently pass cause there shouldn't be anything else
                # And if there is, we don't need it anyway
                pass

    return link_list, Previous_Versions


# Function to scrape latest download links for splunk
def fetch_current_links():
    # Link to current/latest release of splunk
    Current_Version_Link = 'https://www.splunk.com/en_us/download/splunk-enterprise.html'

    # Get page and parse with beautifulsoup 
    Get_Page = requests.get(Current_Version_Link)
    Page_Repsonse = Get_Page.text
    soup = BeautifulSoup(Page_Repsonse, 'html.parser')

    # Lists to keep up with links and versions
    link_list = []
    Current_Versions = []
    
    # Look through all html for download links
    for link in soup.find_all("a"):
        # If download button is found, pull the link
        # For each link, get the os and the version
        if 'Download Now' in link.text:
            Download_Link = link['data-link']
            Start_Index = Download_Link.find('releases/') + len('releases/')
            
            if 'windows' in Download_Link:
                Stop_Index = Download_Link.find('/windows')
                Current_Version = Download_Link[Start_Index:Stop_Index]
                link_list.append(Download_Link)
                if ['Windows', Current_Version] not in Current_Versions:
                    Current_Versions.append(['Windows', Current_Version])

            elif 'linux' in Download_Link:
                Stop_Index = Download_Link.find('/linux')
                Current_Version = Download_Link[Start_Index:Stop_Index]
                link_list.append(Download_Link)
                if ['Linux', Current_Version] not in Current_Versions:
                    Current_Versions.append(['Linux', Current_Version])

            elif 'osx' in Download_Link:
                Stop_Index = Download_Link.find('/osx')
                Current_Version = Download_Link[Start_Index:Stop_Index]
                link_list.append(Download_Link)
                if ['Osx', Current_Version] not in Current_Versions:
                    Current_Versions.append(['Osx', Current_Version])

            else:
                # Silently pass cause there shouldn't be anything else
                # And if there is, we don't need it anyway
                pass

    # Print out versions
    print("Current Version for all Platforms: ")
    for version in Current_Versions:
        print(version[0] + ": " + version[1])
    
    # Return a list of links for version chosen
    return_list = []
    
    # Verify that the latest release is what needs to be used, else user needs to specify a version.
    while True:
        # Get user input to determine what version to use
        User_Input = input("Use latest version of Splunk for install? (y/n) ").lower()

        if User_Input == 'y' or User_Input == "yes":
            print("Continuing using version " + str() + "...")
            return_list = link_list
            
        elif User_Input == 'n' or User_Input == "no":   
            # Parse through links if version entered is valid
            old_links, old_releases = fetch_previous_links()
            # Prompt user for version, check if it is valid, and get respective links
            while True:
                Previous_Version = input("Please enter a previous version to use: ")
                # Keep up with found versions
                found_versions = []
                
                for version in old_releases:
                    current_version = str(version[1])
                    
                    if str(Previous_Version) == current_version:
                        found_versions.append(version)
                    
                if len(found_versions) > 0:
                    for version in found_versions:
                        print("Version " + Previous_Version + " found for " + str(version[0]) + ".")

                    while True:
                        User_Input = input("Continuing using version " + current_version + "? (y/n) ")
                    
                        if User_Input == 'y' or User_Input == "yes":
                            print("Continuing using version " + current_version + "...")
                            # Pull out links for specified version
                            concatenated_link = '/' + str(current_version) + '/'
                            # Return list of older links for chosen version
                            for link in old_links:
                                if concatenated_link in str(link):
                                    return_list.append(link)
                            break
                        elif User_Input == 'n' or User_Input == "no":
                            print("Well I am a bit lost... exiting...")
                            exit()
                        else:
                            print("Invalid answer. Use y/Y for yes, and n/N for no.")
                    break
                else:
                    print("Version " + str(Previous_Version) + " not found.")
        else:
            print("Invalid character used. Please use Y/y for yes or N/n for no.")
            continue
        break
    
    return return_list


# Get machine info to determine download type
def get_machine_info():

    # Get hostname of machine
    hostname = socket.gethostname()
    # Get local IP address
    local_ip = socket.gethostbyname(hostname)
    # Get current operating system
    os_type = platform.platform().lower()
    # Create variable for the file type
    os_extension = ''
    
    # Determine OS, and download respective packages
    if "windows" in os_type:
        print("Current Machine Details: " + platform.platform())
        # Download .msi
        os_extension = '.msi'
    elif ("redhat" in os_type) or ("fedora" in os_type) or ("centos" in os_type):
        print("Current Machine Details: " + platform.platform())
        # Download .rpm
        os_extension = '.rpm'  
    elif ("ubuntu" in os_type) or ("kali" in os_type) or ("parrot" in os_type):
        print("Current Machine Details: " + platform.platform())
        # Download .deb
        os_extension = '.deb'   
    elif "macos" in os_type:
        print("Current Machine Details: " + platform.platform())
        # Download .dmg
        os_extension = '.dmg'
    else:
        print("Unknown OS type: " + platform.platform())
        
    return hostname, local_ip, os_extension

   
# Download splunk with respect to the OS
def download_splunk(os_extension, links):
    # Separate links by their extension
    for link in links:
        if ("linux" in link) and (".deb" in link):
            Deb_Link = link
        if ("linux" in link) and (".rpm" in link):
            Rpm_Link = link
        if ("linux" in link) and (".tgz" in link):
            Linux_Tar_Link = link
        if ("windows" in link) and (".msi" in link):
            if "x64" in link:
                Msi_Link_64 = link
            elif "x86" in link:
                Msi_Link_86 = link
            else:
                pass
        if ("osx" in link) and (".dmg" in link):
            Dmg_Link = link
        if ("osx" in link) and (".tgz" in link):
            Osx_Tar_Link = link

    # Install the correct package based on the current OS
    if os_extension == ".deb":
        print("Starting .deb splunk download...")
        os.system("wget -O splunk.deb " + str(Deb_Link))
        print("Starting splunk install...")
        os.system("dpkg -i splunk.deb")
 
    elif os_extension == ".rpm":
        print("Starting .rpm splunk download...")
        os.system("wget -O splunk.rpm " + str(Rpm_Link))
        print("Starting splunk install...")
        os.system("rpm -ivh splunk.rpm")
    
    # Defaulting to x64 architecture currently for windows
    elif os_extension == ".msi":
        # Windows is a pain. Curl doesn't exist on windows server. Resort to powershell
        # Check to see if OS is a server version of windows or not.
        # 1 means we are not on a server version
        # 2 and 3 are server versions, one with AD, one without
        os_check = subprocess.check_output(["powershell.exe", "$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem; $osInfo.ProductType"])
        os_check = str(os_check.decode("utf-8"))
        os_check = os_check.replace('\n', '')
        os_check = os_check.replace('\r', '')
        
        # Get current directory
        Current_Directory = os.getcwd() + '\\'
        
        # MSI installer failure codes
        # 1625 - This installation is forbidden by system policy.
        
        # If os_check returns a 1, we can use powershell
        if os_check == '1':
            print("Starting .msi splunk download...")
            os.system("curl " + str(Msi_Link_64) + " --output splunk.msi")
            print("Starting splunk install...")
            install = os.system("msiexec /i " + Current_Directory + "splunk.msi AGREETOLICENSE=Yes LOGON_USERNAME='username' LOGON_PASSWORD='password' LAUNCHSPLUNK=0 SPLUNKUSERNAME='username' SPLUNKPASSWORD='password' /l*v C:\\tmp\\SplunkInstall.log /quiet")
            print("Install code:", install)
        # Otherwise, default to powershell commands
        else:
            print("Starting .msi splunk download...")
            subprocess.check_output(["powershell.exe", "Invoke-WebRequest -Uri '", Msi_Link_64, "' -OutFile splunk.msi"])
            print("Starting splunk install...")
            install = os.system("msiexec /i " + Current_Directory + "splunk.msi AGREETOLICENSE=Yes LOGON_USERNAME='username' LOGON_PASSWORD='password' LAUNCHSPLUNK=0 SPLUNKUSERNAME='username' SPLUNKPASSWORD='password' /l*v C:\\tmp\\SplunkInstall.log /quiet")
            print("Install code:", install)

    # Osx will probably need to be manually installed as well
    # No idea how osx works
    elif os_extension == ".dmg":
        print("Starting .dmg splunk download...")
        #os.system("curl " + str(Msi_Link) + " --output splunk.msi")
        print("Starting splunk install...")
        Current_Directory = os.getcwd() + '\\'
        #os.system("msiexec /i " + Current_Directory + "splunk.msi")

    else:
        print("OS is probably unknown. Nothing downloaded.")
        
    return

###########################################################
# Function to login to ssh service for a given ip or hostname
def ssh_connect(hostname, username, password, port=22):
    # setup ssh client, and set key policies (for unknown hosts mainly)
    client = paramiko.SSHClient()
    #client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Set default timeout
    banner_timeout = 10
    
    # Establish connection, run commands, and return command(s) output
    try:
        client.connect(hostname, port, username, password, banner_timeout=banner_timeout)
        ssh_session = client.get_transport()
            
        # Run commands and return output
        stdin, stdout, stderr = client.exec_command('uname -a')
        print(repr(stdout.read()))
        stdin, stdout, stderr = client.exec_command('ls')
        print(repr(stdout.read()))
        
        session = ssh_session.open_session()
        session.set_combine_stderr(True)
        session.get_pty()
        
        # Sudo
        session.exec_command('sudo -k dmesg')
        stdin = session.makefile('wb', -1)
        stdout = session.makefile('rb', -1)
        
        # Check to see if password is needed
        stdin.write(password +'\n')
        stdin.flush()
        for line in stdout.read().splitlines():        
            print(line)

        stdin.close()
        stdout.close()
        stderr.close()
        client.close      
    
    # Catch errors for failed login, or connection rejection
    except paramiko.ssh_exception.AuthenticationException as err:
        print("Authentication Error. Incorrect login credentials.")
    except paramiko.ssh_exception.SSHException as err1:
        print("Too many requests, or not enough resources. Implementing rate limiting.")
        banner_timeout += 2
    except TimeoutError as err2:
        print("Connection attempt timed out.")
    
    # Close client when done
    client.close
    
    return


########################################################################
# Beginning of main
if __name__ == '__main__':
    # Get current version links for all platforms
    Current_Links = fetch_current_links()

##### For this machine (deployment server) #############################

    # Get current machine info
    Current_Hostname, Current_IP, Current_Extension = get_machine_info()
    
    # Download and install splunk
    download_splunk(Current_Extension, Current_Links)
    
########## For Testing #################################################
    hostname = '192.168.0.10'
    username = "user"
    password = "pass"
    
    # ssh into machines, install splunk, create any necessary files,
    # point machine back to deployment server
    #ssh_connect(hostname, username, password)

    # Print exit message
    print("My work here is done. Splunk deployment exiting...")
    exit()


# Future file contents

# splunkd.service
"""
#/etc/systemd/system/
[Unit]
Description=Splunk indexer service
Wants=network.target
After=network.target

[Service]
Type=forking
Restart=always
RestartSec=30s
User=splunk
Group=splunk
ExecStart=/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt
ExecStop=/opt/splunk/bin/splunk stop
ExecReload=/opt/splunk/bin/splunk restart
LimitNOFILE=65535
LimitNPROC=16384
PIDFile=/opt/splunk/var/run/splunk/splunkd.pid

[Install]
WantedBy=multi-user.target
"""

# Indexer server.conf
"""
[replication_port://8080]

[clustering]
master_uri = https://vmcm01.frh.onestreamcloud.com:8089
mode = peer
pass4SymmKey = <pass>
"""





# At least one of each type of machine
# Typical setup to cover all the bases
# 2 search heads
# deployment server
# cluster master
# heavy forwarder
# 2 indexers

                ###### INDEXERS ######
# On each indexer, enable CLI, and restart
# CLI command: splunk enable listen 9997 -auth <username>:<password>

                ###### FOWARDERS ######
# On each forwarder, create a deploymentclient.conf file
# that points back to the deployment server
# etc/system/local/deploymentclient.conf file:
"""
   [deployment-client]

   [target-broker:deploymentServer]
   # Specify the deployment server; for example, "10.1.2.4:8089".
   targetUri= <URI:port> 
"""

             ###### DEPLOYMENT SERVER ######
# Create directories for deployment apps (Dev and Prod)
# Create server classes for the forwarders
# Forwarder will receive a server class, and two apps:
# One for input (inputs.conf) and output (outputs.conf)
# Create server class file etc/system/local/serverclass.conf


#     Indexers
#        ^
#        |
# Deployment Clients (Forwarders)
#        ^
#        |
#  Server Classes 
#        ^  
#        |
# Deployment Server

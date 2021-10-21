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
# Remove pip packages and purge
# Check permissions
"""
/opt/splunk/etc/
chown -R splunk:splunk

HF
/opt/splunk/etc/
chown -R root:root
"""
# for tarballs just decompress them where you want them to live

# Scrape splunk apps
# https://splunkbase.splunk.com/apps/#/product/splunk/

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
    print("Getting previous splunk release links...")

    # Site link to older downloads, if previous version(s) is/are needed
    Previous_Version_Link = 'https://www.splunk.com/en_us/download/previous-releases.html'
    # Site link to older downloads, if previous version(s) is/are needed (splunk forwarder)
    Forwarder_Link_Old = 'https://www.splunk.com/en_us/download/previous-releases/universalforwarder.html'
    
    # Get page and parse with beautifulsoup 
    Get_Page = requests.get(Previous_Version_Link)
    Page_Repsonse = Get_Page.text
    soup = BeautifulSoup(Page_Repsonse, 'html.parser')
    
    # Get page and parse with beautifulsoup (For old forwarder releases)
    Forwarder_Page_Old = requests.get(Forwarder_Link_Old)
    Forwarder_Repsonse_Old = Forwarder_Page_Old.text
    forwarder_soup_old = BeautifulSoup(Forwarder_Repsonse_Old, 'html.parser')

    # Lists to keep up with links and versions
    link_list = []
    forwarders_list = []
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
    
    # Look through all html for download links (Old forwarder links)
    # There are a lot of these...
    for link in forwarder_soup_old.find_all("a"):
        # If download button is found, pull the link
        # For each link, get the os and the version
        if 'Download Now' in link.text:
            Download_Link = link['data-link']
            forwarders_list.append(Download_Link)


    return link_list, Previous_Versions, forwarders_list


# Function to scrape latest download links for splunk
def fetch_current_links():
    print("Getting current splunk release links...")

    # Link to current/latest release of splunk enterprise
    Enterprise_Link = 'https://www.splunk.com/en_us/download/splunk-enterprise.html'
    # Link to current/latest release of splunk forwarder
    Forwarder_Link = 'https://www.splunk.com/en_us/download/universal-forwarder.html'
    Forwarder_Link_Old = 'https://www.splunk.com/en_us/download/previous-releases/universalforwarder.html'

    # Get page and parse with beautifulsoup
    Enterprise_Page = requests.get(Enterprise_Link)
    Enterprise_Repsonse = Enterprise_Page.text
    enterprise_soup = BeautifulSoup(Enterprise_Repsonse, 'html.parser')
    
    # Get page and parse with beautifulsoup (For forwarders)
    Forwarder_Page = requests.get(Forwarder_Link)
    Forwarder_Repsonse = Forwarder_Page.text
    forwarder_soup = BeautifulSoup(Forwarder_Repsonse, 'html.parser')

    # Lists to keep up with links and versions
    Enterprise_List = []
    Forwarder_List = []
    Current_Versions = []
    
    # Look through all html for download links
    for link in enterprise_soup.find_all("a"):
        # If download button is found, pull the link
        # For each link, get the os and the version
        if 'Download Now' in link.text:
            Download_Link = link['data-link']
            Start_Index = Download_Link.find('releases/') + len('releases/')
            
            if 'windows' in Download_Link:
                Stop_Index = Download_Link.find('/windows')
                Current_Version = Download_Link[Start_Index:Stop_Index]
                Enterprise_List.append(Download_Link)
                if ['Windows', Current_Version] not in Current_Versions:
                    Current_Versions.append(['Windows', Current_Version])

            elif 'linux' in Download_Link:
                Stop_Index = Download_Link.find('/linux')
                Current_Version = Download_Link[Start_Index:Stop_Index]
                Enterprise_List.append(Download_Link)
                if ['Linux', Current_Version] not in Current_Versions:
                    Current_Versions.append(['Linux', Current_Version])

            elif 'osx' in Download_Link:
                Stop_Index = Download_Link.find('/osx')
                Current_Version = Download_Link[Start_Index:Stop_Index]
                Enterprise_List.append(Download_Link)
                if ['Osx', Current_Version] not in Current_Versions:
                    Current_Versions.append(['Osx', Current_Version])

            else:
                # Silently pass cause there shouldn't be anything else
                # And if there is, we don't need it anyway
                pass
                
    # Look through all html for download links (Latest forwarder links)
    for link in forwarder_soup.find_all("a"):
        # If download button is found, pull the link
        # For each link, get the os and the version
        if 'Download Now' in link.text:
            Download_Link = link['data-link']
            Forwarder_List.append(Download_Link)

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
            print("Continuing using version " + str(Current_Versions[0][1]) + " ...")
            return_list = Enterprise_List
            
            # Get only the links for the version being used (In this case its the latest)
            for link in Forwarder_List:
                if str(Current_Versions[0][1]) in str(link):
                    return_list.append(link)
            
        elif User_Input == 'n' or User_Input == "no":   
            # Parse through links if version entered is valid
            old_links, old_releases, old_forwarders = fetch_previous_links()
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
                        User_Input = input("Continue using version " + current_version + "? (y/n) ")
                    
                        if User_Input == 'y' or User_Input == "yes":
                            print("Continuing using version " + current_version + "...")
                            # Pull out links for specified version
                            concatenated_link = '/' + str(current_version) + '/'
                            # Return list of older links for chosen version
                            for link in old_links:
                                if concatenated_link in str(link):
                                    return_list.append(link)
                            # Return list of older forwarder links for chosen version
                            for link in old_forwarders:
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


# Get links to the apps on splunk's site
def get_app_links():
    # App link
    App_Link = "https://splunkbase.splunk.com/app/"

    # Splunk app file (in same directory as splunk script)
    App_File = "Splunk_Apps.txt"
    
    print("Reading in known apps...")
    
    # Get already known apps
    Known_Apps = []
    # Read known apps from text file
    with open(App_File, 'r') as file:
        File_Contents = file.readlines()
        for line in File_Contents:
            Current_Line = line.replace('\n', '')
            Current_Line = Current_Line.split(',')
            if len(Current_Line) > 1:
                Current_Line[1] = Current_Line[1].strip()
                Known_Apps.append(Current_Line)
    file.close()

    # Keep up with app pages that are valid (ie. returned a 200 response)
    Valid_Apps = []
    # 4106 seems to be the first non archived app, so this will serve as a starting point
    # Set default app enumeratation limits
    Start = 4106
    Limit = 6000
    
    print("Starting enumeration of new apps (This will take some time...)")
    
    # If apps have been previously discovered, start there
    if len(Known_Apps) > 0:
        Last_App = (Known_Apps[-1][1]).replace(App_Link, '')
        Last_App = int(Last_App)
        Stop_App = Last_App + 500
        # Update enumeratation limits
        Start = Last_App
        Limit = Stop_App
    
    while Start < Limit:
        Possible_App = App_Link + str(Start)

        # Get page and parse with beautifulsoup
        App_Page = requests.get(Possible_App)
        Status = App_Page.status_code

        if Status == 200:
            app_soup = BeautifulSoup(App_Page.text, 'html.parser')
            App_Title = app_soup.title.string
            App_Title = App_Title.replace("| Splunkbase", '')
            App_Title = App_Title.strip()
            
            if "App Unavailable" not in App_Title:
                Valid_Apps.append([App_Title, Possible_App])
        Start += 1

    Newly_Found = 0

    # Write newly discovered apps to file
    with open(App_File, 'a+') as file:
        for app in Valid_Apps:
            if app not in Known_Apps: 
                file.write(app[0] + ", " + app[1] + '\n')
                Known_Apps.append(app)
                Newly_Found += 1
                
    print("Writing " + str(Newly_Found) + " newly found apps to file...") 
    file.close()

    print("Done with app enumeration.")
    
    return Known_Apps
    

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
# Need to differentiate between enterprise and forwarder...
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
        # 1603 - A fatal error occurred during installation.
        # 1622 - There was an error opening installation log file.
        # 1625 - This installation is forbidden by system policy.
        
        # If os_check returns a 1, we can use powershell
        if os_check == '1':
            print("Starting .msi splunk download...")
            os.system("curl " + str(Msi_Link_64) + " --output splunk.msi")
            print("Starting splunk install...")
            # LOGON Credentials are for the user that splunk needs to run as. (If different from the current user)
            # Launch Splunk tells splunk to run at boot (1) or not (0)
            # AGREETOLICENSE=Yes LOGON_USERNAME='username' LOGON_PASSWORD='password' LAUNCHSPLUNK=0 SPLUNKUSERNAME='username' SPLUNKPASSWORD='password' /l*v SplunkInstall.log /quiet
            install = os.system("msiexec /i " + Current_Directory + "splunk.msi AGREETOLICENSE=Yes SPLUNKUSERNAME='username' SPLUNKPASSWORD='password' /l*v SplunkInstall.log /quiet")
            if install == 0:
                print("Splunk install successful!")
            elif install == 1603:
                print("A fatal error occurred during installation.")
            elif install == 1622:
                print("There was an error opening installation log file.")
            elif install == 1625:
                print("This installation is forbidden by system policy.")
            else:
                print("Install failed with error code:", install)
        # Otherwise, default to powershell commands
        else:
            print("Starting .msi splunk download...")
            subprocess.check_output(["powershell.exe", "Invoke-WebRequest -Uri '", Msi_Link_64, "' -OutFile splunk.msi"])
            print("Starting splunk install...")
            install = os.system("msiexec /i " + Current_Directory + "splunk.msi AGREETOLICENSE=Yes SPLUNKUSERNAME='username' SPLUNKPASSWORD='password' /l*v SplunkInstall.log /quiet")
            if install == 0:
                print("Splunk install successful!")
            elif install == 1603:
                print("A fatal error occurred during installation.")
            elif install == 1622:
                print("There was an error opening installation log file.")
            elif install == 1625:
                print("This installation is forbidden by system policy. (Possible lack of privileges)")
            else:
                print("Install failed with error code:", install)
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
    # Load SSH host keys on current machine
    client.load_system_host_keys()
    # Reject unknown host keys (If unknown, there is potential for compromise)
    client.set_missing_host_key_policy(RejectPolicy)
    # AutoAdd will allow SSH session with unknown machine
    #client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
    #Current_Links = fetch_current_links()

    # Scrape Splunkbase site for apps and app links
    Current_Apps = get_app_links()

##### For this machine (deployment server) #############################

    # Get current machine info
    #Current_Hostname, Current_IP, Current_Extension = get_machine_info()
    
    # Download and install splunk
    #download_splunk(Current_Extension, Current_Links)
    
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
# ~/splunkforwarder/etc/system/local/deploymentclient.conf file:
"""
   [deployment-client]

   [target-broker:deploymentServer]
   # Specify the deployment server; for example, "10.1.2.4:8089".
   targetUri= <URI:port> 
"""

# ~/splunkforwarder/etc/system/local/authentication.conf
# Default authentication.conf file for forwarder
"""
    [splunk_auth]
    enablePasswordHistory = 0
    expireAlertDays = 15
    expirePasswordDays = 90
    expireUserAccounts = 0
    forceWeakPasswordChange = 0
    lockoutAttempts = 5
    lockoutMins = 30
    lockoutThresholdMins = 5
    lockoutUsers = 0
    minPasswordDigit = 0
    minPasswordLength = 1
    minPasswordLowercase = 0
    minPasswordSpecial = 0
    minPasswordUppercase = 0
    passwordHistoryCount = 24
"""

# ~/splunkforwarder/etc/system/local/outputs.conf
# Default outputs.conf file for forwarder
# Default port is 9997 on the forwarder outputs
"""
    [tcpout]
    defaultgroup = default-autolb-group
    
    [tcpout:default-autolb-group]
    server = {indexer_ip}:{port}
    
    [tcpout-server://{indexer_ip}:{port}]
"""

# ~/splunkforwarder/etc/system/local/server.conf
# Default server.conf file for forwarder
"""
    [general]
    serverName = {current_forwarder_hostname}
    pass4SymmKey = {ssl_key}
    
    [sslConfig]
    sslPassword = {ssl_password}
    
    [lmpool:auto_generated_pool_forwarder]
    description = auto_generated_pool_forwarder
    quota = Max
    slaves = *
    stack_id = free
"""

# ~/splunkforwarder/etc/system/local/web.conf
# Default web.conf file for forwarder
"""
    [settings]
    mgmtHostPort = 127.0.0.1:8090
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

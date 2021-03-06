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
from os import path


# Function to instal packages via pip (aka Pip Cheat)
def install_library(package):
    # Run pip as a subprocess
    subprocess.call(['pip', 'install', package])

# Install missing packages
while True:
    try:
        # Import packages here
        import bs4
        from bs4 import BeautifulSoup
        import requests
        import paramiko
        break
    except Exception as e:
        Missing_Library = str(e).strip('No module named ')
        Missing_Library = Missing_Library.strip("'")
        install_library(Missing_Library)
        

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


# Get links to the apps on splunk's site and save to text file
def update_app_links():
    # App link
    App_Link = "https://splunkbase.splunk.com/app/"

    # Splunk app file (in same directory as splunk script)
    App_File = "Splunk_Apps.txt"
    
    print("Reading in known apps...")
    # Get already known apps
    Known_Apps = []
    
    # Get current working directory
    Current_Directory = os.getcwd()
    # Full path to app file
    Full_Path = str(Current_Directory) + "\\" + str(App_File)
    # Check to see if file exists
    App_File_Existence = path.exists(Full_Path)
    
    if App_File_Existence == True:
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
    else:
        print("No app file found. Starting from scratch.")

    # Keep up with app pages that are valid (ie. returned a 200 response)
    Valid_Apps = []
    # 4106 seems to be the first non archived app, so this will serve as a starting point
    # Set default app enumeratation limits
    Start = 4106
    Limit = 6150
    
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
        
        # List of versions for the current app
        App_Versions = []

        if Status == 200:
            app_soup = BeautifulSoup(App_Page.text, 'html.parser')
            App_Title = app_soup.title.string
            App_Title = App_Title.replace("| Splunkbase", '')
            App_Title = App_Title.strip()
            
            if "App Unavailable" not in App_Title:
                for version in app_soup.find_all(id="release-option"):
                    # Get all ap versions, strip white spaces and append them to version list
                    versions = version.text.strip()
                    versions = versions.split('\n')
                    App_Versions.append(versions[0])
                
                # Create list of data for each app
                App_Data = [App_Title, Possible_App]
                for version in App_Versions:
                    App_Data.append(version)
            
                # Append Current app data
                Valid_Apps.append(App_Data)
        Start += 1

    Newly_Found = 0

    # Write newly discovered apps to file
    with open(App_File, 'a+') as file:
        for app in Valid_Apps:
            if app not in Known_Apps:
                Current_Line = ''
                # Write app title, link, and versions to file
                i = 0
                while i < len(app):
                    Current_Line += (str(app[i]))
                    if i != (len(app) - 1):
                        Current_Line += ", "
                    else:
                        Current_Line += '\n'
                    i += 1
                print(Current_Line)
                file.write(Current_Line)
                Newly_Found += 1
                
    print("Writing " + str(Newly_Found) + " newly found apps to file...") 
    file.close()
    print("Done with app enumeration.")
    
    return
    

# Read in all apps from text file, for user to specify a download
# Downloads are behind a saml login
'''
def load_apps():
    # Splunk app file (in same directory as splunk script)
    App_File = "Splunk_Apps.txt"
    
    print("Reading in known apps...")
    
    # Get already known apps
    Known_Apps = []
    
    # Get current working directory
    Current_Directory = os.getcwd()
    # Full path to app file
    Full_Path = str(Current_Directory) + "\\" + str(App_File)
    # Check to see if file exists
    App_File_Existence = path.exists(Full_Path)
    
    if App_File_Existence == True:
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
    else:
        print("No app file found. Please run -update to enumerate apps.")
        return
        
    if len(Known_Apps) > 0:
        print(str(len(Known_Apps)) + " apps loaded from file.")
    
    # Create a list of apps that potentially match the user search.
    Possible_Apps = []
    
    Current_App = input("Please enter an app name to download: ")
    for app in Known_Apps:
        if str(Current_App) == str(app[0]):
            Latest_Version = str(app[2])
            print("Found app " + str(app[0]) + ". Latest version is:" + Latest_Version)
            while True:
                Download_App = input("Download latest version of app? (y/n) ").lower()
                if (Download_App == 'y') or (Download_App == "yes"):
                    # Get app number from url
                    App_Number = str(app[1])
                    App_Number = App_Number.replace("https://splunkbase.splunk.com/app/", '')
                    # Get app name
                    App_Name = str(app[0])
                    # Download app
                    # Not implemented yet
                    print("Downloading app...")
                    #download_app(App_Number, Latest_Version, App_Name, username, password):
                    print("Done.")
                    break
                elif (Download_App == 'n') or (Download_App == "no"):
                    print("Skipping...")
                    break
                else:
                    # Other character entered.
                    print("Invalid response entered. Use y/Y for yes, and n/N for no.")
            
        elif str(Current_App) in str(app[0]):
            print("Did you mean: " + str(app[0]) + "?")
            Possible_Apps.append(app)
        else:
            pass

    return
'''    
    

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
    
    
# Function to read in hostnames/IPs, credentials, and roles for all machines involved
def read_in_roles():
    Deployment_Roles = []

    while True:
        # Ask user if they want to manually enter machine data or read in from file
        Read_File = input("Would you like to read in machine roles and credentials from text file? (y/n) ")
        
        if Read_File == 'y' or Read_File == "yes":
            # read in data from file
            print("File should be in csv format with each line containing: ")
            print("\nHostname,IP Address,Username:Password,Role,\n")

            while True:
                File_Path = input("Enter filename if in current directory, or complete filepath otherwise: ")
                # Make sure file/path exists
                File_Existence = path.exists(File_Path)
                # If file exists, open it and read in contents
                if File_Existence == True:
                    # Open file
                    with open(File_Path, 'r') as file:
                        File_Contents = file.readlines()
                        # Parse list in place
                        # Create nested list conataing information from each line in the text file
                        for index, item in enumerate(File_Contents):
                            File_Contents[index] = item.replace('\n', '')
                        
                        for index, item in enumerate(File_Contents):
                            File_Contents[index] = item.split(',')
                            
                        for index, item in enumerate(File_Contents):
                            for new_index, data in enumerate(item):
                                if len(data) == 0:
                                    del item[new_index]
                    # Close file and break out of loop
                    file.close()
                    Deployment_Roles = File_Contents
                    break
                else:
                    # If the file cannot be found, tell the user, and ask for input again
                    print("Cannot find path specified...")    
            break
        elif Read_File == 'n' or Read_File == "no":
            # ask user for each machine's data
            
            pass
            break
        else:
            print("Invalid answer. Use y/Y for yes, and n/N for no.")
    return Deployment_Roles

   
# Download splunk with respect to the OS
# Need to differentiate between enterprise and forwarder...
def download_splunk(os_extension, links):
    # Separate links by their extension
    for link in links:    
        if ("linux" in link) and (".deb" in link):
            if "splunkforwarder" not in link:
                Deb_Link = link
            else:
                Deb_Forwarder_Link = link
        if ("linux" in link) and (".rpm" in link):
            if "splunkforwarder" not in link:
                Rpm_Link = link
            else:
                Rpm_Forwarder_Link = link
        if ("linux" in link) and (".tgz" in link):
            if "splunkforwarder" not in link:
                Linux_Tar_Link = link
            else:
                Forwarder_Tar_Link = link
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
    # Most of these commands need to be run with sudo
    if os_extension == ".deb":
        print("Starting .deb splunk download...")
        os.system("wget -O splunk.deb " + str(Deb_Link))
        print("Starting splunk install...")
        os.system("dpkg -i splunk.deb")
        
        # Start splunk forwarder and auto accept license agreement
        os.system("cd /opt/splunk/bin; ./splunk start --accept-license --answer-yes --seed-passwd 'password'")
 
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
        print("Starting splunk install...")
        Current_Directory = os.getcwd() + '\\'

    else:
        print("OS is probably unknown. Nothing downloaded.")
        
    return

###########################################################
# Function to login to ssh service for a given ip or hostname
def ssh_connect(hostname, username, password, links, port=22):
    # setup ssh client, and set key policies (for unknown hosts mainly)
    client = paramiko.SSHClient()
    # Load SSH host keys on current machine
    client.load_system_host_keys()
    # Reject unknown host keys (If unknown, there is potential for compromise)
    #client.set_missing_host_key_policy(paramiko.RejectPolicy())
######### Figure out way to load current machine host keys ####################################
    # AutoAdd will allow SSH session with unknown machine (For first time connecting)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Set default timeout
    banner_timeout = 10
    
    # Establish connection, run commands, and return command(s) output
    try:
        # Connect to client machine
        client.connect(hostname, port, username, password, banner_timeout=banner_timeout)
        ssh_session = client.get_transport()
            
        # Get the os running on the target machine
        # Works on debian
        #stdin, stdout, stderr = client.exec_command('uname -a')
        # Works on redhat
        stdin, stdout, stderr = client.exec_command('cat /proc/version')
        Current_OS = stdout.read().decode("utf-8").lower()
        print(Current_OS)

        # Separate links by their extension
        for link in links:    
            if ("linux" in link) and (".deb" in link):
                if "splunkforwarder" not in link:
                    Deb_Link = link
                else:
                    Deb_Forwarder_Link = link
            if ("linux" in link) and (".rpm" in link):
                if "splunkforwarder" not in link:
                    Rpm_Link = link
                else:
                    Rpm_Forwarder_Link = link
            if ("linux" in link) and (".tgz" in link):
                if "splunkforwarder" not in link:
                    Linux_Tar_Link = link
                else:
                    Forwarder_Tar_Link = link
            # Still need forwarder for windows
            if ("windows" in link) and (".msi" in link):
                if "x64" in link:
                    Msi_Link_64 = link
                elif "x86" in link:
                    Msi_Link_86 = link
                else:
                    pass
            # Need forwarder for mac
            if ("osx" in link) and (".dmg" in link):
                Dmg_Link = link
            if ("osx" in link) and (".tgz" in link):
                Osx_Tar_Link = link
    
        # Determine OS, and download respective packages
        if "windows" in Current_OS:
            print("Using .msi package")
            # Download .msi
            download_splunk(".msi", ["www.app1.com", "www.app2.com"])
            
        elif ("redhat" in Current_OS) or ("red hat" in Current_OS) or ("fedora" in Current_OS) or ("centos" in Current_OS):
            # Download splunk
            print("Starting .rpm splunk download...")
            # Set up for running commands that need sudo
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo wget -O splunk.rpm " + str(Rpm_Link))
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)
                    
            # Install splunk
            print("Starting splunk install...")
            # Set up for running commands that need sudo
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo rpm -ivh splunk.rpm")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)
                    
            # Start splunk
            print("Starting splunk service...")
            # Set up for running commands that need sudo
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("cd /opt/splunk/bin && sudo ./splunk start --accept-license --answer-yes --seed-passwd 'password'")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)
            session.close()
 
            # Get grub config file and create a new edited one
            print("Editing Grub file to disable Transparent Huge Pages...")
            New_Grub_Contents = []
            stdin, stdout, stderr = client.exec_command('cat /etc/default/grub')
            Grub_Contents = stdout.read().decode("utf-8")
            Grub_Contents = Grub_Contents.split('\n')
            for line in Grub_Contents:
                if ("GRUB_CMDLINE_LINUX" in line) and ("GRUB_CMDLINE_LINUX_DEFAULT" not in line):
                    if "transparent_hugepage=never" not in line:
                        Current_Line = line
                        Disable_THP = Current_Line[:-1] + ' transparent_hugepage=never"'
                        New_Grub_Contents.append(str(Disable_THP))
                else:
                    New_Grub_Contents.append(str(line))

            # Get current permissions of grub file (typically 644)
            stdin, stdout, stderr = client.exec_command('stat -c %a /etc/default/grub')
            Grub_Permissions = stdout.read().decode("utf-8").lower()
            Grub_Permissions = Grub_Permissions.replace('\n', '')

            # Change grub permissions so anyone can write to it
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo chmod 777 /etc/default/grub")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)

            # Write new configurations to grub file
            sftp = paramiko.SFTPClient.from_transport(ssh_session)
            Grub_File = sftp.open('/etc/default/grub', 'w+')
            for line in New_Grub_Contents:
                Grub_File.write((line + '\n'))
            Grub_File.flush()
            Grub_File.close()
            
            # Change grub permissions back to original
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo chmod " + str(Grub_Permissions) + " /etc/default/grub")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)
            
            # Update grub
            # sudo update-grub works on debian
            # For redhat
            # sudo grub2-mkconfig -o /boot/grub2/grub.cfg
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo grub2-mkconfig -o /boot/grub2/grub.cfg")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)
            
            # Close connection and exit
            stdin.close()
            stdout.close()
            stderr.close()
            session.close()

        elif ("ubuntu" in Current_OS) or ("kali" in Current_OS) or ("parrot" in Current_OS):
            # Download splunk
            print("Starting .deb splunk download...")
            # Set up for running commands that need sudo
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo wget -O splunk.deb " + str(Deb_Link))
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)

            # Install splunk
            print("Starting splunk install...")
            # Set up for running commands that need sudo
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo dpkg -i splunk.deb")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)
                    
            # Start splunk
            print("Starting splunk service...")
            # Set up for running commands that need sudo
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("cd /opt/splunk/bin && sudo ./splunk start --accept-license --answer-yes --seed-passwd 'password'")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)      
            
            # Get grub config file and create a new edited one
            print("Editing Grub file to disable Transparent Huge Pages...")
            New_Grub_Contents = []
            stdin, stdout, stderr = client.exec_command('cat /etc/default/grub')
            Grub_Contents = stdout.read().decode("utf-8")
            Grub_Contents = Grub_Contents.split('\n')
            for line in Grub_Contents:
                if ("GRUB_CMDLINE_LINUX" in line) and ("GRUB_CMDLINE_LINUX_DEFAULT" not in line):
                    if "transparent_hugepage=never" not in line:
                        Current_Line = line
                        Disable_THP = Current_Line[:-1] + ' transparent_hugepage=never"'
                        New_Grub_Contents.append(str(Disable_THP))
                else:
                    New_Grub_Contents.append(str(line))

            # Get current permissions of grub file (typically 644)
            stdin, stdout, stderr = client.exec_command('stat -c %a /etc/default/grub')
            Grub_Permissions = stdout.read().decode("utf-8").lower()
            Grub_Permissions = Grub_Permissions.replace('\n', '')

            # Change grub permissions so anyone can write to it
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo chmod 777 /etc/default/grub")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)

            # Write new configurations to grub file
            sftp = paramiko.SFTPClient.from_transport(ssh_session)
            Grub_File = sftp.open('/etc/default/grub', 'w+')
            for line in New_Grub_Contents:
                Grub_File.write((line + '\n'))
            Grub_File.flush()
            Grub_File.close()
            
            # Change grub permissions back to original
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo chmod " + str(Grub_Permissions) + " /etc/default/grub")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)
            
            # Update grub
            # sudo update-grub works on debian
            # For redhat
            # sudo grub2-mkconfig -o /boot/grub2/grub.cfg
            session = ssh_session.open_session()
            session.set_combine_stderr(True)
            session.get_pty()
            stdin = session.makefile('wb', -1)
            stdout = session.makefile('rb', -1)
            session.exec_command("sudo update-grub")
            stdin.write(password +'\n')
            stdin.flush()
            for line in stdout.read().splitlines():
                Current_Line = line.decode("utf-8")
                if len(Current_Line) > 0:
                    print(Current_Line)

            # Close connection and exit
            stdin.close()
            stdout.close()
            stderr.close()
            session.close()
            
        elif "macos" in Current_OS:
            #print("Using .dmg package")
            # Download .dmg
            print("OSX currently not supported yet.")
        else:
            print("Unknown OS type")   
    
    # Catch errors for failed login, or connection rejection
    except paramiko.ssh_exception.AuthenticationException as error:
        print("Authentication Error. Incorrect login credentials.")
    except paramiko.ssh_exception.SSHException as error_1:
        print("Too many requests, or not enough resources. Implementing rate limiting.")
        banner_timeout += 2
    except TimeoutError as error_2:
        print("Connection attempt timed out.")
    
    # Close client when done
    client.close()
    
    return


###### Functions to set up each role within the splunk environment #####
# Function to setup a deployment server
def create_deployment_server(machine_data, links):
    # This should be the current machine
    # Download splunk
    # Configure
    # Install apps
    
    return
# Function to setup an indexer  
def create_indexer(machine_data, links):
    # Role is obviously indexer if we are at this point, so need to get that
    # If we have 4 items, assume they are hostname, ip address, credentials, role
    # If there are only 3, assume that we only got ip address or hostnames
    if len(machine_data) == 4:
        hostname = machine_data[0]
        ip_address = machine_data[1]
        credentials = machine_data[2]
        credentials = credentials.split(':')
        if len(credentials) == 2:
            username = credentials[0]
            password = credentials[1]
        else:
            print("Incorrect format for credentials.")
            
        # Try to connect by hostname first, if that fails, try IP
        try:
            # SSH into machine, download/install/start splunk, disable THP
            ssh_connect(hostname, username, password, links)
        except socket.gaierror:
            print("Failed to connect to hostname : " + str(hostname))
            print("Trying ip address instead...")
            try:
                # SSH into machine, download/install/start splunk, disable THP
                ssh_connect(ip_address, username, password, links)
            except socket.gaierror:
                print("Failed to connect to ip address: " + str(ip_address))
                print("Cannot establish connection to machine.")
                
    # If only given 3 items, assume we didn't get both the hostname and ip address. Only one of them
    elif len(machine_data) == 3:
        connect_name = machine_data[0]
        credentials = machine_data[1]
        credentials = credentials.split(':')
        if len(credentials) == 2:
            username = credentials[0]
            password = credentials[1]
        else:
            print("Incorrect format for credentials.")
        
        # Try to connect to machine
        try:
            # SSH into machine, download/install/start splunk, disable THP
            ssh_connect(connect_name, username, password, links)
        except socket.gaierror:
            print("Failed to connect to: " + str(connect_name))
            print("Cannot establish connection to machine.")
    
    # Do other configuration stuff
    # At the very end, reboot machine
    
    return
# Function to setup a (universal) forwarder
def create_forwarder(machine_data, links):
    # SSH into machine
    # Download splunk
    # Configure
    
    return
# Function to setup a heavy forwarder
def create_heavy_forwarder(machine_data, links):
    # SSH into machine
    # Download splunk
    # Configure
    
    return
# Function to setup a cluster master
def create_cluster_master(machine_data, links):
    # SSH into machine
    # Download splunk
    # Configure
    
    return
# Function to setup a search head
def create_search_head(machine_data, links):
    # SSH into machine
    # Download splunk
    # Configure
    
    return
# Function to setup a license server
def create_license_server(machine_data, links):
    # SSH into machine
    # Download splunk
    # Configure
    
    return
# Function to setup a monitoring console
def create_monitoring_console(machine_data, links):
    # SSH into machine
    # Download splunk
    # Configure
    
    return


########################################################################
# Beginning of main
if __name__ == '__main__':
    # Get current version links for all platforms
    Current_Links = fetch_current_links()

    # Scrape Splunkbase site for apps and app links
    #Current_Apps = get_app_links()
    
    # Download apps from splunkbase site
    #load_apps()

    # Get all machines involved in deployment
    All_Roles = read_in_roles()
    
##### For all other machines, set them up with respect to their role ###
    # Keep up with the number of machines associated with each role.
    # (Purely just to print back to user. Not inherently important)
    Number_Of_DS = 0
    Number_Of_I = 0
    Number_Of_F = 0
    Number_Of_HF = 0
    Number_Of_CM = 0
    Number_Of_SH = 0
    Number_Of_LS = 0
    Number_Of_MC = 0

    # For each of the servers, set them up according to their roles
    for server in All_Roles:
        Current_Role = server[-1].lower()
        # Deployment server (Should be this machine)
        if Current_Role == "deployment server" or Current_Role == "ds":
            # This one is different, since it should be the current machine
            # Check IP and Hostname to make sure it mactches
            # Get current machine info
            Current_Hostname, Current_IP, Current_Extension = get_machine_info()
            # Download and install splunk
            download_splunk(Current_Extension, Current_Links)
            Number_Of_DS += 1
            
        # Indexer
        if Current_Role == "indexer" or Current_Role == "idx" or Current_Role == "i":
            create_indexer(server, Current_Links)
            Number_Of_I += 1
            
        # Forwarder
        if Current_Role == "universal forwarder" or Current_Role == "forwarder" or Current_Role == "uf" or Current_Role == "f":
            create_forwarder(server, Current_Links)
            Number_Of_F += 1
            
        # Heavy Forwarder
        if Current_Role == "heavy forwarder" or Current_Role == "hf":
            create_heavy_forwarder(server, Current_Links)
            Number_Of_HF += 1
            
        # Cluster Manager
        if Current_Role == "cluster manager" or Current_Role == "cluster master" or Current_Role == "cm":
            create_cluster_master(server, Current_Links)
            Number_Of_CM += 1
            
        # Search Head
        if Current_Role == "search head" or Current_Role == "sh":
            create_search_head(server, Current_Links)
            Number_Of_SH += 1
            
        # License server (possibly pair with deployment server) (Maybe default to that if not specified)
        if Current_Role == "license manager" or Current_Role == "lm" or Current_Role == "license server" or Current_Role == "ls":
            create_license_server(server, Current_Links)
            # If no machine is given, default to adding it to the deployment server
            Number_Of_LS += 1
            
        # Monitoring console
        if Current_Role == "monitoring console" or Current_Role == "mc":
            create_monitoring_console(server, Current_Links)
            Number_Of_MC += 1
    
    # Total number of machines for each role
    print("Total number of Deployment Servers: " + str(Number_Of_DS))
    print("Total number of Indexers: " + str(Number_Of_I))
    print("Total number of Forwarders (Heavy and Universal): " + str(Number_Of_F + Number_Of_HF))
    print("Total number of Cluster Masters: " + str(Number_Of_CM))
    print("Total number of Search Heads: " + str(Number_Of_SH))
    print("Total number of License Servers: " + str(Number_Of_LS))
    print("Total number of Monitoring Consoles: " + str(Number_Of_MC))

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

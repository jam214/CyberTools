#Cybertools.py
"""
Creator: James S.
Purpose: To create a menu based program with multiple cyber security tools
"""

import requests
from bs4 import BeautifulSoup
import json
import psutil
import datetime
from tabulate import tabulate
import socket
from exif import Image
import xml.etree.ElementTree as ET
class Menu:
    def __init__(self, title, options):
        self.title = title
        self.options = options

    def display(self):
        print(self.title)
        for idx, option in enumerate(self.options, start=1):
            print(f"{idx}. {option}")

    def ProcessChoice(self):
        while True:
            try:
                choice = int(input(f"Enter Menu choice (1-{len(self.options)}): "))
                if 1 <= choice <= len(self.options):
                    return choice
            except ValueError:
                pass

class NewsFeed:
    """
    Represents a NewsFeed object to fetch and display news titles. Apart of the Get Web Data submenu.
    """
    def __init__(self):
        """
        Initializes the NewsFeed object with site URLs and an empty dictionary for titles.
        """
        self.site_urls = {
            'FoxNews': 'http://feeds.foxnews.com/foxnews/tech',
            'CNN': 'http://rss.cnn.com/rss/cnn_tech.rss',
            'BBC': 'http://feeds.bbci.co.uk/news/technology/rss.xml',
            'ABC': 'http://feeds.abcnews.com/abcnews/technologyheadlines',
            'CBS': 'https://www.cbsnews.com/latest/rss/technology'
        }
        self.titles_dict = {}

    def GrabTitles(self):
        """
        Fetches news titles from various sites and saves them to XML files.
        """
        for site, url in self.site_urls.items():
            feed_data = requests.get(url).content
            feed_soup = BeautifulSoup(feed_data, 'xml')
            
            # Save XML feed to file
            with open(f'{site}_FeedData.xml', 'w', encoding='utf-8') as outfile:
                outfile.write(feed_soup.prettify())
            
            if 'rss.cnn.com' in url:
                titles = [item.find('description').text for item in feed_soup.find_all('item')]
            else:
                titles = [item.find('title').text for item in feed_soup.find_all('item')]
                
            self.titles_dict[site] = titles

    def SaveToJson(self):
        """
        Saves news titles dictionary to a JSON file.
        """
        filename = input("Enter the name of the JSON file to save to: ")
        with open(filename, "w", encoding="utf-8") as json_file:
         json.dump(self.titles_dict, json_file, ensure_ascii=False)
         print(f"Data saved to {filename}")

    def ReadJsonFile(self):
        """
        Reads news titles dictionary from a JSON file.
        """
        filename = input("Enter the name of the JSON file to read from: ")
        with open(filename, "r", encoding="utf-8") as json_file:
            self.titles_dict = json.load(json_file)
            print(f"Data read from {filename}")

    def PrintXMLTitles(self):
        """
        Prints news titles from the titles dictionary.
        """
        for site, titles in self.titles_dict.items():
            print(f"{site}:")
            for i, title in enumerate(titles, start=1):
                print(f"{i}. {title}")
            print()  # Print an empty line between sites
class SystemInfo:
    """
    Represents a SystemInfo object to fetch and display system information.Apart of the Forensics submenu.
    """
    def __init__(self):
        """
        Initializes the SystemInfo object with disk usage, disk partitions, and CPU stats.
        """
        self.diskusage = psutil.disk_usage('/')
        self.diskparitions= psutil.disk_partitions()
        self.cpustat = psutil.cpu_stats()
    
    def DiskInfo(self):
        """
        Prints information about the disk partitions and usage.
        
        """
        print (f'The Disk partitions are: {self.diskparitions}')
        print (f"The Disk usage is: {self.diskusage}")
    
    def UserInfo(self):
        '''
         grabs info about users on the system
        '''
        print (f"Users are: {psutil.users()[0].name} \n Started on local time: {datetime.datetime.fromtimestamp(psutil.users()[0].started)} \n UTC: {datetime.datetime.utcfromtimestamp(psutil.users()[0].started)}")
    def CPUStats(self):
        """
        Prints information about the CPU
        
        """
        print(f"The current statistics of the CPU is : {self.cpustat}")

    def PidsInfo(self):
        """
        grabs the process details (ids)
        
        """
        AllPIDs = psutil.pids()
        print (f'The type of structure is: {type(AllPIDs)}')
        print (f'The number of processes are: {len(AllPIDs)}')
        for APID in AllPIDs:
            Aprocess = psutil.Process(APID)
            print (f" Type is: {type(Aprocess)} ID is: {Aprocess.pid} Name: {Aprocess.name} IsRunning: {Aprocess.is_running()}")
    
    def BootInfo(self):
         """
         Prints the boot time
         """

         BootTime = psutil.boot_time()
         print(f"The system booted on: {datetime.datetime.fromtimestamp(BootTime)}")
class Vulnerabilities:
    """
    Represents a Vulnerabilities object to fetch and display known vulnerabilities. Apart of the Get Web Data submenu.
    """
    def __init__(self):
        """
        Initializes the Vulnerabilities object with an empty list for vulnerabilities.
        """
        self.vulnerabilities = []

    def GetVulns(self):
        """
        Fetches known vulnerabilities from CISA and populates the vulnerabilities list.
        """
        try:
            Vulns = requests.get('https://cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
            VulnsJson = Vulns.json()
            self.vulnerabilities = VulnsJson.get('vulnerabilities', [])
            print("CISA vulnerabilities obtained")
        except requests.RequestException as e:
            print("Failed to obtain CISA vulnerabilities data:", e)

    def DisplayTotalVulns(self):
        """
        Displays the total number of known vulnerabilities.
        """
        if not self.vulnerabilities:
            print("No vulnerabilities have been obtained")
            return
        TotalVulns = len(self.vulnerabilities)
        print(f"Total number of vulnerabilities: {TotalVulns}")

    def GetVendorVulns(self):
        """
        Fetches and displays vulnerabilities for a specific vendor project.
        """
        if not self.vulnerabilities:
            print("No vulnerabilities have been obtained")
            return

        VendorInput = input("Enter the vendor project name: ")
        VendorVulns = [
            (vuln['cveID'], vuln['dateAdded'], vuln['vulnerabilityName'])
            for vuln in self.vulnerabilities
            if vuln.get('vendorProject') == VendorInput
        ]

        if not VendorVulns:
            print(f"No vulnerabilities found for {VendorInput}")
        else:
            print(f"Number of vulnerabilities for {VendorInput}: {len(VendorVulns)}")
            print(tabulate(VendorVulns, headers=['cveID', 'dateAdded', 'vulnerabilityName']))

        return VendorVulns
class PortScanner:
    """
    Represents a PortScanner object to scan ports on a given IP. Apart of the Network Tools submenu.
    """
    def __init__(self, IPNum, ports):
        """
        Initializes the PortScanner object with an IP address and ports to scan.
        
        Parameter IPNum: The IP address to scan.
        Parameter ports: A list of ports to scan.
        """
        self.IPNum = IPNum
        self.ports = ports

    def PortScan(self):
        """
        Scans the specified ports on the IP address and prints the results.
        """
        for index in range(10):  # Scan only the first 10 ports
            if index < len(self.ports):
                port = self.ports[index]
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        result = s.connect_ex((self.IPNum, port))
                        if result == 0:
                            print(f"Port {port} is open")
                        else:
                            print(f"Port {port} is closed")
                except Exception as e:
                    print(f"Error scanning port {port}: {e}")


def PortFileReader(file_name):
    """
    Reads a file containing port numbers and returns them as a list.
    
    parameter file_name: The name of the file containing port numbers.
    returns A list of port numbers.
    """
    try:
        PortFile=open(file_name, 'r') 
        ports = [int(port.strip()) for port in PortFile.readlines()]
        return ports
    except FileNotFoundError:
        print(f"File {file_name} not found.")
        return []
class LogFileScanner:
    """
    Represents a LogFileScanner object to scan and search through log files. Apart of the Forensics submenu.
    """
    def __init__(self, log_file):
        """
        Initializes the LogFileScanner object with a log file path.
        
        parameter log_file: The path to the log file.
        """
        self.log_file = log_file

    def NonBlankLines(self):
        """
        Counts and returns the number of non-blank lines in the log file.
        returns The number of non-blank lines.
        """
        NonBlankFile=open(self.log_file, 'r')
        return sum(1 for line in NonBlankFile if line.strip())

    def SearchLog(self, WordSearch, AllSearch=True):
        """
        Searches for lines in the log file containing the specified words.
        
        parameter WordSearch: A list of words to search for.
        parameter AllSearch: Whether all words must be present in a line (default=True).
        returns A list of matching lines.
        """
        LineResult = []
        SearchFile= open(self.log_file, 'r')
        for idx, line in enumerate(SearchFile, start=1):
                if AllSearch:
                    if all(word in line for word in WordSearch):
                        LineResult.append((idx, line.strip()))
                else:
                    if any(word in line for word in WordSearch):
                        LineResult.append((idx, line.strip()))
        return LineResult
class ImageMetadataChanger:
    """
    A class to change image metadata. Apart of the Forensics submenu.

    """
    def __init__(self):
        """
        Initializes the ImageMetadataChanger object.
        """
        pass

    def UserInput(self):
        """
        Asks the user to enter metadata.
        """
        self.filename = input("Enter Filename: ")
        print("Enter New Metadata")
        self.make = input("Enter Make: ")
        self.model = input("Enter Model: ")
        self.datetime = input("Enter Time: ")

    def ChangeMetadata(self):
        """
        Changes the metadata of an image.
        """
       # Open the image file
        with open(self.filename, 'rb') as f:
            # Create an Image instance with the file object
            MyImage = Image(f)

            # Get the existing EXIF data
            ExifData = MyImage.get_all()

            # Update EXIF data
            ExifData['Make'] = self.make  # Make
            ExifData['Model'] = self.model  # Model
            ExifData['DateTime'] = self.datetime  # DateTimeOriginal

        # Create the filename for the changed image
        ChangedFilename = f"Changed_{self.filename}"

        # Save the changed image
        with open(ChangedFilename, 'wb') as Ofile:
            Ofile.write(MyImage.get_file())

        # Print changed metadata
        print(f"Changed Photo info:")
        print(f"Make: {self.make}")
        print(f"Model: {self.model}")
        print(f"Time of when photo was taken: {self.datetime}\n")
class APIHandler:
    """
    A class to handle API calls. Apart of the Get Web Data submenu.
    """
    def __init__(self):
        """
        Initializes the APIHandler object.
        """
        pass

    def GetIP2Location(self):
        """
        Calls the API from ip2location.io and saves the data to a  .txt file.
        """
        Endpoint = 'https://api.ip2location.io'
        qparams = {'ip': '109.144.143.35'}
        MyResponse = requests.get(Endpoint, params=qparams).json()

        FileName = "ip2location_info.txt"
        with open(FileName, 'w') as file:
            file.write("IP2Location Info:\n")
            for k, v in MyResponse.items():
                file.write(f"{k}: {v}\n")
        print(f"Data saved to {FileName}")

    def GetPlayerData(self):
        """
        Calls the API from nba-stats and saves the data to a .json file.
        
        """
        url = "https://nba-stats-db.herokuapp.com/api/playerdata/name/Tim Duncan"
        response = requests.get(url).json()

        FileNameNba = "player_data.json"
        with open(FileNameNba, 'w') as file:
            json.dump(response, file)
        print(f"Data saved to {FileNameNba}")

    def GetHackerNews(self):
        """
        Calls the API from hacker-news and ssaves the data to a .xml file.
        """
        HackerUrl = "https://hacker-news.firebaseio.com/v0/item/18872485.json?print=pretty"
        response = requests.get(HackerUrl).json()

        FileNameHacker = "hacker_news_item.xml"
        root = ET.Element("HackerNewsItem")
        for key, value in response.items():
            ET.SubElement(root, key).text = str(value)

        FileNameHacker = "hacker_news_item.xml"
        with open(FileNameHacker, 'wb') as file:
            tree = ET.ElementTree(root)
            tree.write(file)
        print(f"Response saved to {FileNameHacker}")


def main():
    MainMenu = Menu("Main Menu", ["Get Web Data","Forensics","Network Tools", "Quit"])
    WebData = Menu("Web Data Menu",["Vulnerabilty Info","Get XML Pages","GetAPIData", "Go back To Main Menu"])
    VulnMenu = Menu("Vulnerabilty Menu",["Get Vulnerabilities","Display Number of Vulnerabilities", "Get Vendor Vulnerabilities","Go Back to Main Menu"]) # Apart of the Get Web Data submenu.
    APIMenu = Menu("API Menu",["Get IP2Location", "Get Player Data", "Get Hacker News","Go back To Main Menu"])# Apart of the Get Web Data submenu.
    ForensicsMenu = Menu("Forensic Menu",["Log File Scanning","View & change Metadata","Disk Info","User Info ","CPUInfo","PIDS","Boot Info","Go Back to Main Menu "])
    NetworkMenu =Menu ("Network Menu",["Port Scanner","Go Back to Main Menu"])
    XMLGrab = NewsFeed()
    SysDetails = SystemInfo()
    CISAVulns = Vulnerabilities()
    MetaData= ImageMetadataChanger()
    APICall= APIHandler()
    LogScan=LogFileScanner("auth.log")
    PortScan=PortScanner('77.111.240.4',[21,22,23,25,53,80,443,3306])
    while True:
        MainMenu.display()
        MenuChoice = MainMenu.ProcessChoice()
        if MenuChoice == 1:
            while True:
                WebData.display()
                WebDataChoice = WebData.ProcessChoice()
                if WebDataChoice == 1:
                    while True:
                        VulnMenu.display()
                        VulnMenuChoice= VulnMenu.ProcessChoice()
                        if VulnMenuChoice == 1:
                            CISAVulns.GetVulns()
                        elif VulnMenuChoice == 2:
                            CISAVulns.DisplayTotalVulns()
                        elif VulnMenuChoice == 3:
                            CISAVulns.GetVendorVulns()
                        elif VulnMenuChoice == 4:
                            print(f"Exiting Vulnerability Menu")
                            break
                elif WebDataChoice == 2:
                    XMLGrab.GrabTitles()
                    XMLGrab.SaveToJson()
                    XMLGrab.ReadJsonFile()
                    XMLGrab.PrintXMLTitles()
                elif WebDataChoice == 3:
                    while True:
                        APIMenu.display()
                        APIMenuChoice = APIMenu.ProcessChoice()
                        if APIMenuChoice == 1:
                            APICall.GetIP2Location()
                        elif APIMenuChoice == 2:
                            APICall.GetPlayerData()
                        elif APIMenuChoice == 3:
                            APICall.GetHackerNews()
                        elif APIMenuChoice == 4:
                            print(f"Exiting API Menu")
                            break
                elif WebDataChoice == 4:
                    print(f"Exiting Web Data Menu")
                    break
        elif MenuChoice == 2:
            while True:
                ForensicsMenu.display()
                ForensicsMenuChoice = ForensicsMenu.ProcessChoice()
                if ForensicsMenuChoice == 1:
                    LogScan.NonBlankLines()
                    LogScan.SearchLog()
                elif ForensicsMenuChoice == 2:
                    MetaData.UserInput()
                    MetaData.ChangeMetadata()
                elif ForensicsMenuChoice == 3:
                    SysDetails.DiskInfo()
                elif ForensicsMenuChoice == 4:
                    SysDetails.UserInfo()
                elif ForensicsMenuChoice == 5:
                    SysDetails.CPUStats()
                elif ForensicsMenuChoice == 6:
                    SysDetails.PidsInfo()
                elif ForensicsMenuChoice == 7:
                    SysDetails.BootInfo()
                elif ForensicsMenuChoice == 8:
                    print(f"Exiting Forensics Menu")
                    break
        elif MenuChoice == 3:
            while True:
                NetworkMenu.display()
                NetworkMenuChoice = NetworkMenu.ProcessChoice()
                if NetworkMenuChoice == 1:
                    PortScan.PortScan()
                elif NetworkMenuChoice == 2:
                    print(f"Exiting Network Menu")
                    break
        elif MenuChoice == 4:
            print(f"Exiting Program")
            break




    # # Fetch titles from the sites
    # XMLGrab.GrabTitles()

    # # Save titles to JSON file
    # XMLGrab.SaveToJson()

    # # Read titles back from JSON file
    # XMLGrab.ReadJsonFile()

    # # Print titles
    # XMLGrab.PrintXMLTitles()

if __name__ == "__main__":
    main()

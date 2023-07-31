# Import necessary modules
import subprocess
from datetime import datetime
import configparser as ConfigParser

# Get the configparser object
config = ConfigParser.ConfigParser()

# Main function

def main():
    config.read('config.ini')
    project_folder = config.get('FOLDERS', 'project_folder')
    wordlist_folder = project_folder + "dependencies/Dome/wordlists/subdomains-top1million-5000.txt"

    print("Welcome to Shinobi!")

    target = input("Target URL/IP Address: ")

    print("Running subdomain enumerator...")
    dome_output = subprocess.run(["python3", "dependencies/Dome/dome.py", "-m", "passive", "-d", target, "-w", wordlist_folder], capture_output=True)
    
    filename = 'results/' + get_unique_filename()
    with open(filename, 'w') as file:
        file.write(dome_output.stdout.decode())

    print("Thank you for using Shinobi!")

def get_unique_filename():
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    return f"results_{timestamp}.txt"

# Entry point
if __name__ == "__main__":
    main()

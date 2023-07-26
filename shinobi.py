# Import necessary modules
import subprocess
from datetime import datetime
import configparser as ConfigParser

# Get the configparser object
config = ConfigParser.ConfigParser()

# You can import any modules or packages you need for your application here.

# Define your functions

# You can define your application's functions here.


# Main function

def main():
    config.read('config.ini')
    project_folder = config.get('FOLDERS', 'project_folder')
    wordlist_folder = project_folder + "Dome/wordlists/subdomains-top1million-5000.txt"

    print("Welcome to Shinobi!")

    target = input("Target URL/IP Address: ")

    print("Running subdomain enumerator...")
    dome_output = subprocess.run(["python3", "Dome/dome.py", "-m", "passive", "-d", target, "-w", wordlist_folder], capture_output=True)
    
    filename = 'results/' + get_unique_filename()
    with open(filename, 'w') as file:
        file.write(dome_output.stdout.decode())
    
    # while True:
    #     # Display a menu or prompt for user input
    #     # Example: print("1. Option 1")
    #     #          print("2. Option 2")
    #     #          choice = input("Enter your choice (1/2): ")
    #     #          if choice == "1":
    #     #              function_option_1()
    #     #          elif choice == "2":
    #     #              function_option_2()
    #     #          else:
    #     #              print("Invalid choice. Please try again.")
    #     #              continue
        
    #     # Handle user input and call appropriate functions
    #     # Example: if choice == "1":
    #     #              function_option_1()
    #     #          elif choice == "2":
    #     #              function_option_2()
    #     #          elif choice == "exit":
    #     #              print("Exiting the application.")
    #     #              break
    #     #          else:
    #     #              print("Invalid choice. Please try again.")
        
    #     # Alternatively, you can implement a different flow for your application.
    #     # For instance, you could use a command line argument parser for a more complex application.
        
    #     break  # Remove this if you have a loop-based application flow.

    print("Thank you for using Shinobi!")

def get_unique_filename():
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    return f"results_{timestamp}.txt"

# Entry point
if __name__ == "__main__":
    main()

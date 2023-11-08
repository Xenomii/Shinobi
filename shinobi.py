# Import necessary modules
import requests
import socket
import shodan
import time
import json
import configparser as ConfigParser
from datetime import datetime

# Get the configparser object
config = ConfigParser.ConfigParser()

def get_unique_filename():
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    return f"results_{timestamp}.txt"

FILENAME = 'results/' + get_unique_filename()
CVELOOKUP = True

def check_ssl_certificate(domain):
    try:
        # Initiate SSL certificate assessment
        api_url = f'https://api.ssllabs.com/api/v3/analyze?host={domain}&all=on'
        response = requests.get(api_url)
        result = response.json()

        while result['status'] != 'READY':
            print(f"SSL certificate assessment is in progress. Current status: {result['status']}.")
            time.sleep(10)  # Wait for 10 seconds before checking again
            response = requests.get(api_url)
            result = response.json()

        print("SSL certificate assessment completed.")
        with open(FILENAME, 'a') as file:

            #  more detailed information about the SSL certificate
            endpoints = result.get('endpoints', [])
            for endpoint in endpoints:
                file.write(f"\n\nServer: {endpoint.get('serverName', 'N/A')}")
                file.write(f"\nGrade: {endpoint.get('grade', 'N/A')}")
                file.write(f"\nIP Address: {endpoint.get('ipAddress', 'N/A')}")
                details = endpoint.get('details', {})
                
                protocols = details.get('protocols', [])
                if protocols:
                    file.write("\nTLS Version(s): ")
                    for x in range(len(protocols)):
                        file.write("\n" + protocols[x].get('version'))
                else:
                    file.write("\nProtocol: N/A")
                
                suites = details.get('suites', [])
                if suites:
                    file.write("\n\nCipher Suites:")
                    for x in range(len(suites)):
                        slist = suites[x].get('list', [])
                        for y in range(len(slist)):
                            file.write("\n" + slist[y].get('name'))
                else:
                    file.write("\nCipher Suite: N/A")

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

def lookup_cve(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: {e}"

def use_shodan(ip):
    config.read('config.ini')
    SHODAN_API_KEY = config.get('API KEYS', 'shodan')
    
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host_info = api.host(ip)

        with open(FILENAME, "a") as file:        
            file.write(f"\nOrganization: {host_info.get('org', 'N/A')}")
            file.write(f"\nOperating System: {host_info.get('os', 'N/A')}")

            results = host_info['data']

            file.write("\n\nOpen Ports:")
            for item in results:
                open_port = item['port']
                file.write(f"\n{open_port}\n")
                for x in range(len(results)):
                    port = results[x].get('port')
                    if open_port == port:
                        file.write(results[x].get('data'))


            file.write("\n\nVulnerabilities:\n")
            vuln_info = host_info.get('vulns', 'No vulnerabilities found')
            print(vuln_info)

            if vuln_info != 'No vulnerabilities found' and CVELOOKUP == True:
                print("Collecting details on identified CVEs...")
                request_count = 0
                for cve_id in vuln_info:
                    result = lookup_cve(cve_id)
                    request_count += 1

                    if request_count % 5 == 0:
                        time.sleep(40)

                    if "result" in result:
                        cve_data = result["result"]["CVE_Items"][0]
                        description = cve_data["cve"]["description"]["description_data"][0]["value"]
                        cve_url = cve_data["cve"]["references"]["reference_data"][0]["url"]
                        cwe = cve_data["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
                        cvss = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
                        file.write("\nCVE ID: " + cve_id + "\n")
                        file.write("Description: " + description + "\n")
                        file.write("URL: " + cve_url + "\n")
                        file.write("CWE: " + cwe + "\n")
                        file.write(f"CVSS Base Score: {cvss}\n")
                    else:
                        print(f"Error looking up CVE {cve_id}: {result}")

    except shodan.APIError as e:
        print(f"Error: {e}")

def passive_ip_lookup(domain):
    try:
        # Use socket library to get the IP address
        ip_address = socket.gethostbyname(domain)
        print(f"IP address for '{domain}': {ip_address}")

        # Use ipinfo.io for additional information
        ipinfo_url = f"https://ipinfo.io/{ip_address}/json"
        response = requests.get(ipinfo_url)
        ipinfo_data = response.json()

        with open(FILENAME, "a") as file:
            file.write(f"\nCity: {ipinfo_data.get('city', 'N/A')}")
            file.write(f"\nRegion: {ipinfo_data.get('region', 'N/A')}")
            file.write(f"\nCountry: {ipinfo_data.get('country', 'N/A')}")
            file.write(f"\nISP: {ipinfo_data.get('org', 'N/A')}")
    except socket.gaierror:
        print(f"Unable to resolve the IP address for '{domain}'")
    except requests.exceptions.RequestException:
        print("Unable to retrieve additional information from ipinfo.io")
    return ip_address

def passive_subdomain_enum(domain):
    sources = [
        "https://crt.sh/?q=%.{0}&output=json".format(domain),
        "https://certspotter.com/api/v0/certs?domain={0}".format(domain)
    ]

    subdomains = set()

    for source in sources:
        try:
            response = requests.get(source)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    subdomains.add(entry.get("name_value", ""))
        except Exception as e:
            print(f"Error while querying {source}: {e}")

    if subdomains:
        with open(FILENAME, 'a') as file:
            file.write("\n\nSubdomains found:\n")
            for subdomain in subdomains:
                file.write(subdomain)
    else:
        print("No subdomains found for the provided domain.")

if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")
    print("Collecting IP information...")
    ip_add = passive_ip_lookup(target_domain)
    print("Collecting port information and determining vulnerabilities...")
    use_shodan(ip_add)
    print("Collecting & assessing SSL certificate...")
    check_ssl_certificate(target_domain)
    print("Finding subdomains that can increase attack vector...")
    passive_subdomain_enum(target_domain)

    

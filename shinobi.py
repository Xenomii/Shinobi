# Import necessary modules
import requests
import socket
import shodan
import time
import json
import configparser as ConfigParser

# Get the configparser object
config = ConfigParser.ConfigParser()

CVE_LOOKUP = False

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
        print(f"Overall grade: {result['endpoints'][0]['grade']}")

        # Print more detailed information about the SSL certificate
        endpoints = result.get('endpoints', [])
        for endpoint in endpoints:
            print(f"\nServer: {endpoint.get('serverName', 'N/A')}")
            print(f"Grade: {endpoint.get('grade', 'N/A')}")
            print(f"IP Address: {endpoint.get('ipAddress', 'N/A')}")
            details = endpoint.get('details', {})
            
            protocols = details.get('protocols', [])
            if protocols:
                print("TLS Version(s):")
                for x in range(len(protocols)):
                    print(protocols[x].get('version'))
            else:
                print("Protocol: N/A")
            
            suites = details.get('suites', [])
            if suites:
                print('Cipher Suites:')
                for x in range(len(suites)):
                    slist = suites[x].get('list', [])
                    for y in range(len(slist)):
                        print(slist[y].get('name'))
            else:
                print("Cipher Suite: N/A")

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

        print(f"Organization: {host_info.get('org', 'N/A')}")
        print(f"Operating System: {host_info.get('os', 'N/A')}")

        print("Open Ports:")
        for item in host_info['data']:
            port = item['port']
            service = item.get('banner', 'N/A')
            print(f"Port: {port} - Service: {service}")

        print("Vulnerabilities:")
        vuln_info = host_info.get('vulns', 'No vulnerabilities found')
        print(vuln_info)

        if vuln_info != 'No vulnerabilities found' and CVE_LOOKUP == True:
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
                    print(f"CVE ID: {cve_id}")
                    print(f"Description: {description}")
                    print(f"URL: {cve_url}\n")
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

        print(f"City: {ipinfo_data.get('city', 'N/A')}")
        print(f"Region: {ipinfo_data.get('region', 'N/A')}")
        print(f"Country: {ipinfo_data.get('country', 'N/A')}")
    except socket.gaierror:
        print(f"Unable to resolve the IP address for '{domain}'")
    except requests.exceptions.RequestException:
        print("Unable to retrieve additional information from ipinfo.io")
    return ip_address

def passive_subdomain_enum(domain):
    sources = [
        "https://crt.sh/?q=%.{0}&output=json".format(domain),
        "https://certspotter.com/api/v0/certs?domain={0}".format(domain),
        # Add more data sources here
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

    return subdomains

if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")
    
    ip_add = passive_ip_lookup(target_domain)

    use_shodan(ip_add)
    
    check_ssl_certificate(target_domain)

    subdomains = passive_subdomain_enum(target_domain)

    if subdomains:
        print("\nSubdomains found:")
        for subdomain in subdomains:
            print(subdomain)
    else:
        print("No subdomains found for the provided domain.")

    

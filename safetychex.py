import requests

# Define endpoint and security source
endpoint = input("Enter the endpoint to scan: ")
security_source = input("Enter the security source to search for IOCs (Alienvault, Krebs, Symantec, FireEye, etc.): ")

# Define IOC search URL based on security source
if security_source == "Alienvault":
    url = "https://reputation.alienvault.com/reputation.generic"
elif security_source == "Krebs":
    url = "https://krebsonsecurity.com/iocs/"
elif security_source == "Symantec":
    url = "https://www.symantec.com/blogs/threat-intelligence/ioc-to-watch-in-2021"
elif security_source == "FireEye":
    url = "https://www.fireeye.com/current-threats/iocs.html"
else:
    print("Invalid security source.")
    exit()

# Make HTTP request to IOC search URL
response = requests.get(url)

# Check if response is successful
if response.status_code != 200:
    print("Error: could not retrieve IOCs.")
    exit()

# Search for IOCs in response content
ioc_list = []
content = response.content.decode("utf-8")
for line in content.split("\n"):
    if endpoint in line:
        ioc_list.append(line)

# Print found IOCs
if len(ioc_list) == 0:
    print("No IOCs found for endpoint", endpoint)
else:
    print("Found IOCs for endpoint", endpoint, "in", security_source, ":")
    for ioc in ioc_list:
        print(ioc)

# Allow remediation if available
remediation = input("Would you like to attempt remediation if available? (Y/N): ")
if remediation.lower() == "y":
    remediation_url = input("Enter the URL for remediation instructions: ")
    response = requests.get(remediation_url)
    if response.status_code != 200:
        print("Error: could not retrieve remediation instructions.")
        exit()
    else:
        print("Remediation instructions for IOCs found:")
        print(response.content.decode("utf-8"))
else:
    print("Exiting script.")

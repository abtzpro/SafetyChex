import requests

# Endpoint to scan
endpoint = "https://example.com"

# List of public IOC sources
ioc_sources = ["https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
               "https://api.krebscycle.com/riskservice/domain/{domain}",
               "https://api.symantec.com/v1/threatintel/ip/{ip_address}/risk",
               "https://www.fireeye.com/intel/indicator-of-compromise/iocs.html"]

# Loop through each IOC source and scan the endpoint
for ioc_source in ioc_sources:
    # Replace {domain} and {ip_address} with the endpoint being scanned
    ioc_url = ioc_source.format(domain=endpoint, ip_address=endpoint)
    response = requests.get(ioc_url)
    
    if response.status_code == 200:
        iocs = response.json()
        print(f"IOCs from {ioc_source}: {iocs}")
    else:
        print(f"Error retrieving IOCs from {ioc_source}")

import requests
import smtplib
import subprocess

# Endpoint to scan
endpoint = input("Enter the endpoint to scan: ")

# Email settings
smtp_server = input("Enter your SMTP server: ")
smtp_port = input("Enter your SMTP port: ")
smtp_username = input("Enter your SMTP username: ")
smtp_password = input("Enter your SMTP password: ")
from_email = input("Enter the email address to send from: ")
to_email = input("Enter the email address to send to: ")

# List of public IOC sources
ioc_sources = [
    {"name": "Alienvault", "url": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", "remediation_url": ""},
    {"name": "Krebs Research", "url": "https://api.krebscycle.com/riskservice/domain/{domain}", "remediation_url": "https://krebsonsecurity.com/how-to-remove-bad-extensions-from-chrome/"},
    {"name": "Symantec", "url": "https://api.symantec.com/v1/threatintel/ip/{ip_address}/risk", "remediation_url": "https://support.symantec.com/us/en/article.tech255924.html"},
    {"name": "FireEye", "url": "https://www.fireeye.com/intel/indicator-of-compromise/iocs.html", "remediation_url": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dga-traffic-analysis.pdf"}
]

def check_ioc(ioc, source):
    """
    Check if an IOC is found on the endpoint and email the user if it is.
    """
    # Replace {domain} and {ip_address} with the endpoint being scanned
    ioc_url = source["url"].format(domain=endpoint, ip_address=endpoint)
    response = requests.get(ioc_url)
    
    if response.status_code == 200:
        iocs = response.json()
        if ioc in iocs:
            remediation_url = source["remediation_url"]
            if remediation_url:
                remediate(ioc, remediation_url)
            else:
                print(f"{ioc} found on {source['name']} but no remediation instructions available.")
            send_email(ioc, source)
    
def send_email(ioc, source):
    """
    Send an email to the user indicating that an IOC has been found on the endpoint.
    """
    message = f"Subject: IOC Found\n\nThe following IOC was found on {endpoint}:\n\n{ioc}\n\nRemediation instructions: {source['remediation_url']}"
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(from_email, to_email, message)
        print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")

def remediate(ioc, remediation_url):
    """
    Open the remediation URL in the user's default web browser.
    """
    try:
        subprocess.Popen(['open', remediation_url])
        print(f"Remediation instructions for {ioc} opened in your default web browser.")
    except Exception as e:
        print(f"Error opening remediation instructions: {e}")

# Loop through each IOC source and scan the endpoint
for ioc_source in ioc_sources:
    # Replace {domain} and {ip_address} with the endpoint being scanned
   

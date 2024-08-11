import requests
import time
from dotenv import load_dotenv
import os
from msal import ConfidentialClientApplication

# Load environment variables from .env file
load_dotenv()

# Get API keys and Azure AD details from environment variables
VT_API_KEY = os.getenv('vt_api_key')
URLSCAN_API_KEY = os.getenv('urlscan_api_key')
TALOS_API_KEY = os.getenv('talos_api_key')
AZURE_CLIENT_ID = os.getenv('azure_client_id')
AZURE_CLIENT_SECRET = os.getenv('azure_client_secret')
AZURE_TENANT_ID = os.getenv('azure_tenant_id')


def check_virustotal(url):
    print("Checking with VirusTotal...")
    api_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": VT_API_KEY, "resource": url}
    
    try:
        response = requests.get(api_url, params=params)
        result = response.json()
        
        if result["response_code"] == 1:
            positives = result["positives"]
            total = result["total"]
            return f"VirusTotal: {'Potentially malicious' if positives > 0 else 'Safe'}. {positives}/{total} security vendors flagged this URL."
        else:
            return "VirusTotal: URL not found in database."
    except requests.RequestException as e:
        return f"VirusTotal: An error occurred: {str(e)}"

def check_urlscan(url):
    print("Checking with urlscan.io...")
    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": URLSCAN_API_KEY}
    data = {"url": url}
    
    try:
        response = requests.post(api_url, headers=headers, json=data)
        result = response.json()
        
        if "result" in result:
            scan_id = result["uuid"]
            result_url = f"https://urlscan.io/result/{scan_id}/"
            
            # Wait for the scan to complete
            time.sleep(10)
            
            # Fetch the scan results
            result_response = requests.get(result_url + "api/")
            result_data = result_response.json()
            
            verdicts = result_data.get("verdicts", {})
            overall_score = verdicts.get("overall", {}).get("score", 0)
            
            return f"urlscan.io: Scan completed. Score: {overall_score}/100. Full results: {result_url}"
        else:
            return f"urlscan.io: {result.get('message', 'An error occurred')}"
    except requests.RequestException as e:
        return f"urlscan.io: An error occurred: {str(e)}"

def get_access_token():
    app = ConfidentialClientApplication(
        AZURE_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{AZURE_TENANT_ID}",
        client_credential=AZURE_CLIENT_SECRET,
    )
    
    result = app.acquire_token_silent(["https://graph.microsoft.com/.default"], account=None)
    if not result:
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    
    if "access_token" in result:
        return result["access_token"]
    else:
        print(f"Error getting token: {result.get('error')}")
        return None

def check_defender_atp_enrollment(device_name):
    print("Checking Defender ATP enrollment...")
    api_url = "https://graph.microsoft.com/v1.0/devices"
    access_token = get_access_token()
    
    if not access_token:
        return "Defender ATP: Failed to authenticate with Microsoft Graph API"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    params = {
        "$filter": f"displayName eq '{device_name}'",
        "$select": "displayName,isManaged,onPremisesSyncEnabled"
    }
    
    try:
        response = requests.get(api_url, headers=headers, params=params)
        result = response.json()
        
        if "value" in result and len(result["value"]) > 0:
            device = result["value"][0]
            is_managed = device.get("isManaged", False)
            is_synced = device.get("onPremisesSyncEnabled", False)
            
            if is_managed and is_synced:
                return f"Defender ATP: Device '{device_name}' is successfully enrolled and synced."
            elif is_managed:
                return f"Defender ATP: Device '{device_name}' is enrolled but not synced."
            else:
                return f"Defender ATP: Device '{device_name}' is not enrolled in Defender ATP."
        else:
            return f"Defender ATP: Device '{device_name}' not found."
    except requests.RequestException as e:
        return f"Defender ATP: An error occurred: {str(e)}"

def display_menu():
    print("\nMenu:")
    print("1. Check with VirusTotal")
    print("2. Check with urlscan.io")
    print("3. Check with Cisco Talos")
    print("4. Check Defender ATP enrollment")
    print("5. Exit")

def main():
    url = input("Enter the URL you want to check: ")
    
    while True:
        display_menu()
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            result = check_virustotal(url)
        elif choice == '2':
            result = check_urlscan(url)
        elif choice == '3':
            result = check_cisco_talos(url)
        elif choice == '4':
            device_name = input("Enter the device name to check Defender ATP enrollment: ")
            result = check_defender_atp_enrollment(device_name)
        elif choice == '5':
            print("Exiting...")
            break
        else:
            result = "Invalid choice. Please select 1-5."

        print("\nResult:")
        print(result)

if __name__ == "__main__":
    main()
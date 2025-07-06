import requests
import sys

API_KEY = "VIRUSTOTAL_API_KEY_HERE"

def main():

    hash = sys.argv[1]
    headers = {
        "accept": "application/json",
        "X-Apikey": API_KEY
    }

    response = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers=headers)

    if response.status_code != 200:
        print(f"> Error: Hash not found")
        return

    json_data = response.json()

    try:
        detections = json_data['data']['attributes']['last_analysis_stats']['malicious']
        detections = f"{detections}/72 Detections"

        link_to_scan = json_data['data']['links']['self']

        yara_results = response.json()['data']['attributes'].get('crowdsourced_yara_results', [])


        if not yara_results:
            print("> No YARA results found.")
        else:
            ruleset_names = [entry['ruleset_name'] for entry in yara_results]
            print(f"> Rule: {ruleset_names}")

        print(f"> {detections}")
        print(f"> Sample: {link_to_scan}")

    except KeyError as e:
        print(f"KeyError: {e}")
        print("Full response:")
        print(json_data)

if __name__ == "__main__":
    main()

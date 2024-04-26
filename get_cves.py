if False:
    # import requests

    # def make_request():
    #     # Set publication start and end dates for 2022 and 2023
    #     pub_start_date = '2022-01-01T00:00:00Z'
    #     pub_end_date = '2023-12-31T23:59:59Z'

    #     query_params = {
    #         'resultsPerPage': '100',
    #         'pubStartDate': pub_start_date,
    #         'pubEndDate': pub_end_date
    #     }
    #     headers = {'api_key': '6f726d1a-039c-4ad7-88c6-cf12ac3ba800'}
    #     response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=query_params, headers=headers)

    #     if response.status_code == 200:
    #         return response.json()  # or however you wish to process/aggregate the results
    #     else:
    #         print(f"Request failed with status code: {response.status_code}")
    #         return None

    # if __name__ == "__main__":
    #     data = make_request()
    #     # Process or aggregate your results here
    #     if data and "result" in data and "CVE_Items" in data["result"]:
    #         vulnerabilities = data["result"]["CVE_Items"]

    #         # Iterate through the CVE items in the response
    #         for cve_item in vulnerabilities:
    #             cve_id = cve_item.get('cve', {}).get('CVE_data_meta', {}).get('ID')
    #             description_data = cve_item.get('cve', {}).get('description', {}).get('description_data', [])
    #             description = description_data[0].get('value') if description_data else "No description available."

    #             print(f"CVE ID: {cve_id}\nDescription: {description}\n")

    #             # Iterate through the references
    #             references = cve_item.get('cve', {}).get('references', {}).get('reference_data', [])
    #             for reference in references:
    #                 if 'patch' in reference.get('tags', []) or 'Third Party Advisory' in reference.get('tags', []):
    #                     print(f"Possible Patch/Repo URL: {reference.get('url')}")
    #             print("\n" + "-"*80 + "\n")
    #     else:
    #         print("No data found or an error occurred")

    import requests
    from datetime import datetime, timedelta

    def date_range_segments(start_date, end_date, delta_days=120):
        current_date = start_date
        while current_date < end_date:
            segment_end = min(current_date + timedelta(days=delta_days - 1), end_date)
            yield (current_date, segment_end)
            current_date = segment_end + timedelta(days=1)

    def make_request():
        query_params = {
            'resultsPerPage': '2000',
            'startIndex': '200000',
            # "lastModEndDate": pub_end_date.strftime('%Y-%m-%dT00:00:00.000Z')
        }

        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=query_params)

        if response.status_code == 200:
            return response.json()["vulnerabilities"]
        else:
            print(f"Request failed with status code: {response.status_code}")
            return []

    # def fetch_cves_with_references(start_year, end_year):
    #     start_date = datetime(start_year, 1, 1)
    #     end_date = datetime(end_year, 12, 31)

    #     all_cves = []
    #     for segment_start, segment_end in date_range_segments(start_date, end_date):
    #         cves = make_request(segment_start, segment_end)
    #         all_cves.extend(cves)

    #     return all_cves


    keywords = ['c++', 'c ', ' c/', '.c ', '.cpp', 'stdlib.h', 'stdio.h']

    def is_c_or_cpp(cve_entry):
        descriptions = cve_entry.get('cve', {}).get('descriptions', [])
        for description in descriptions:
            desc_text = description.get('value', '').lower()
            for keyword in keywords:
                if keyword in desc_text:
                    return True
        return False

    if __name__ == "__main__":
        cves = make_request()
        for cve in cves:
            if is_c_or_cpp(cve):
                cve_id = cve.get('cve', {}).get('CVE_data_meta', {}).get('ID')
                descriptions = cve.get('cve', {}).get('descriptions', [])
                description = next((d.get('value') for d in descriptions if d.get('lang') == 'en'), None)

                references = cve.get('cve', {}).get('references', [])
                for reference in references:
                    if "github" in reference:
                        print(f"CVE ID: {cve_id}\nDescription: {description}\n")
                        print(f"Reference: {reference}")
                        print("\n" + "-"*80 + "\n")

        # for cve_item in cves:
        #     cve_id = cve_item.get('cve', {}).get('id')

        #     descriptions = cve_item.get('cve', {}).get('descriptions', [])
        #     description = next((d.get('value') for d in descriptions if d.get('lang') == 'en'), None)

        #     references = cve_item.get('cve', {}).get('references', [])
        #     keywords = ['c++', 'c ', ' c/', '.c ', '.cpp', 'stdlib.h', 'stdio.h']

        #     for reference in references:
        #         if "github" in reference:
        #             print(f"CVE ID: {cve_id}\nDescription: {description}\n")
        #             print(f"Reference: {reference}")


import requests
import json
from datetime import datetime, timedelta

from vuln_scanner_helper import make_request

# Base URL for the NVD CVE API
base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'

def fetch_cves_for_date_range(start_date, end_date):
    """
    Fetches CVEs for the specified date range.
    """
    headers = {
        'resultsPerPage': '2000',  # Adjust based on your needs and rate limits
        'pubStartDate': start_date.isoformat() + 'Z',
        'pubEndDate': end_date.isoformat() + 'Z'
    }

    cves = []
    current_start_index = 0
    total_results = 1  # Initialize to enter the loop

    while current_start_index < total_results:
        headers['startIndex'] = str(current_start_index)
        try:
            response = make_request(base_url, headers=headers)
        except Exception as e:
            print("Failed to fetch CVEs:", e)
            break
        if response.status_code == 200:
            data = response.json()
            cves.extend(data.get('vulnerabilities', []))
            total_results = data.get('totalResults', 0)
            current_start_index += len(data.get('vulnerabilities', []))
        else:
            print(f"Failed to fetch CVEs, status code: {response.status_code}")
            break

    return cves

def fetch_cves_for_year(year):
    """
    Fetches CVEs for the specified year, considering the 120-day date range limit.
    """
    cves = []
    start_date = datetime(year, 1, 1)
    end_date = datetime(year, 12, 31)

    while start_date < end_date:
        # Calculate the end date for the current segment, ensuring it's within 120 days
        segment_end_date = min(start_date + timedelta(days=119), end_date)
        cves.extend(fetch_cves_for_date_range(start_date, segment_end_date))

        # Move to the next segment
        start_date = segment_end_date + timedelta(days=1)

    return cves



def main():
    years = [2024, 2023, 2022]
    for year in years:
        print(f"Fetching CVEs for {year}...")
        cves = fetch_cves_for_year(year)
        print(f"Fetched {len(cves)} CVEs for {year}.")

        # Process or store the CVEs as needed
        # For demonstration, we'll just print the count
        # You can extend this to save the data to a file or database

        # I need write cvs to a yml and json file
        with open(f'cves_{year}.json', 'w') as f:
            json.dump(cves, f, indent=4)

if __name__ == '__main__':
    main()

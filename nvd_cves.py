import requests
import json
import os
import time
from datetime import datetime, timedelta
from vuln_scanner_helper import make_request, remove_formatting_changes_from_single_file, append_to_yaml

ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
HEADERS = {'Authorization': f'token {ACCESS_TOKEN}'} if ACCESS_TOKEN else {}

import logging

logging.basicConfig(level=logging.INFO)

def fetch_cves_by_date_range(start_date, end_date, retries=3):
    results = []
    start_index = 0
    page_size = 2000  # Adjust as needed, up to the maximum allowed by the API
    has_more = True

    while has_more:
        start_date_str = start_date.strftime('%Y-%m-%dT00:00:00Z')
        end_date_str = end_date.strftime('%Y-%m-%dT00:00:00Z')
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start_date_str}&pubEndDate={end_date_str}&resultsPerPage={page_size}&startIndex={start_index}"
        try:
            response = requests.get(url)
        except requests.exceptions.ConnectTimeout:
            print("Connection timeout. Retrying...")
            retries -= 1
            if retries == 0:
                print("Max retries reached. Aborting.")
                break
            time.sleep(60)
            fetch_cves_by_date_range(start_date, end_date, retries)
        if response.status_code == 200:
            data = response.json()
            results.extend(data.get('vulnerabilities', []))
            # Check if there are more items to fetch
            total_results = data.get('totalResults', 0)
            has_more = start_index + page_size < total_results
            start_index += page_size
        else:
            print(f"Failed to fetch CVEs: {response.status_code}")
            return results

    return results


def fetch_cves(start_date: datetime, end_date: datetime = datetime.utcnow()):
    delta = timedelta(days=120)
    results = []

    while start_date < end_date:
        current_end_date = min(start_date + delta, end_date)
        # Fetch the CVEs in the current date range
        result = fetch_cves_by_date_range(start_date, current_end_date)
        results.append(result)
        start_date = current_end_date + timedelta(days=1)  # Move start date forward to start just after the last range

    return results

# if __name__ == "__main__":
#     start_date = datetime(2022, 1, 1)

#     print(f"Fetching CVEs starting from {start_date}...")
#     cves = fetch_cves(start_date)

#     with open('cves.json', 'w') as f:
#         f.write(json.dumps(cves, indent=4))


# reade the cves.json file and make a list of all the cves which contains patch information github commit or gitlab commit
def read_cves():
    with open('cves.json', 'r') as f:
        cves = json.load(f)
    return cves

def get_cves_with_patch_info(cves):
    cves_with_patch_info = []
    for cves in cves:
        for cve in cves:
            cve = cve['cve']
            if 'references' in cve:
                for reference in cve['references']:
                    reference_url = reference['url']
                    if ('github.com' in reference_url or 'gitlab.com' in reference_url) and 'commit' in reference_url:
                        cves_with_patch_info.append(cve)
                        break
    return cves_with_patch_info

if __name__ == "__main__":
    cves = read_cves()
    cves_with_patch_info = get_cves_with_patch_info(cves)
    for cve in cves_with_patch_info:
        references = cve['references']
        identifiers = []
        identifiers.append(cve['id'])
        try:
            identifier = next((weakness['description'][0]['value'] for weakness in cve['weaknesses'] if weakness['description']), '')
            identifiers.append(identifier)
        except:
            pass
        diff_content = []
        title = next((desc['value'] for desc in cve['descriptions'] if desc['lang'] == 'en'), '')
        for reference in references:
                references_url = reference['url']
                if "commit" in references_url and 'github.com' in references_url:
                    # Handle GitHub URLs
                    parts = references_url.split('/')
                    owner = parts[3]
                    repo = parts[4]
                    commit_hash = parts[6]
                    api_url = f'https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}'
                    try:
                        response = make_request(api_url, headers=HEADERS)
                    except Exception as e:
                        print(f"Failed to get GitHub commit {commit_hash}: {e}")
                        continue
                    if response.status_code == 200:
                        data = response.json()
                        files = data['files']
                        for file in files:
                            filename = file['filename']
                            if filename.endswith(('.c', '.cpp')):
                                try:
                                    patch_without_formatting_changes = remove_formatting_changes_from_single_file(file['patch'])
                                except Exception as e:
                                    print(f"Failed to remove formatting changes from {filename}: {e}")
                                    continue
                                if patch_without_formatting_changes != '':
                                    diff_content.append(f"--- a/{filename}\n+++ b/{filename}\n{patch_without_formatting_changes}")
                    else:
                        print('Failed to get GitHub commit', commit_hash)
                elif "commit" in references_url and 'gitlab.com' in references_url:
                    # Handle GitLab URLs
                    parts = references_url.split('/')
                    project_id = parts[3] + '%2F' + parts[4]
                    commit_hash = parts[7]
                    api_url = f'https://gitlab.com/api/v4/projects/{project_id}/repository/commits/{commit_hash}/diff'
                    try:
                        response = make_request(api_url)
                    except Exception as e:
                        print(f"Failed to get GitLab commit {commit_hash}: {e}")
                        continue
                    if response.status_code == 200:
                        data = response.json()
                        diffs = []
                        try:
                            diffs = [(item['new_path'], item['diff']) for item in data]
                        except:
                            pass
                        for file_name, diff in diffs:
                            if file_name.endswith(('.c', '.cpp')):
                                patch_without_formatting_changes = remove_formatting_changes_from_single_file(diff)
                                if patch_without_formatting_changes != '':
                                    diff_content.append(f"--- a/{file_name}\n+++ b/{file_name}\n{patch_without_formatting_changes}")
                    else:
                        print('Failed to get GitLab commit', commit_hash)

        if not diff_content:
            continue

        data_dict = {
            'title': title,
            'identifiers': identifiers,
            'overview': title,
            'references': references,
            'diff_content': diff_content
        }

        append_to_yaml("nvd_cves.yml", data_dict)

    print(f"Found {len(cves_with_patch_info)} CVEs with patch information.")
    print(cves_with_patch_info)
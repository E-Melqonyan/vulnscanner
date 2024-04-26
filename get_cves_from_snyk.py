import requests
import json
import re
from html import unescape
from bs4 import BeautifulSoup, NavigableString

import logging

logging.basicConfig(level=logging.INFO)

from vuln_scanner_helper import remove_formatting_changes_from_single_file, append_to_yaml, make_request

base_url = "https://security.snyk.io"

headers = {
    "Authorization": "token 713ddde6-431e-427d-a611-15f4d155da41",
    "Content-Type": "application/vnd.api+json"
}

#  finde and return all urls from the page
def get_urls(url):
    response = make_request(url, headers=headers)
    if response.status_code == 200:
        html_content = response.text.encode('utf-8').decode('unicode_escape')
        vuln_urls = re.findall(r'vulnUrl:"([^"]*)"', html_content)
        return vuln_urls
    else:
        print("Failed to retrieve HTML data. Status code:", response.status_code)
        return None

# gen n times urls every page has 30 vulnerabilities need return list of n urls
def gen_vuln_urls(n):
    vuln_urls = []
    i = 1
    while len(vuln_urls) < n:
        new_vuln_urls = get_urls(f"{base_url}/vuln/unmanaged/{i}")
        if not new_vuln_urls:
            break
        vuln_urls += new_vuln_urls
        print(f"{base_url}/vuln/unmanaged/{i}")
        i += 1
    return vuln_urls[:n]

def main():
    vuln_urls = gen_vuln_urls(10000)
    for url in vuln_urls:
        url_of_cve = f"{base_url}/{url}"
        response = make_request(url_of_cve, headers=headers)
        if response.status_code == 200:
            try:
                html_content = response.text.encode('utf-8').decode('unicode_escape')
            except Exception as e:
                print(f"Failed to decode response: {e}")
                continue
            match = re.search(r'data:\[{(.*)}\]', html_content, re.DOTALL)
            data_string = match.group(1)
            title = re.search(r'title:"([^"]*)"', data_string).group(1)
            identifiers = re.search(r'identifiers:\{([^}]*)\}', data_string).group(1)
            vuln_description = re.search(r'vulnDescription:\{([^}]*)\}', data_string).group(1)
            overview_match = re.search(r'Overview:"<p>(.*?)<\/p>', vuln_description)
            overview = ""
            if overview_match:
                overview_match = unescape(overview_match.group(1))
                overview = overview_match.replace('<code>', '`').replace('</code>', '`')
            references_match = re.findall(r'<a href="(.*?)">(.*?)</a>', vuln_description)
            references = {name: link for link, name in references_match}
            diff_content = []
            for  reference in references:
                references_url = references[ reference]
                if ("Github Commit" in  reference or "GitHub Commit" in  reference) and 'github.com' in references_url:
                    # Handle GitHub URLs
                    parts = references_url.split('/')
                    owner = parts[3]
                    repo = parts[4]
                    commit_hash = parts[6]
                    api_url = f'https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}'
                    try:
                        response = make_request(api_url)
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
                elif ("Gitlab Commit" in  reference or "GitLab Commit" in  reference) and 'gitlab.com' in references_url:
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
                        diffs = [(item['new_path'], item['diff']) for item in data]
                        for file_name, diff in diffs:
                            if file_name.endswith(('.c', '.cpp')):
                                patch_without_formatting_changes = remove_formatting_changes_from_single_file(diff)
                                if patch_without_formatting_changes != '':
                                    diff_content.append(f"--- a/{file_name}\n+++ b/{file_name}\n{patch_without_formatting_changes}")
                    else:
                        print('Failed to get GitLab commit', commit_hash)
                elif "Git Commit" in  reference and 'git.kernel.org' in references_url:
                    # Function to iterate over sibling elements until the next 'head' or end
                    def get_block_siblings(start_element):
                        elements = [start_element]
                        for sibling in start_element.next_siblings:
                            if isinstance(sibling, NavigableString):
                                continue
                            if sibling.get('class') == ['head']:
                                break
                            elements.append(sibling)
                        return elements

                    try:
                        response = make_request(references_url)
                    except Exception as e:
                        print(f"Failed to get git.kernel.org commit: {e}")
                        continue
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        diff_container = soup.find('table', class_='diff')
                        # Find all 'head' divs and their related blocks
                        blocks = [get_block_siblings(head) for head in diff_container.find_all('div', class_='head')]
                        for block in blocks:
                            file_name = block[0].text.split(' ')[-1]
                            if file_name.endswith(('.c', '.cpp')):
                                for element in block[1:]:
                                    diff += f"{element.text}\n"
                                patch_without_formatting_changes = remove_formatting_changes_from_single_file(diff)
                                if patch_without_formatting_changes != '':
                                    diff_content.append(f"--- a/{file_name}\n+++ b/{file_name}\n{patch_without_formatting_changes}")
                    else:
                        print('Failed to get git.kernel.org commit', url)

            if not diff_content:
                continue

            data_dict = {
                'title': title,
                'identifiers': identifiers,
                'overview': overview,
                'references': references,
                'diff_content': diff_content
            }

            append_to_yaml("new_yml_snyk.yml", data_dict)
        else:
            print("Failed to retrieve HTML data. Status code:", response.status_code)


if __name__ == "__main__":
    main()

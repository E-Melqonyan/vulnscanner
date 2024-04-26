import os
from collections import defaultdict
from bs4 import BeautifulSoup

def extract_details_from_report(report_path):
    """Extract the repository, file name, and CVE/CWE identifier from the report file."""
    with open(report_path, 'r', encoding='utf-8') as file:
        soup = BeautifulSoup(file.read(), 'html.parser')
    source_div = soup.find('div', class_='source')
    filepath_div = None
    try:
        filepath_div = source_div.find('div', class_='filepath')
    except AttributeError:
        print(f'Error parsing {report_path}')
    if filepath_div:
        filepath = filepath_div.get_text(strip=True)
        parts = filepath.split('/')
        identifier = os.path.splitext(os.path.basename(report_path))[0].split('_')[-1]  # Extract CVE/CWE identifier
        if 'cloned_repos' in parts:
            repo_index = parts.index('cloned_repos') + 1
            repo_name = parts[repo_index]
            file_name = parts[-1]
            return repo_name, file_name, identifier
    return None, None, None

def generate_reports_structure(reports_dir, output_dir):
    reports_structure = defaultdict(list)

    # Extract details from each report and organize by repository
    for report_file in os.listdir(reports_dir):
        if report_file.endswith('.html') and report_file != 'index.html':
            report_path = os.path.join(reports_dir, report_file)
            repo_name, file_name, identifier = extract_details_from_report(report_path)
            if repo_name and file_name:
                reports_structure[repo_name].append((file_name, report_file, identifier))

    # Generate index pages for each repository
    for repo, files in reports_structure.items():
        repo_page_path = os.path.join(output_dir, f'{repo}_index.html')
        with open(repo_page_path, 'w', encoding='utf-8') as repo_page:
            repo_page.write(f'<html><head><title>{repo} Reports</title></head><body>')
            repo_page.write(f'<h1>{repo} - File Reports</h1><ul>')
            for file_name, report_file, identifier in files:
                repo_page.write(f'<li><a href="{report_file}">{file_name} {identifier}</a></li>')
            repo_page.write('</ul></body></html>')

    # Generate the main index page
    with open(os.path.join(output_dir, 'index.html'), 'w', encoding='utf-8') as main_index:
        main_index.write('<html><head><title>Main Index</title></head><body>')
        main_index.write('<h1>Repository Reports</h1><ul>')
        for repo in reports_structure:
            main_index.write(f'<li><a href="{repo}_index.html">{repo}</a></li>')
        main_index.write('</ul></body></html>')

# Usage example
reports_dir = 'outputs_test'
output_dir = 'outputs_test'
os.makedirs(output_dir, exist_ok=True)
generate_reports_structure(reports_dir, output_dir)

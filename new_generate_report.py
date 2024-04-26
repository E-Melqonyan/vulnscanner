# import os
# from collections import defaultdict
# from bs4 import BeautifulSoup

# def create_html_head(title="Report Page"):
#     """Generates the HTML head section."""
#     return f'''
#     <head>
#         <meta charset="UTF-8">
#         <meta name="viewport" content="width=device-width, initial-scale=1.0">
#         <title>{title}</title>
#         <link rel="stylesheet" href="style.css"> <!-- Ensure you have a style.css or remove this line -->
#     </head>
#     '''

# def extract_details_from_report(report_path):
#     """Extract the repository, file name, and CVE/CWE identifier from the report file."""
#     with open(report_path, 'r', encoding='utf-8') as file:
#         soup = BeautifulSoup(file.read(), 'html.parser')
#     source_div = soup.find('div', class_='source')
#     filepath_div = None
#     try:
#         filepath_div = source_div.find('div', class_='filepath')
#     except AttributeError:
#         print(f'Error parsing {report_path}')
#     if filepath_div:
#         filepath = filepath_div.get_text(strip=True)
#         parts = filepath.split('/')
#         identifier = os.path.splitext(os.path.basename(report_path))[0].split('_')[-1]  # Extract CVE/CWE identifier
#         if 'cloned_repos' in parts:
#             repo_index = parts.index('cloned_repos') + 1
#             repo_name = parts[repo_index]
#             file_name = parts[-1]
#             return repo_name, file_name, identifier
#     return None, None, None

# def generate_reports_structure(reports_dir, output_dir):
#     reports_structure = defaultdict(lambda: defaultdict(list))

#     print(f"Generating reports from: {reports_dir}")
#     for report_file in os.listdir(reports_dir):
#         if report_file.endswith('.html') and report_file != 'index.html':
#             report_path = os.path.join(reports_dir, report_file)
#             repo_name, file_name, cve_identifier = extract_details_from_report(report_path)
#             print(f"Report added: {report_file} for {repo_name}")
#             if repo_name:
#                 reports_structure[repo_name][cve_identifier].append((file_name, report_file, cve_identifier))
#                 print("Completed extraction. Generating index...")

#     with open(os.path.join(output_dir, 'index.html'), 'w', encoding='utf-8') as main_index:
#         main_index.write(f'<html>{create_html_head("Main Index")}<body>')
#         main_index.write('<h1>Repository CVE Reports</h1>')
#         for repo, cves in reports_structure.items():
#             main_index.write(f'<h2>{repo}</h2>')
#             main_index.write('<table border="1"><tr><th>CVE</th><th>Report Files</th></tr>')
#             for cve, files in cves.items():
#                 main_index.write(f'<tr><td><a href="https://nvd.nist.gov/vuln/detail/{cve}">{cve}</a></td><td>')
#                 for file_name, report_file, cve_identifier in files:
#                     main_index.write(f'<a href="{report_file}">{file_name}</a><br>')
#                 main_index.write('</td></tr>')
#             main_index.write('</table>')
#         main_index.write('</body></html>')

# # Adjust paths as necessary
# reports_dir = 'outputs_new'
# output_dir = 'outputs_new'
# generate_reports_structure(reports_dir, output_dir)

import os
from collections import defaultdict
from bs4 import BeautifulSoup

def create_html_head(title="Report Page"):
    """Generates the HTML head section with link to CSS."""
    return f'''
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <link rel="stylesheet" href="style.css">
    </head>
    '''

def generate_css_style(output_dir):
    """Generates the CSS file."""
    css_content = """
body {
    font-family: Arial, sans-serif;
    margin: 20px;
    background-color: #f0f0f0;
}
h1, h2 {
    color: #333;
}
table {
    width: 100%;
    border-collapse: collapse;
}
table, th, td {
    border: 1px solid #999;
    padding: 8px;
    text-align: left;
}
th {
    background-color: #4CAF50;
    color: white;
}
tr:nth-child(even) {
    background-color: #f2f2f2;
}
a {
    color: #007bff;
    text-decoration: none;
}
a:hover {
    text-decoration: underline;
}
"""
    with open(os.path.join(output_dir, 'style.css'), 'w') as css_file:
        css_file.write(css_content)

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

def generate_repository_page(repo_name, cves, output_dir):
    """Generates an HTML page for a specific repository with its CVEs and report files."""
    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Define the path for the repository's HTML page
    repo_page_path = os.path.join(output_dir, f"{repo_name}.html")

    # Open the file for writing
    with open(repo_page_path, 'w', encoding='utf-8') as repo_page:
        # Write the HTML head including the title and link to the CSS file
        repo_page.write(f'<html>{create_html_head(repo_name)}<body>')
        repo_page.write(f'<h1>Report for {repo_name}</h1>')
        repo_page.write('<table><tr><th>CVE/CWE Identifier</th><th>Report Files</th></tr>')

        # Loop through each CVE and its associated files for the current repository
        for cve, files in cves.items():
            # Write a table row for the CVE/CWE identifier linking to the NVD page
            repo_page.write(f'<tr><td><a href="https://nvd.nist.gov/vuln/detail/{cve}">{cve}</a></td><td>')
            # Loop through each file associated with the current CVE/CWE identifier
            for file_name, report_file, _ in files:
                # Write a link to the report file
                repo_page.write(f'<a href="{report_file}">{file_name}</a><br>')
            repo_page.write('</td></tr>')

        # Close the table and the HTML body
        repo_page.write('</table></body></html>')

def generate_reports_structure(reports_dir, output_dir):
    """Generates the structure of reports, including the main index and individual repository pages."""
    reports_structure = defaultdict(lambda: defaultdict(list))
    for report_file in os.listdir(reports_dir):
        if report_file.endswith('.html') and report_file != 'index.html':
            report_path = os.path.join(reports_dir, report_file)
            repo_name, file_name, cve_identifier = extract_details_from_report(report_path)
            if repo_name:
                reports_structure[repo_name][cve_identifier].append((file_name, report_file, cve_identifier))

    os.makedirs(output_dir, exist_ok=True)
    generate_css_style(output_dir)  # Generate CSS file

    # Generate main index
    with open(os.path.join(output_dir, 'index.html'), 'w', encoding='utf-8') as main_index:
        main_index.write(f'<html>{create_html_head("Main Index")}<body>')
        main_index.write('<h1>Repository CVE Reports</h1>')
        for repo in reports_structure:
            main_index.write(f'<h2><a href="{repo}.html">{repo}</a></h2>')
        main_index.write('</body></html>')

    # Generate pages for each repository
    for repo, cves in reports_structure.items():
        generate_repository_page(repo, cves, output_dir)

# Adjust paths as necessary
reports_dir = 'outputs'
output_dir = 'outputs'
generate_reports_structure(reports_dir, output_dir)

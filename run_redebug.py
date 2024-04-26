import os
import subprocess
import multiprocessing
import yaml
import hashlib
import shutil
import re
import logging
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from yaml.loader import SafeLoader

from vuln_scanner_helper import get_repos
from utilitys import attach_debugger

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

WORKING_DIR = Path(__file__).parents[0]

CLONED_REPOS_DIR = WORKING_DIR / 'cloned_repos'
OUTPUTS_DIR = WORKING_DIR / 'outputs'
NUM_PROCESSES = multiprocessing.cpu_count() - 1


def calculate_hash_from_strings(string1, string2):
    combined_string = string1 + string2
    sha256_hash = hashlib.sha256(combined_string.encode()).hexdigest()
    return sha256_hash


def get_patches_from_old_yml():
    with open('vulnerable_commits.yml', 'r') as f:
        yaml_data = yaml.load(f, Loader=SafeLoader)

    patches_path = os.path.join(os.getcwd(), 'patches')

    if os.path.exists(patches_path):
        shutil.rmtree(patches_path)
    os.makedirs(patches_path, exist_ok=True)

    patch_identifier_pairs = []
    index = 0

    for data in yaml_data:
        commit_message = data.get('commit_message', '')
        patches = data.get('commit_diff', [])

        # Search for CVE and CWE identifiers in the commit message
        cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', commit_message)
        cwe_ids = re.findall(r'CWE-\d+', commit_message)

        identifier = None
        if cve_ids:
            identifier = cve_ids[0]
        elif cwe_ids:
            identifier = cwe_ids[0]

        for patch in patches:
            index += 1
            patch_filename = os.path.join(patches_path, f'patch_{index}.diff')

            with open(patch_filename, 'w') as patch_file:
                patch_file.write(patch)

            patch_identifier_pairs.append((patch_filename, identifier))

    return patch_identifier_pairs

def get_patches():
    with open('nvd_cves.yml', 'r') as f:
        yaml_data = yaml.load(f, Loader=SafeLoader)

    patches_path = WORKING_DIR / 'patches'

    if os.path.exists(patches_path):
        shutil.rmtree(patches_path)
    os.makedirs(patches_path, exist_ok=True)

    patch_identifier_pairs = []
    index = 0

    for data in yaml_data:
        title = data.get('title', '')
        patches = data.get('diff_content', [])
        identifiers = data.get('identifiers', '')

        cve_ids = []
        cwe_ids = []

        # If identifiers is a string, search for CVE and CWE identifiers in the string
        if isinstance(identifiers, str):
            cve_ids = re.findall(r'CVE-\d{4}-\d{4,7}', identifiers)
            cwe_ids = re.findall(r'CWE-\d+', identifiers)
        # If identifiers is a dictionary, get the CVE and CWE values directly
        elif isinstance(identifiers, dict):
            cve_ids = identifiers.get('CVE', [])
            cwe_ids = identifiers.get('CWE', [])
        # If identifiers is a list, iterate over the list and extract the CVE and CWE values from the strings
        elif isinstance(identifiers, list):
            for identifier in identifiers:
                if identifier.startswith('CVE'):
                    cve_ids.append(identifier)
                elif identifier.startswith('CWE'):
                    cwe_ids.append(identifier)

        identifier = None
        if cve_ids:
            identifier = cve_ids[0]
        elif cwe_ids:
            identifier = cwe_ids[0]

        for patch in patches:
            index += 1
            patch_filename = os.path.join(patches_path, f'patch_{index}.diff')

            with open(patch_filename, 'w') as patch_file:
                patch_file.write(patch)

            patch_identifier_pairs.append((patch_filename, identifier))

    return patch_identifier_pairs


def clone_repo(repo):
    """Clone repositories if they haven't been cloned already."""
    os.makedirs(CLONED_REPOS_DIR, exist_ok=True)
    repo_name = repo.split('/')[-1]
    repo_path = os.path.join(CLONED_REPOS_DIR, repo_name)
    if not os.path.exists(repo_path):
        logging.info(f"Cloning repository '{repo_name}'...")
        subprocess.run(["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", repo_path], check=True)
    else:
        logging.info(f"Repository '{repo_name}' already exists. Skipping.")

    # return the path to the cloned repository
    return repo_path

def find_c_cpp_files(directory):
    """Find .c and .cpp files, excluding those in paths containing 'test' or 'tests'."""
    all_files = []
    for root, dirs, files in os.walk(directory):
        if 'test' in root.lower().split(os.sep) or 'tests' in root.lower().split(os.sep):
            continue  # Skip directories with 'test' or 'tests' in the path
        for file in files:
            if (file.endswith('.c') or file.endswith('.cpp')) and 'test' not in file.lower() and 'tests' not in file.lower():
                all_files.append(os.path.join(root, file))
    return all_files

def run_redebug_single(patch_path, source_path, identifier=None):
    """Run redebug.py on a single source file with a specified patch, capturing and displaying output."""
    output_path = WORKING_DIR / f'outputs/{calculate_hash_from_strings(patch_path, source_path)}{f"_{identifier}.html" if identifier is not None else ".html"}'
    command = ["python3", WORKING_DIR / "redebug/redebug.py", patch_path, source_path, "--output_path", output_path]
    result = subprocess.run(command, capture_output=True, text=True)
    logger.info(result.stdout)  # Display stdout from redebug.py
    if result.stderr:
        logger.error(f"Error processing {source_path} with {patch_path}: {result.stderr}")

def process_repository(repo_name, patch_identifier_pairs):
    """Process a repository with patches, ensuring all files are processed."""

    repo_path = clone_repo(repo_name)
    source_paths = find_c_cpp_files(repo_path)
    logger.info(f"Processing {repo_path} with {len(source_paths)} source files...")

    # Generate tasks for each combination of source file and patch
    tasks = [(patch_path, source, identifier) for (patch_path, identifier) in patch_identifier_pairs for source in source_paths]

    jobs = []
    with ProcessPoolExecutor(max_workers=NUM_PROCESSES) as executor:
        # Submit tasks including the identifier
        jobs.append({executor.submit(run_redebug_single, patch, source, identifier): (patch, source, identifier) for patch, source, identifier in tasks})

    for job in jobs:
        for future in job:
            patch, source, identifier = job[future]
            try:
                future.result()
                logger.info(f"Task completed for source: {source}, patch: {patch}, identifier: {identifier}")
            except Exception as e:
                logger.error(f"Error processing source: {source} with patch: {patch}, identifier: {identifier}: {e}")
    logger.info(f"Processing complete of {repo_path}")

def main():
    # repos = get_repos(300)
    # repo_names = [repo['node']['nameWithOwner'] for repo in repos]

    repo_names = ['redis/redis']

    if os.path.exists(OUTPUTS_DIR):
        shutil.rmtree(OUTPUTS_DIR)
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    patch_identifier_pairs = get_patches()

    jobs = []
    # Process each repository in parallel using ProcessPoolExecutor
    with ProcessPoolExecutor(max_workers=NUM_PROCESSES) as executor:
        for repo_name in repo_names:
            jobs.append(executor.submit(process_repository, repo_name, patch_identifier_pairs))

    for job in jobs:
        job.result()

if __name__ == '__main__':
    # attach_debugger()
    main()


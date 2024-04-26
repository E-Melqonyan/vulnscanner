import os
import re
import yaml
import requests
import argparse
import logging
import threading
import time
import datetime

from retrying import retry
from requests.exceptions import HTTPError, ConnectionError, Timeout

from utilitys import attach_debugger, time_it

# Constants
VULNERABLE_COMMITS_FILE_PATH = 'vulnerable_commits.yml'
GITHUB_API_URL = 'https://api.github.com/graphql'
KEYWORDS = ['CVE', 'Vuln', 'Vulnerability', 'CWE']
PROCESS_COUNT = 16
WORKER_COUNT = 16

# Initialize logging
logging.basicConfig(level=logging.INFO)

class VulnerabilitySearcher:
    """
    A class that searches for vulnerable commits in GitHub repositories.
    """

    def __init__(self, access_token):
        if access_token is None:
            logging.info('Please set the ACCESS_TOKEN environment variable')
            exit(1)
        self.ACCESS_TOKEN = access_token
        self.HEADERS = {'Authorization': f'token {self.ACCESS_TOKEN}'}

    def check_for_non_formating_changes(self, patch_content):
        def normalize_line(line):
            """Remove all whitespace from a line for comparison."""
            return re.sub(r'\s+', '', line)

        """Check if a patch contains only formatting changes, considering all scenarios, from a string."""
        lines = patch_content.split('\n')

        # Variables to keep track of code changes
        added_lines = []
        removed_lines = []

        # Parse the patch file
        for line in lines:
            if line.startswith('+') and not line.startswith('+++'):
                normalized_line = normalize_line(line[1:])  # Normalize and check if not empty
                if normalized_line:  # Consider only non-empty lines after normalization
                    added_lines.append(normalized_line)
            elif line.startswith('-') and not line.startswith('---'):
                normalized_line = normalize_line(line[1:])  # Normalize and check if not empty
                if normalized_line:  # Consider only non-empty lines after normalization
                    removed_lines.append(normalized_line)

        # Check for additions or deletions that are not formatting changes
        if added_lines or removed_lines:  # If there are any added or removed lines
            # Compare added and removed lines
            for added, removed in zip(added_lines, removed_lines):
                if added != removed:
                    return False

            # Additional checks for unmatched added or removed lines
            if len(added_lines) != len(removed_lines):
                return False

        return True

    def split_git_patch_into_blocks(self, patch_content):
        # Split the patch into lines
        lines = patch_content.split('\n')

        # Initialize variables to hold the blocks and the current block being processed
        blocks = []
        current_block = []

        # Iterate over each line in the patch
        for line in lines:
            if line.startswith('@@'):  # This line indicates the start of a new hunk/block
                # If there is a current block being built, add it to the blocks list
                if current_block:
                    blocks.append('\n'.join(current_block))
                    current_block = [line]  # Start a new block with the current line
                else:
                    # This handles the case where the first line of the patch is a hunk header
                    current_block.append(line)
            else:
                # Add the current line to the ongoing block
                current_block.append(line)

        # Don't forget to add the last block to the list
        if current_block:
            blocks.append('\n'.join(current_block))

        return blocks

    def remove_formatting_changes_from_single_file(self, patch_content):
        new_patch_content = []
        patch_blocks = self.split_git_patch_into_blocks(patch_content)
        for block in patch_blocks:
            if not self.check_for_non_formating_changes(block):
                new_patch_content.append(block)

        return '\n'.join(new_patch_content)


    def append_to_yaml(self, file_path, new_data):
        # Check if the file exists and has content
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            # File exists and has content, read the existing data
            with open(file_path, 'r') as file:
                try:
                    existing_data = yaml.safe_load(file) or []
                except yaml.YAMLError as exc:
                    print(f"Error reading YAML file: {exc}")
                    return
        else:
            # File does not exist or is empty, prepare to create new
            existing_data = []

        # Append the new data
        # This assumes existing_data is a list, adjust if your structure differs
        existing_data.extend([new_data])

        # Write the updated data back to the file
        with open(file_path, 'w') as file:
            yaml.dump(existing_data, file, default_flow_style=False)

    def create_parser(self):
        """
        Create an argument parser for the command-line interface.

        Returns:
            argparse.ArgumentParser: The argument parser.
        """
        parser = argparse.ArgumentParser(
            description='Search for vulnerable commits in GitHub repositories.')
        parser.add_argument('--repos_count', type=int, default=100,
                            help='Number of repositories to search.')
        parser.add_argument('--commits_count', type=int, default=1000,
                            help='Number of commits per repository to search.')
        return parser


    @time_it
    def get_repos(self, count: int):
        if self.ACCESS_TOKEN is None:
            logging.info('Please set the ACCESS_TOKEN environment variable')
            return

        # Keep the original query template unchanged.
        query_template = '''
        {
            search(query: "language:C++ language:C", type: REPOSITORY, first: 100, after: AFTER_PLACEHOLDER) {
                pageInfo {
                    endCursor
                    hasNextPage
                }
                edges {
                    node {
                        ... on Repository {
                            nameWithOwner
                            stargazers {
                                totalCount
                            }
                            url
                        }
                    }
                }
            }
        }
        '''
        end_cursor = "null"  # Initialize the end_cursor.
        all_repos = []

        while True:
            # Create a new query string for each iteration by replacing AFTER_PLACEHOLDER
            # with the current value of end_cursor.
            current_query = query_template.replace('AFTER_PLACEHOLDER', end_cursor)

            response = self.make_request(GITHUB_API_URL, method='post', json={'query': current_query}, headers=self.HEADERS)
            data = response.json()

            all_repos.extend(data['data']['search']['edges'])

            if not data['data']['search']['pageInfo']['hasNextPage'] or len(all_repos) >= count:
                break

            # Update end_cursor with the new value for the next iteration.
            # Ensure it's properly quoted for the GraphQL query.
            end_cursor = '"' + data['data']['search']['pageInfo']['endCursor'] + '"'

        return all_repos[:count]


    @time_it
    def search_vulnerable_commits_in_repo(self, repo, commits_count):
        """
        Search for vulnerable commits in a specific repository.

        Args:
            repo (dict): The repository information.
            commits_count (int): The number of commits to search in the repository.
        """
        name = repo['node']['nameWithOwner']
        # print time in user friendly format
        logging.info("Current time: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        logging.info(f"Searching for vulnerable commits in repository {name}...")
        commits = []
        # Since GitHub API allows only 100 items per page, we need to divide the commits_count by 100
        pages = commits_count // 100
        for page in range(1, pages + 1):
            commits_url = f'https://api.github.com/repos/{name}/commits?per_page=100&page={page}'
            response = self.make_request(commits_url, headers=self.HEADERS)
            try:
                commits.extend(response.json())
            except Exception as e:
                print(e)

        for commit in commits:
            self.search_vulnerable_commit(commit, name)

    def search_vulnerable_commit(self, commit, repo_name):
        """
        Search for a vulnerable commit in a repository.

        Args:
            commit (dict): The commit information.
            repo_name (str): The name of the repository.
        """
        commit_sha = commit['sha']
        commit_message = commit['commit']['message']
        if not any(keyword in commit_message for keyword in KEYWORDS):
            return
        diff_url = f'https://api.github.com/repos/{repo_name}/commits/{commit_sha}'
        diff_response = self.make_request(diff_url, headers=self.HEADERS)
        diff_data = diff_response.json()
        files = diff_data['files']
        diff_content = []
        try:
            for file in files:
                filename = file['filename']
                if filename.endswith(('.c', '.cpp')):
                    patch_without_formatting_changes = self.remove_formatting_changes_from_single_file(file['patch'])
                    if patch_without_formatting_changes != '':
                        diff_content.append(f"--- a/{filename}\n+++ b/{filename}\n{patch_without_formatting_changes}")
        except KeyError:
            pass

        if not diff_content:
            return

        commit_info = {
            'repo_name': repo_name,
            'commit_sha': commit_sha,
            'commit_message': commit_message,
            'commit_diff': diff_content
        }

        self.append_to_yaml(VULNERABLE_COMMITS_FILE_PATH, commit_info)
        logging.info(f"Vulnerable commit found in repository {repo_name} with commit SHA {commit_sha}")

    @time_it
    def search_vulnerable_commits_in_all_repos(self, repos_count, commits_count):
        """
        Search for vulnerable commits in all repositories.

        Args:
            repos_count (int): The number of repositories to search.
            commits_count (int): The number of commits per repository to search.
        """
        if os.path.exists(VULNERABLE_COMMITS_FILE_PATH):
            os.remove(VULNERABLE_COMMITS_FILE_PATH)
        repos = self.get_repos(repos_count)
        logging.info(f"Searching for vulnerable commits in {len(repos)} repositories...")

        for repo in repos:
            self.search_vulnerable_commits_in_repo(repo, commits_count)

    @time_it
    def main(self, repos_count, commits_count):
        if os.path.exists(VULNERABLE_COMMITS_FILE_PATH):
            os.remove(VULNERABLE_COMMITS_FILE_PATH)

        try:
            self.search_vulnerable_commits_in_all_repos(repos_count, commits_count)
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt received, exiting...")


    @retry(stop_max_attempt_number=3, wait_fixed=200)
    def make_request(self, url, method='get', headers={}, json={}):
        """
        Make an HTTP request.

        Args:
            url (str): The URL to make the request to.
            method (str, optional): The HTTP method. Defaults to 'get'.
            headers (dict, optional): The request headers. Defaults to {}.
            json (dict, optional): The request payload as JSON. Defaults to {}.

        Returns:
            requests.Response: The response object.
        """
        try:
            if method == 'get':
                response = requests.get(url, headers=headers)
            elif method == 'post':
                response = requests.post(url, headers=headers, json=json)
            else:
                raise ValueError(f'Invalid HTTP method: {method}')
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            if response.status_code == 403:
                if 'X-RateLimit-Reset' in response.headers:
                    # We hit the rate limit. Sleep until it resets.
                    reset_timestamp = int(response.headers['X-RateLimit-Reset'])
                    sleep_time = max(reset_timestamp - time.time(), 0)
                    logging.info(f"Current time: {datetime.datetime.now()}")
                    logging.info(f"Rate limit exceeded. Sleeping for {sleep_time} seconds")
                    time.sleep(sleep_time)
                elif 'Retry-After' in response.headers:
                    # Server asked us to retry after a certain period of time
                    sleep_time = int(response.headers['Retry-After'])
                    logging.info(f"Current time: {datetime.datetime.now()}")
                    logging.info(f"Server asked us to retry after {sleep_time} seconds")
                    time.sleep(sleep_time)
                # Retry the request.
                return self.make_request(url, method, headers, json)
            else:
                logging.error(f"Request error: {e}")

if __name__ == '__main__':
    # attach_debugger()
    access_token = os.getenv('ACCESS_TOKEN')
    searcher = VulnerabilitySearcher(access_token)
    args = searcher.create_parser().parse_args()
    searcher.main(args.repos_count, args.commits_count)
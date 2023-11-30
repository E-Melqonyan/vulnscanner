import os
import yaml
import requests
import argparse
import multiprocessing
import concurrent.futures
import logging
import threading
import traceback
import time

from retrying import retry
from requests.exceptions import HTTPError, ConnectionError, Timeout

from utilitys import attach_debugger, time_it

# Constants
VULNERABLE_COMMITS_FILE_PATH = 'vulnerable_commits.yml'
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
GITHUB_API_URL = 'https://api.github.com/graphql'
HEADERS = {'Authorization': f'token {ACCESS_TOKEN}'}
KEYWORDS = ['CVE', 'Vuln', 'Vulnerability', 'CWE']
PROCESS_COUNT = 16
WORKER_COUNT = 16

# Initialize logging
logging.basicConfig(level=logging.INFO)
# Create a global lock
lock = threading.Lock()


class VulnerabilitySearcher:
    """
    A class that searches for vulnerable commits in GitHub repositories.
    """

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
        """
        Get a list of repositories to search for vulnerable commits.

        Args:
            count (int): The number of repositories to search.

        Returns:
            list: A list of repositories.
        """
        if ACCESS_TOKEN is None:
            logging.info('Please set the ACCESS_TOKEN environment variable')
            return

        query = '''
        {
            search(query: "language:C++", type: REPOSITORY, first: 100, after: AFTER_PLACEHOLDER) {
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
        end_cursor = "null"
        all_repos = []
        while True:
            query = query.replace('AFTER_PLACEHOLDER', end_cursor)
            response = self.make_request(GITHUB_API_URL, method='post', json={'query': query}, headers=HEADERS)
            data = response.json()
            all_repos.extend(data['data']['search']['edges'])
            if not data['data']['search']['pageInfo']['hasNextPage'] or len(all_repos) >= count:
                break
            end_cursor = '"' + \
                data['data']['search']['pageInfo']['endCursor'] + '"'
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
        commits = []
        # Since GitHub API allows only 100 items per page, we need to divide the commits_count by 100
        pages = commits_count // 100
        for page in range(1, pages + 1):
            commits_url = f'https://api.github.com/repos/{name}/commits?per_page=100&page={page}'
            response = self.make_request(commits_url, headers=HEADERS)
            try:
                commits.extend(response.json())
            except Exception as e:
                print(e)
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKER_COUNT) as executor:
            futures = [executor.submit(
                self.search_vulnerable_commit, commit, name) for commit in commits]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(
                        f'Exception in repository {repo}: {e}\n{traceback.format_exc()}')

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
        diff_response = self.make_request(diff_url, headers=HEADERS)
        diff_data = diff_response.json()
        files = diff_data['files']
        diff_content = []
        try:
            for file in files:
                if file['filename'].endswith(('.c', '.h', '.hpp', '.cpp')):  # Check file extension
                    diff_content.append(file['patch'])
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
        # Acquire the lock before writing to the file
        with lock:
            with open(VULNERABLE_COMMITS_FILE_PATH, 'a') as f:
                yaml.dump(commit_info, f)

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
        pool = multiprocessing.Pool(processes=PROCESS_COUNT)
        pool.starmap(self.search_vulnerable_commits_in_repo, [
                     (repo, commits_count) for repo in repos])

    @time_it
    def main(self, repos_count, commits_count):
        """
        The main entry point of the program.

        Args:
            repos_count (int): The number of repositories to search.
            commits_count (int): The number of commits per repository to search.
        """
        self.search_vulnerable_commits_in_all_repos(repos_count, commits_count)

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
                    time.sleep(sleep_time)
                elif 'Retry-After' in response.headers:
                    # Server asked us to retry after a certain period of time
                    sleep_time = int(response.headers['Retry-After'])
                    time.sleep(sleep_time)
                # Retry the request.
                return self.make_request(url, method, headers, json)
            else:
                logging.error(f"Request error: {e}")


if __name__ == '__main__':
    searcher = VulnerabilitySearcher()
    args = searcher.create_parser().parse_args()
    searcher.main(args.repos_count, args.commits_count)

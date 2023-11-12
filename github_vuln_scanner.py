import os
import yaml
import requests
import argparse
import multiprocessing
import concurrent.futures
from utilitys import attach_debugger, time_it
import logging
import threading
import traceback
import time


# Constants
VULNERABLE_COMMITS_FILE_PATH = 'vulnerable_commits.yml'
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
GITHUB_API_URL = 'https://api.github.com/graphql'
HEADERS = {'Authorization': f'token {ACCESS_TOKEN}'}
KEYWORDS = ['CVE', 'Vuln', 'Vulnerability', 'CWE']
PROCESS_COUNT = 16
WORKER_COUNT = 16
RATE_LIMIT_THRESHOLD = 10
# Initialize logging
logging.basicConfig(level=logging.INFO)
# Create a global lock
lock = threading.Lock()


class VulnerabilitySearcher:

    def create_parser(self):
        parser = argparse.ArgumentParser(
            description='Search for vulnerable commits in GitHub repositories.')
        parser.add_argument('--repos_count', type=int, default=100,
                            help='Number of repositories to search.')
        parser.add_argument('--commits_count', type=int, default=1000,
                            help='Number of commits per repository to search.')
        return parser

    def get_rate_limit(self):
        rate_limit_url = 'https://api.github.com/rate_limit'
        response = requests.get(rate_limit_url, headers=HEADERS)
        if response.status_code == 200:
            rate_limit_data = response.json()
            remaining = rate_limit_data['resources']['core']['remaining']
            reset_time = rate_limit_data['resources']['core']['reset']
            return remaining, reset_time
        else:
            return None, None

    def handle_rate_limit(self):
        remaining, reset_time = self.get_rate_limit()
        if remaining is not None and remaining < RATE_LIMIT_THRESHOLD:
            sleep_time = reset_time - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

    @time_it
    def get_repos(self, count: int):
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
            self.handle_rate_limit()
            response = requests.post(GITHUB_API_URL, json={
                                     'query': query}, headers=HEADERS)
            data = response.json()
            all_repos.extend(data['data']['search']['edges'])
            if not data['data']['search']['pageInfo']['hasNextPage'] or len(all_repos) >= count:
                break
            end_cursor = '"' + \
                data['data']['search']['pageInfo']['endCursor'] + '"'
        return all_repos[:count]

    @time_it
    def search_vulnerable_commits_in_repo(self, repo, commits_count):
        name = repo['node']['nameWithOwner']
        commits = []
        # Since GitHub API allows only 100 items per page, we need to divide the commits_count by 100
        pages = commits_count // 100
        for page in range(1, pages + 1):
            commits_url = f'https://api.github.com/repos/{name}/commits?per_page=100&page={page}'
            self.handle_rate_limit()
            response = requests.get(commits_url, headers=HEADERS)
            commits.extend(response.json())
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
        commit_sha = commit['sha']
        commit_message = commit['commit']['message']
        if not any(keyword in commit_message for keyword in KEYWORDS):
            return
        diff_url = f'https://api.github.com/repos/{repo_name}/commits/{commit_sha}'
        self.handle_rate_limit()
        diff_response = requests.get(diff_url, headers=HEADERS)
        diff_data = diff_response.json()
        files = diff_data['files']
        diff_content = []
        try:
            for file in files:
                diff_content.append(file['patch'])
        except KeyError:
            pass
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
        if os.path.exists(VULNERABLE_COMMITS_FILE_PATH):
            os.remove(VULNERABLE_COMMITS_FILE_PATH)
        repos = self.get_repos(repos_count)
        pool = multiprocessing.Pool(processes=PROCESS_COUNT)
        pool.starmap(self.search_vulnerable_commits_in_repo, [
                     (repo, commits_count) for repo in repos])

    @time_it
    def main(self, repos_count, commits_count):
        self.search_vulnerable_commits_in_all_repos(repos_count, commits_count)


if __name__ == '__main__':
    searcher = VulnerabilitySearcher()
    args = searcher.create_parser().parse_args()
    searcher.main(args.repos_count, args.commits_count)

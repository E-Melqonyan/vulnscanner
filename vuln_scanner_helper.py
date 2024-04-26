import os
import re
import yaml
import requests
import logging
import datetime
import time

logging.basicConfig(level=logging.INFO)

GITHUB_API_URL = 'https://api.github.com/graphql'
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN', None)
HEADERS = {'Authorization': f'token {ACCESS_TOKEN}'}

def check_for_non_formating_changes(patch_content):
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

def split_git_patch_into_blocks(patch_content):
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

def remove_formatting_changes_from_single_file(patch_content):
    new_patch_content = []
    patch_blocks = split_git_patch_into_blocks(patch_content)
    for block in patch_blocks:
        if not check_for_non_formating_changes(block):
            new_patch_content.append(block)

    return '\n'.join(new_patch_content)


def append_to_yaml(file_path, new_data):
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

def make_request(url, method='get', headers={}, json={}, retries=3):
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
            if response.status_code == 403 or response.status_code == 429:
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
                return make_request(url, method, headers, json)
            else:
                if retries > 0:
                    logging.warning(f"Request failed. Retries left: {retries} response_code: {response.status_code}")
                    time.sleep(60)
                    return make_request(url, method, headers, json, retries - 1)
                else:
                    logging.error(f"Request error: {e}")
                    raise


def get_repos(count: int):
    if ACCESS_TOKEN is None:
        logging.error('Please set the ACCESS_TOKEN environment variable')
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

        response = make_request(GITHUB_API_URL, method='post', json={'query': current_query}, headers=HEADERS)
        data = response.json()

        all_repos.extend(data['data']['search']['edges'])

        if not data['data']['search']['pageInfo']['hasNextPage'] or len(all_repos) >= count:
            break

        # Update end_cursor with the new value for the next iteration.
        # Ensure it's properly quoted for the GraphQL query.
        end_cursor = '"' + data['data']['search']['pageInfo']['endCursor'] + '"'

    return all_repos[:count]
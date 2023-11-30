# GitHub Vulnerability Scannerscanner
Simple vulnerability scanner based on code clone detection

## Getting Started

These instructions will help you set up and run the GitHub vulnerability scanner on your local machine.

### Prerequisites

- Python 3
- pip3
- GitHub Personal Access Token (set as the ACCESS_TOKEN environment variable)

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/E-Melqonyan/vulnscanner.git
    cd your-repository
    ```

2. Run the script to install dependencies:

    ```bash
    source script.sh
    _install_pip_requirements
    ```

3. Set the `ACCESS_TOKEN` environment variable:

    ```bash
    export ACCESS_TOKEN=your-github-token
    ```

### Usage

Run the GitHub vulnerability scanner with the desired parameters:

```bash
source venv/bin/activate
python3 github_vuln_scanner.py --repos_count 100 --commits_count 1000
```

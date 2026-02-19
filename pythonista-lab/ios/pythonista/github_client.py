#!/usr/bin/env python3
"""
GitHub Integration for Pythonista
Fetch files, sync repos, and manage bug bounty code from your iPhone
"""

import requests
import json
import base64
from pathlib import Path
from typing import Dict, List, Optional, Any
import os


class GitHubClient:
    """
    Simple GitHub API client for Pythonista
    Works without git command-line tools
    """

    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub client

        Args:
            token: GitHub personal access token (optional, but recommended)
        """
        self.token = token or os.environ.get('GITHUB_TOKEN')
        self.base_url = "https://api.github.com"
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Pythonista-BugBounty-Client'
        }

        if self.token:
            self.headers['Authorization'] = f'token {self.token}'

    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make GitHub API request"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        response = requests.request(method, url, headers=self.headers, **kwargs)
        response.raise_for_status()
        return response

    def get_file(self, repo: str, path: str, branch: str = 'main') -> Dict[str, Any]:
        """
        Fetch a file from GitHub repository

        Args:
            repo: Repository in format 'owner/repo'
            path: File path in repository
            branch: Branch name (default: 'main')

        Returns:
            Dict with file metadata and content
        """
        endpoint = f"/repos/{repo}/contents/{path}"
        params = {'ref': branch}

        response = self._request('GET', endpoint, params=params)
        data = response.json()

        # Decode base64 content
        if data.get('encoding') == 'base64':
            content = base64.b64decode(data['content']).decode('utf-8')
            data['decoded_content'] = content

        return data

    def save_file_locally(self, repo: str, path: str, local_path: Path, branch: str = 'main') -> Path:
        """
        Fetch file from GitHub and save locally

        Args:
            repo: Repository in format 'owner/repo'
            path: File path in repository
            local_path: Local path to save file
            branch: Branch name

        Returns:
            Path to saved file
        """
        file_data = self.get_file(repo, path, branch)
        content = file_data.get('decoded_content', '')

        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(content, encoding='utf-8')

        print(f"✅ Saved: {local_path}")
        return local_path

    def list_directory(self, repo: str, path: str = '', branch: str = 'main') -> List[Dict]:
        """
        List files in a directory

        Args:
            repo: Repository in format 'owner/repo'
            path: Directory path (empty for root)
            branch: Branch name

        Returns:
            List of file/directory metadata
        """
        endpoint = f"/repos/{repo}/contents/{path}"
        params = {'ref': branch}

        response = self._request('GET', endpoint, params=params)
        return response.json()

    def get_repo_info(self, repo: str) -> Dict:
        """Get repository metadata"""
        endpoint = f"/repos/{repo}"
        response = self._request('GET', endpoint)
        return response.json()

    def search_code(self, query: str, repo: Optional[str] = None) -> List[Dict]:
        """
        Search for code in GitHub

        Args:
            query: Search query
            repo: Optionally limit to specific repo

        Returns:
            List of code search results
        """
        if repo:
            query = f"{query} repo:{repo}"

        endpoint = "/search/code"
        params = {'q': query}

        response = self._request('GET', endpoint, params=params)
        return response.json().get('items', [])

    def clone_repo(self, repo: str, local_dir: Path, branch: str = 'main',
                   include_patterns: Optional[List[str]] = None) -> Path:
        """
        "Clone" repository by downloading files
        (Pythonista doesn't have git, so we download files via API)

        Args:
            repo: Repository in format 'owner/repo'
            local_dir: Local directory to save files
            branch: Branch to clone
            include_patterns: Only download files matching these patterns (e.g., ['*.py', '*.md'])

        Returns:
            Path to cloned directory
        """
        local_dir = Path(local_dir)
        local_dir.mkdir(parents=True, exist_ok=True)

        print(f"📦 Cloning {repo} to {local_dir}...")

        # Get repository contents recursively
        def download_directory(path: str = ''):
            items = self.list_directory(repo, path, branch)

            for item in items:
                if item['type'] == 'file':
                    # Check if file matches include patterns
                    if include_patterns:
                        if not any(item['name'].endswith(p.replace('*', '')) for p in include_patterns):
                            continue

                    # Download file
                    file_path = item['path']
                    local_file = local_dir / file_path

                    try:
                        self.save_file_locally(repo, file_path, local_file, branch)
                    except Exception as e:
                        print(f"⚠️  Failed to download {file_path}: {e}")

                elif item['type'] == 'dir':
                    # Recursively download subdirectory
                    download_directory(item['path'])

        download_directory()
        print(f"✅ Clone complete: {local_dir}")
        return local_dir

    def get_latest_release(self, repo: str) -> Dict:
        """Get latest release information"""
        endpoint = f"/repos/{repo}/releases/latest"
        response = self._request('GET', endpoint)
        return response.json()

    def download_tool(self, repo: str, local_dir: Path, tool_name: Optional[str] = None) -> Path:
        """
        Download a specific bug bounty tool from GitHub

        Args:
            repo: Repository containing the tool
            local_dir: Local directory to save
            tool_name: Specific tool name (if repo has multiple)

        Returns:
            Path to downloaded tool
        """
        print(f"🔧 Downloading tool from {repo}...")

        # Clone only Python files to save bandwidth
        return self.clone_repo(repo, local_dir, include_patterns=['*.py', '*.md', '*.txt'])


class BugBountyGitHub:
    """
    Bug bounty specific GitHub operations
    Manages your bug bounty repository from iPhone
    """

    def __init__(self, repo: str, token: Optional[str] = None):
        """
        Initialize bug bounty GitHub manager

        Args:
            repo: Your bug bounty repo in format 'owner/repo'
            token: GitHub token
        """
        self.repo = repo
        self.client = GitHubClient(token)
        self.local_base = Path.home() / 'Documents' / 'BugBounty' / 'GitHub'
        self.local_base.mkdir(parents=True, exist_ok=True)

    def sync_reports(self, direction: str = 'pull') -> None:
        """
        Sync bug reports between local and GitHub

        Args:
            direction: 'pull' (download) or 'push' (upload)
        """
        reports_dir = self.local_base / 'reports'

        if direction == 'pull':
            print("📥 Pulling reports from GitHub...")
            # Download all reports
            items = self.client.list_directory(self.repo, 'reports')

            for item in items:
                if item['type'] == 'file' and item['name'].endswith('.md'):
                    local_file = reports_dir / item['name']
                    self.client.save_file_locally(
                        self.repo,
                        f"reports/{item['name']}",
                        local_file
                    )

            print("✅ Reports synced to local")

        # Note: 'push' would require write access and is more complex
        # For now, focus on read operations which are most useful on mobile

    def fetch_templates(self) -> Path:
        """Download all report templates"""
        print("📋 Fetching report templates...")
        templates_dir = self.local_base / 'templates'

        items = self.client.list_directory(self.repo, 'templates')

        for item in items:
            if item['type'] == 'file' and item['name'].endswith('.md'):
                local_file = templates_dir / item['name']
                self.client.save_file_locally(
                    self.repo,
                    f"templates/{item['name']}",
                    local_file
                )

        print(f"✅ Templates saved to {templates_dir}")
        return templates_dir

    def fetch_scripts(self) -> Path:
        """Download all Python scripts from the repo"""
        print("🐍 Fetching Python scripts...")
        scripts_dir = self.local_base / 'scripts'

        # Download pythonista-lab tools
        self.client.clone_repo(
            self.repo,
            scripts_dir,
            include_patterns=['*.py']
        )

        print(f"✅ Scripts saved to {scripts_dir}")
        return scripts_dir

    def get_latest_tool(self, tool_path: str) -> Path:
        """
        Fetch the latest version of a specific tool

        Args:
            tool_path: Path to tool in repo (e.g., 'pythonista-lab/utilities/header_analyzer.py')
        """
        local_file = self.local_base / Path(tool_path).name
        self.client.save_file_locally(self.repo, tool_path, local_file)
        return local_file

    def check_for_updates(self) -> Dict[str, Any]:
        """Check if there are updates to the repository"""
        repo_info = self.client.get_repo_info(self.repo)

        return {
            'last_updated': repo_info.get('updated_at'),
            'last_pushed': repo_info.get('pushed_at'),
            'default_branch': repo_info.get('default_branch'),
            'description': repo_info.get('description')
        }


def main():
    """Example usage"""
    import sys

    print("\n🐙 GitHub Integration for Pythonista Bug Bounty\n")

    # Example: Fetch a file
    if len(sys.argv) > 1:
        if sys.argv[1] == 'clone':
            # Clone a tool repository
            repo = input("Enter repo (owner/repo): ")
            token = input("GitHub token (optional, press Enter to skip): ").strip() or None

            client = GitHubClient(token)
            local_dir = Path.home() / 'Documents' / 'BugBounty' / 'Tools' / repo.split('/')[-1]

            client.clone_repo(repo, local_dir, include_patterns=['*.py', '*.md'])
            print(f"\n✅ Repository cloned to: {local_dir}")

        elif sys.argv[1] == 'sync':
            # Sync your bug bounty repo
            repo = input("Your bug bounty repo (owner/repo): ")
            token = input("GitHub token: ")

            bb = BugBountyGitHub(repo, token)
            bb.sync_reports()
            bb.fetch_templates()
            bb.fetch_scripts()

            print("\n✅ Repository fully synced!")

        elif sys.argv[1] == 'fetch':
            # Fetch a specific file
            repo = input("Repository (owner/repo): ")
            path = input("File path: ")
            token = input("GitHub token (optional): ").strip() or None

            client = GitHubClient(token)
            local_file = Path.home() / 'Documents' / Path(path).name

            client.save_file_locally(repo, path, local_file)
            print(f"\n✅ File saved to: {local_file}")

    else:
        print("Usage:")
        print("  python github_client.py clone   - Clone a repository")
        print("  python github_client.py sync    - Sync your bug bounty repo")
        print("  python github_client.py fetch   - Fetch a specific file")
        print("\nOr import and use programmatically:")
        print("  from github_client import GitHubClient, BugBountyGitHub")


if __name__ == "__main__":
    main()

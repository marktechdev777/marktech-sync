import os
import re
import subprocess
import tempfile
import logging
import requests
from datetime import datetime
from urllib.parse import urlparse
import time

# ---- LOGGING SETUP ----
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "sync.log")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_FILE, encoding="utf-8")
    ]
)
logger = logging.getLogger("MarktechSync")

def notify_teams_sync(webhook_url, provider, source_repo_url, destination_repo_url, message, error=False):
    color = "d9534f" if error else "0076D7"
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "Git Repository Sync" + (" Error" if error else " Result"),
        "themeColor": color,
        "title": f"Repository Sync {'FAILED' if error else 'Completed'}",
        "sections": [
            {
                "facts": [
                    {"name": "Provider", "value": provider},
                    {"name": "Source Repository", "value": source_repo_url},
                    {"name": "Destination Repository", "value": destination_repo_url},
                    {"name": "Result", "value": message},
                    {"name": "Time", "value": datetime.utcnow().isoformat() + " UTC"}
                ],
                "markdown": True
            }
        ]
    }
    try:
        resp = requests.post(webhook_url, headers={"Content-Type": "application/json"}, json=card, timeout=10)
        if resp.status_code != 200:
            logger.error(f"Teams notification failed: {resp.status_code} {resp.text}")
    except Exception as exc:
        logger.error(f"Teams notification exception: {exc}")

def create_gitlab_destination_path(provider, repo_path):
    path = repo_path.lower()
    path = re.sub(r'[/_]', '-', path)
    path = re.sub(r'-+', '-', path)
    provider = provider.lower()
    return f"marktech-sync/{provider}/{path}"

def run_command(cmd, cwd=None):
    try:
        result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        return result
    except Exception as exc:
        logger.error(f"Command failed: {' '.join(cmd)} | Exception: {exc}")
        return None

class GitHubSource:
    def __init__(self, access_token, username):
        self.api_url = "https://api.github.com"
        self.headers = {"Authorization": f"token {access_token}"}
        self.username = username

    def fetch_all_repositories(self):
        repositories = []
        page = 1
        while True:
            url = f"{self.api_url}/user/repos"
            try:
                response = requests.get(url, headers=self.headers, params={"per_page": 100, "page": page}, timeout=20)
                if response.status_code != 200:
                    logger.error(f"GitHub API error {response.status_code}: {response.text}")
                    break
                data = response.json()
                if not data:
                    break
                for repo in data:
                    repositories.append({"owner": repo["owner"]["login"], "name": repo["name"]})
                page += 1
            except Exception as exc:
                logger.error(f"GitHub fetch error: {exc}")
                break
        logger.info(f"GitHub: Found {len(repositories)} repositories.")
        return repositories

    def get_clone_url(self, repo):
        return f"https://github.com/{repo['owner']}/{repo['name']}.git"

    def fetch_branches(self, repo):
        url = f"{self.api_url}/repos/{repo['owner']}/{repo['name']}/branches"
        try:
            response = requests.get(url, headers=self.headers, timeout=20)
            if response.status_code != 200:
                logger.error(f"GitHub branch API error {response.status_code}: {response.text}")
                return []
            return [b["name"] for b in response.json()]
        except Exception as exc:
            logger.error(f"GitHub branch fetch error: {exc}")
            return []

class GiteeSource:
    def __init__(self, access_token, username):
        self.api_url = "https://gitee.com/api/v5"
        self.access_token = access_token
        self.username = username

    def fetch_all_repositories(self):
        repositories = []
        page = 1
        while True:
            url = f"{self.api_url}/users/{self.username}/repos"
            try:
                response = requests.get(url, params={"access_token": self.access_token, "page": page, "per_page": 100}, timeout=20)
                if response.status_code != 200:
                    logger.error(f"Gitee API error {response.status_code}: {response.text}")
                    break
                data = response.json()
                if not data:
                    break
                for repo in data:
                    repositories.append({"owner": repo["owner"]["login"], "name": repo["name"]})
                page += 1
            except Exception as exc:
                logger.error(f"Gitee fetch error: {exc}")
                break
        logger.info(f"Gitee: Found {len(repositories)} repositories.")
        return repositories

    def get_clone_url(self, repo):
        return f"https://gitee.com/{repo['owner']}/{repo['name']}.git"

    def fetch_branches(self, repo):
        url = f"{self.api_url}/repos/{repo['owner']}/{repo['name']}/branches"
        try:
            response = requests.get(url, params={"access_token": self.access_token}, timeout=20)
            if response.status_code != 200:
                logger.error(f"Gitee branch API error {response.status_code}: {response.text}")
                return []
            return [b["name"] for b in response.json()]
        except Exception as exc:
            logger.error(f"Gitee branch fetch error: {exc}")
            return []

class BitbucketSource:
    def __init__(self, access_token, username):
        self.api_url = "https://api.bitbucket.org/2.0"
        self.auth = (username, access_token)

    def fetch_all_repositories(self):
        repositories = []
        url = f"{self.api_url}/repositories/{self.auth[0]}"
        while url:
            try:
                response = requests.get(url, auth=self.auth, params={"pagelen": 100}, timeout=20)
                if response.status_code != 200:
                    logger.error(f"Bitbucket API error {response.status_code}: {response.text}")
                    break
                data = response.json()
                for repo in data.get("values", []):
                    repositories.append({"workspace": repo["workspace"]["slug"], "slug": repo["slug"]})
                url = data.get("next")
            except Exception as exc:
                logger.error(f"Bitbucket fetch error: {exc}")
                break
        logger.info(f"Bitbucket: Found {len(repositories)} repositories.")
        return repositories

    def get_clone_url(self, repo):
        return f"https://bitbucket.org/{repo['workspace']}/{repo['slug']}.git"

    def fetch_branches(self, repo):
        url = f"{self.api_url}/repositories/{repo['workspace']}/{repo['slug']}/refs/branches"
        try:
            response = requests.get(url, auth=self.auth, timeout=20)
            if response.status_code != 200:
                logger.error(f"Bitbucket branch API error {response.status_code}: {response.text}")
                return []
            return [b["name"] for b in response.json().get("values",[])]
        except Exception as exc:
            logger.error(f"Bitbucket branch fetch error: {exc}")
            return []

class GitLabDestination:
    def __init__(self, access_token, username):
        self.api_url = "https://gitlab.com/api/v4"
        self.headers = {"PRIVATE-TOKEN": access_token}
        self.username = username

    def get_destination_url(self, repo_path):
        return f"https://gitlab.com/{repo_path}.git"

def sync_branch(source_clone_url, branch, destination_gitlab_url, teams_webhook_url=None, provider=None):
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            clone_result = run_command([
                "git", "clone", "--single-branch", "--branch", branch, source_clone_url, "repo"
            ], cwd=temp_dir)
            if not clone_result or clone_result.returncode != 0:
                msg = f"Failed to clone branch '{branch}' from {source_clone_url} | {clone_result.stderr.decode() if clone_result else ''}"
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider, source_clone_url, destination_gitlab_url, msg, error=True)
                return

            repo_dir = os.path.join(temp_dir, "repo")
            run_command(["git", "remote", "remove", "destination"], cwd=repo_dir)
            run_command(["git", "remote", "add", "destination", destination_gitlab_url], cwd=repo_dir)

            push_result = run_command(["git", "push", "-u", "destination", f"{branch}:{branch}"], cwd=repo_dir)
            if not push_result or push_result.returncode != 0:
                stderr = push_result.stderr.decode() if push_result else ""
                msg = f"Failed to push branch '{branch}' to {destination_gitlab_url} | {stderr}"
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider, source_clone_url, destination_gitlab_url, msg, error=True)
            else:
                stdout = push_result.stdout.decode()
                stderr = push_result.stderr.decode()
                if ("Everything up-to-date" not in stdout) and ("Everything up-to-date" not in stderr):
                    logger.info(f"Branch '{branch}' changes pushed: {source_clone_url} -> {destination_gitlab_url}")
                    if teams_webhook_url:
                        notify_teams_sync(teams_webhook_url, provider, source_clone_url, destination_gitlab_url, f"Branch '{branch}' changes pushed")
                else:
                    logger.info(f"No changes to sync for branch '{branch}' in {source_clone_url}")

        except Exception as exc:
            msg = f"Sync error for branch '{branch}': {exc}"
            logger.error(msg)
            if teams_webhook_url:
                notify_teams_sync(teams_webhook_url, provider, source_clone_url, destination_gitlab_url, msg, error=True)

def main():
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME")
    GITEE_TOKEN = os.environ.get("GITEE_TOKEN")
    GITEE_USERNAME = os.environ.get("GITEE_USERNAME")
    BITBUCKET_TOKEN = os.environ.get("BITBUCKET_TOKEN")
    BITBUCKET_USERNAME = os.environ.get("BITBUCKET_USERNAME")
    GITLAB_TOKEN = os.environ.get("GITLAB_TOKEN")
    GITLAB_USERNAME = os.environ.get("GITLAB_USERNAME")
    TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL")
    SLEEP_SECONDS = int(os.environ.get("SYNC_INTERVAL", "180"))  # Default: 3 minutes

    sources = []
    if GITHUB_TOKEN and GITHUB_USERNAME:
        sources.append(("github", GitHubSource(GITHUB_TOKEN, GITHUB_USERNAME)))
    if GITEE_TOKEN and GITEE_USERNAME:
        sources.append(("gitee", GiteeSource(GITEE_TOKEN, GITEE_USERNAME)))
    if BITBUCKET_TOKEN and BITBUCKET_USERNAME:
        sources.append(("bitbucket", BitbucketSource(BITBUCKET_TOKEN, BITBUCKET_USERNAME)))
    if not sources:
        logger.error("No source providers configured!")
        return

    gitlab_destination = GitLabDestination(GITLAB_TOKEN, GITLAB_USERNAME)

    while True:
        logger.info("=== Starting full sync cycle ===")
        for provider_label, source_provider in sources:
            logger.info(f"==== Syncing repositories from {provider_label.upper()} ====")
            repositories = source_provider.fetch_all_repositories()
            for repo_info in repositories:
                source_clone_url = source_provider.get_clone_url(repo_info)
                repo_path = f"{repo_info.get('owner') or repo_info.get('workspace')}/{repo_info.get('name') or repo_info.get('slug')}"
                destination_path = create_gitlab_destination_path(provider_label, repo_path)
                destination_gitlab_url = gitlab_destination.get_destination_url(destination_path)

                branches = source_provider.fetch_branches(repo_info)
                for branch in branches:
                    sync_branch(
                        source_clone_url, branch, destination_gitlab_url,
                        teams_webhook_url=TEAMS_WEBHOOK_URL, provider=provider_label
                    )
        logger.info(f"=== Sync cycle complete. Sleeping {SLEEP_SECONDS} seconds ===")
        time.sleep(SLEEP_SECONDS)

if __name__ == "__main__":
    main()
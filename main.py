import os
import re
import subprocess
import tempfile
import requests
import json
import logging
from datetime import datetime
from urllib.parse import urlparse

# ------------------- LOGGING SETUP -------------------
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
logger = logging.getLogger("GitSync")

# ------------------- TEAMS NOTIFICATION -------------------
def notify_teams_sync(webhook_url, provider, source_repo_url, destination_repo_url, message, error=False):
    color = "d9534f" if error else "0076D7"  # Red for errors, blue for success
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
        resp = requests.post(webhook_url, headers={"Content-Type": "application/json"}, data=json.dumps(card), timeout=10)
        if resp.status_code != 200:
            logger.error(f"Teams notification failed: {resp.status_code} {resp.text}")
    except Exception as exc:
        logger.error(f"Teams notification exception: {exc}")

# ------------------- SYNC PATH UTIL -------------------
def create_gitlab_destination_path(provider_name, source_repo_url):
    url_parts = urlparse(source_repo_url)
    path = url_parts.path.lstrip('/').rstrip('.git').rstrip('/')
    if path.endswith('.git'):
        path = path[:-4]
    path = path.lower()
    path = re.sub(r'[/_]', '-', path)
    path = re.sub(r'-+', '-', path)
    provider_name = provider_name.lower()
    return f"marktech-sync/{provider_name}/{path}"

def execute_command(command, cwd=None):
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120
        )
        return result
    except subprocess.TimeoutExpired:
        return "timeout"
    except Exception as exc:
        return exc

# ------------------- PROVIDER CLASSES -------------------
class GitHubSource:
    def __init__(self, access_token, username):
        self.api_url = "https://api.github.com"
        self.headers = {"Authorization": f"token {access_token}"}
        self.username = username

    def fetch_all_repositories(self, teams_webhook_url=None):
        repositories = []
        page = 1
        while True:
            url = f"{self.api_url}/user/repos"
            try:
                response = requests.get(url, headers=self.headers, params={"per_page": 100, "page": page}, timeout=20)
                if response.status_code != 200:
                    msg = f"GitHub API error {response.status_code}: {response.text}"
                    if teams_webhook_url:
                        notify_teams_sync(teams_webhook_url, "github", url, "", msg, error=True)
                    break
                data = response.json()
                if not data:
                    break
                for repo in data:
                    repositories.append({"owner": repo["owner"]["login"], "name": repo["name"]})
                page += 1
            except Exception as exc:
                msg = f"GitHub fetch error: {exc}"
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, "github", url, "", msg, error=True)
                break
        logger.info(f"GitHub: Found {len(repositories)} repositories.")
        return repositories

    def get_clone_url(self, repo):
        return f"https://github.com/{repo['owner']}/{repo['name']}.git"

class GiteeSource:
    def __init__(self, access_token, username):
        self.api_url = "https://gitee.com/api/v5"
        self.access_token = access_token
        self.username = username

    def fetch_all_repositories(self, teams_webhook_url=None):
        repositories = []
        page = 1
        while True:
            url = f"{self.api_url}/users/{self.username}/repos"
            try:
                response = requests.get(url, params={"access_token": self.access_token, "page": page, "per_page": 100}, timeout=20)
                if response.status_code != 200:
                    msg = f"Gitee API error {response.status_code}: {response.text}"
                    if teams_webhook_url:
                        notify_teams_sync(teams_webhook_url, "gitee", url, "", msg, error=True)
                    break
                data = response.json()
                if not data:
                    break
                for repo in data:
                    repositories.append({"owner": repo["owner"]["login"], "name": repo["name"]})
                page += 1
            except Exception as exc:
                msg = f"Gitee fetch error: {exc}"
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, "gitee", url, "", msg, error=True)
                break
        logger.info(f"Gitee: Found {len(repositories)} repositories.")
        return repositories

    def get_clone_url(self, repo):
        return f"https://gitee.com/{repo['owner']}/{repo['name']}.git"

class BitbucketSource:
    def __init__(self, access_token, username):
        self.api_url = "https://api.bitbucket.org/2.0"
        self.auth = (username, access_token)

    def fetch_all_repositories(self, teams_webhook_url=None):
        repositories = []
        url = f"{self.api_url}/repositories/{self.auth[0]}"
        while url:
            try:
                response = requests.get(url, auth=self.auth, params={"pagelen": 100}, timeout=20)
                if response.status_code != 200:
                    msg = f"Bitbucket API error {response.status_code}: {response.text}"
                    if teams_webhook_url:
                        notify_teams_sync(teams_webhook_url, "bitbucket", url, "", msg, error=True)
                    break
                data = response.json()
                for repo in data.get("values", []):
                    repositories.append({"workspace": repo["workspace"]["slug"], "slug": repo["slug"]})
                url = data.get("next")
            except Exception as exc:
                msg = f"Bitbucket fetch error: {exc}"
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, "bitbucket", url, "", msg, error=True)
                break
        logger.info(f"Bitbucket: Found {len(repositories)} repositories.")
        return repositories

    def get_clone_url(self, repo):
        return f"https://bitbucket.org/{repo['workspace']}/{repo['slug']}.git"

class GitLabDestination:
    def __init__(self, access_token, username):
        self.api_url = "https://gitlab.com/api/v4"
        self.headers = {"PRIVATE-TOKEN": access_token}
        self.username = username

    def get_destination_url(self, repo_path):
        return f"https://gitlab.com/{repo_path}.git"

# ------------------- SYNC FUNCTION -------------------
def mirror_repository(
    source_provider, 
    destination_provider, 
    provider_label, 
    repository_info, 
    teams_webhook_url=None
):
    try:
        source_clone_url = source_provider.get_clone_url(repository_info)
    except Exception as exc:
        msg = f"Failed to compose clone URL for {provider_label}: {exc}"
        logger.error(msg)
        if teams_webhook_url:
            notify_teams_sync(teams_webhook_url, provider_label, str(repository_info), "", msg, error=True)
        return

    destination_path = create_gitlab_destination_path(provider_label, source_clone_url)
    destination_gitlab_url = destination_provider.get_destination_url(destination_path)
    logger.info(f"Sync: {source_clone_url} --> {destination_gitlab_url}")

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Clone all refs (branches/tags)
            clone_result = execute_command(["git", "clone", "--mirror", source_clone_url, "repo"], cwd=temp_dir)
            if clone_result == "timeout" or isinstance(clone_result, Exception):
                msg = f"Cloning timed out or failed: {source_clone_url}"
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider_label, source_clone_url, destination_gitlab_url, msg, error=True)
                return
            if not clone_result or clone_result.returncode != 0:
                msg = f"Failed to clone {source_clone_url} | {clone_result.stderr.decode() if clone_result else ''}"
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider_label, source_clone_url, destination_gitlab_url, msg, error=True)
                return

            repo_dir = os.path.join(temp_dir, "repo")
            # Set destination remote and push all refs
            set_url_result = execute_command(["git", "remote", "set-url", "origin", destination_gitlab_url], cwd=repo_dir)
            if set_url_result == "timeout" or isinstance(set_url_result, Exception) or (set_url_result and set_url_result.returncode != 0):
                msg = f"Failed to set remote URL for {destination_gitlab_url}"
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider_label, source_clone_url, destination_gitlab_url, msg, error=True)
                return

            push_result = execute_command(["git", "push", "--mirror", "origin"], cwd=repo_dir)
            if push_result == "timeout" or isinstance(push_result, Exception):
                msg = f"Pushing timed out or failed: {destination_gitlab_url}"
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider_label, source_clone_url, destination_gitlab_url, msg, error=True)
                return
            if not push_result:
                msg = "Push subprocess failed."
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider_label, source_clone_url, destination_gitlab_url, msg, error=True)
                return
            stdout = push_result.stdout.decode()
            stderr = push_result.stderr.decode()
            if push_result.returncode == 0:
                if ("Everything up-to-date" not in stdout) and ("Everything up-to-date" not in stderr):
                    logger.info(f"Changes pushed: {source_clone_url} -> {destination_gitlab_url}")
                    if teams_webhook_url:
                        notify_teams_sync(
                            teams_webhook_url,
                            provider_label,
                            source_clone_url,
                            destination_gitlab_url,
                            "Changes pushed"
                        )
                else:
                    logger.info(f"No changes to sync for {source_clone_url}")
            else:
                msg = f"Failed to push: {source_clone_url} to {destination_gitlab_url} | {stderr}"
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider_label, source_clone_url, destination_gitlab_url, msg, error=True)
        except Exception as exc:
            msg = f"Sync error: {exc}"
            logger.error(msg)
            if teams_webhook_url:
                notify_teams_sync(teams_webhook_url, provider_label, source_clone_url, destination_gitlab_url, msg, error=True)

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

    github_provider = GitHubSource(GITHUB_TOKEN, GITHUB_USERNAME) if GITHUB_TOKEN and GITHUB_USERNAME else None
    gitee_provider = GiteeSource(GITEE_TOKEN, GITEE_USERNAME) if GITEE_TOKEN and GITEE_USERNAME else None
    bitbucket_provider = BitbucketSource(BITBUCKET_TOKEN, BITBUCKET_USERNAME) if BITBUCKET_TOKEN and BITBUCKET_USERNAME else None
    gitlab_destination = GitLabDestination(GITLAB_TOKEN, GITLAB_USERNAME)

    sources = []
    if github_provider: sources.append(("github", github_provider))
    if gitee_provider: sources.append(("gitee", gitee_provider))
    if bitbucket_provider: sources.append(("bitbucket", bitbucket_provider))

    for provider_label, source_provider in sources:
        logger.info(f"==== Syncing all repositories from {provider_label.upper()} ====")
        if hasattr(source_provider, "fetch_all_repositories"):
            repositories = []
            try:
                repositories = source_provider.fetch_all_repositories(TEAMS_WEBHOOK_URL)
            except Exception as exc:
                msg = f"Failed to list repositories for {provider_label}: {exc}"
                logger.error(msg)
                if TEAMS_WEBHOOK_URL:
                    notify_teams_sync(TEAMS_WEBHOOK_URL, provider_label, "", "", msg, error=True)
                continue
            for repo_info in repositories:
                try:
                    mirror_repository(
                        source_provider,
                        gitlab_destination,
                        provider_label,
                        repo_info,
                        TEAMS_WEBHOOK_URL
                    )
                except Exception as err:
                    msg = f"Failed to sync {provider_label} repo {repo_info}: {err}"
                    logger.error(msg)
                    if TEAMS_WEBHOOK_URL:
                        notify_teams_sync(TEAMS_WEBHOOK_URL, provider_label, str(repo_info), "", msg, error=True)
        else:
            msg = f"Provider {provider_label} does not support listing repositories."
            logger.warning(msg)
            if TEAMS_WEBHOOK_URL:
                notify_teams_sync(TEAMS_WEBHOOK_URL, provider_label, "", "", msg, error=True)

if __name__ == "__main__":
    main()
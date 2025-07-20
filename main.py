import os
import re
import subprocess
import tempfile
import logging
import requests
from datetime import datetime
import time

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

def safe_dir_name(path):
    return re.sub(r'[^a-zA-Z0-9_\-]', '-', path)

def log_prefix(provider, repo_idx, repo_total, repo_path, branch, branch_idx, branch_total, status=None, emoji=None):
    # Example custom: add emoji and sync status
    em = f"{emoji} " if emoji else ""
    stat = f"[{status}]" if status else ""
    parts = [
        em,
        f"[{provider.capitalize()} {repo_idx}/{repo_total}]",
        f"[Repo: {repo_path}]"
    ]
    if branch:
        parts.append(f"[Branch: {branch} {branch_idx}/{branch_total}]")
    if status:
        parts.append(stat)
    return ' '.join(parts)

def run_command(cmd, cwd=None, retries=3, retry_delay=20, timeout=600,
                log_ctx="", operation_name="", attempt_offset=1):
    display_cmd = [re.sub(r"://[^:]+:[^@]+@", "://<redacted>@", a) if "@" in a else a for a in cmd]
    for attempt in range(attempt_offset, retries + attempt_offset):
        prefix = log_ctx
        attempt_str = f"[{attempt}/{retries}]"
        logger.info(f"{prefix}{attempt_str} {operation_name} {' '.join(display_cmd)}")
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
            )
            elapsed = time.time() - start_time
            logger.info(f"{prefix}{attempt_str} {operation_name} Command duration: {elapsed:.2f} seconds")
            if result.returncode == 0:
                return result
            else:
                logger.error(f"{prefix}{attempt_str} {operation_name} Command failed: Return code: {result.returncode} | Stderr: {result.stderr.decode().strip()}")
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            logger.error(f"{prefix}{attempt_str} {operation_name} Command timed out: Timeout: {timeout}s after {elapsed:.2f}s")
        except Exception as exc:
            logger.error(f"{prefix}{attempt_str} {operation_name} Command error: Exception: {exc}")
        if attempt < retries + attempt_offset - 1:
            logger.info(f"{prefix}{attempt_str} Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)
    return None

class GitHubSource:
    def __init__(self, access_token, username):
        self.api_url = "https://api.github.com"
        self.access_token = access_token
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
        return f"https://{self.username}:{self.access_token}@github.com/{repo['owner']}/{repo['name']}.git"

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
        return f"https://{self.username}:{self.access_token}@gitee.com/{repo['owner']}/{repo['name']}.git"

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
        return f"https://{self.auth[0]}:{self.auth[1]}@bitbucket.org/{repo['workspace']}/{repo['slug']}.git"

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
        self.access_token = access_token

    def get_destination_url(self, repo_path):
        return f"https://{self.username}:{self.access_token}@gitlab.com/{repo_path}.git"

    def ensure_project_exists(self, repo_path):
        try:
            namespace, name = repo_path.rsplit("/", 1)
            group_id = self.get_group_id(namespace)
            if not group_id:
                logger.error(f"GitLab group '{namespace}' not found. Cannot create project '{name}'.")
                return False
            url = f"{self.api_url}/projects/{namespace.replace('/', '%2F')}%2F{name}"
            r = requests.get(url, headers=self.headers)
            if r.status_code == 200:
                return True  # Project exists
            create_url = f"{self.api_url}/projects"
            data = {
                "name": name,
                "namespace_id": group_id,
                "path": name,
                "visibility": "private"
            }
            r = requests.post(create_url, headers=self.headers, data=data)
            if r.status_code == 201:
                logger.info(f"Created GitLab project {namespace}/{name}")
                return True
            logger.error(f"Failed to create GitLab project {namespace}/{name}: {r.status_code} {r.text}")
            return False
        except Exception as exc:
            logger.error(f"Exception while ensuring GitLab project exists: {exc}")
            return False

    def get_group_id(self, namespace):
        url = f"{self.api_url}/groups/{namespace.replace('/', '%2F')}"
        r = requests.get(url, headers=self.headers)
        if r.status_code == 200:
            return r.json()["id"]
        return None

def sync_branch(source_clone_url, branch, destination_gitlab_url, repo_dir_name,
                teams_webhook_url=None, provider=None, repo_idx=None, repo_total=None, repo_path=None, branch_idx=None, branch_total=None):
    CLONE_RETRIES = 3
    CLONE_DELAY = 30
    CLONE_TIMEOUT = 600
    PUSH_RETRIES = 3
    PUSH_DELAY = 30
    PUSH_TIMEOUT = 600

    prefix = log_prefix(provider, repo_idx, repo_total, repo_path, branch, branch_idx, branch_total)

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir_path = os.path.join(temp_dir, repo_dir_name)
        try:
            clone_result = run_command(
                ["git", "clone", "--single-branch", "--branch", branch, source_clone_url, repo_dir_path],
                cwd=temp_dir, retries=CLONE_RETRIES, retry_delay=CLONE_DELAY, timeout=CLONE_TIMEOUT,
                log_ctx=prefix, operation_name="git clone"
            )
            if not clone_result or clone_result.returncode != 0:
                stderr = clone_result.stderr.decode() if clone_result else ''
                msg = (f"{prefix} Failed to clone branch '{branch}' from {source_clone_url} after {CLONE_RETRIES} attempts. "
                       f"Last error: {stderr}")
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider, source_clone_url, destination_gitlab_url, msg, error=True)
                return {"status": "failed", "message": msg}

            run_command(["git", "remote", "remove", "destination"], cwd=repo_dir_path, retries=1,
                        log_ctx=prefix, operation_name="git remote remove")
            run_command(["git", "remote", "add", "destination", destination_gitlab_url], cwd=repo_dir_path, retries=1,
                        log_ctx=prefix, operation_name="git remote add")

            push_result = run_command(
                ["git", "push", "-u", "destination", f"{branch}:{branch}"],
                cwd=repo_dir_path, retries=PUSH_RETRIES, retry_delay=PUSH_DELAY, timeout=PUSH_TIMEOUT,
                log_ctx=prefix, operation_name="git push"
            )
            if not push_result or push_result.returncode != 0:
                stderr = push_result.stderr.decode() if push_result else ''
                msg = (f"{prefix} Failed to push branch '{branch}' to {destination_gitlab_url} after {PUSH_RETRIES} attempts. "
                       f"Last error: {stderr}")
                logger.error(msg)
                if teams_webhook_url:
                    notify_teams_sync(teams_webhook_url, provider, source_clone_url, destination_gitlab_url, msg, error=True)
                return {"status": "failed", "message": msg}
            else:
                stdout = push_result.stdout.decode()
                stderr = push_result.stderr.decode()
                if ("Everything up-to-date" not in stdout) and ("Everything up-to-date" not in stderr):
                    msg = f"{prefix} Branch '{branch}' changes pushed: {source_clone_url} -> {destination_gitlab_url}"
                    logger.info(msg)
                    if teams_webhook_url:
                        notify_teams_sync(teams_webhook_url, provider, source_clone_url, destination_gitlab_url, f"Branch '{branch}' changes pushed")
                    return {"status": "success", "message": msg}
                else:
                    msg = f"{prefix} No changes to sync for branch '{branch}' in {source_clone_url}"
                    logger.info(msg)
                    return {"status": "success", "message": msg}

        except Exception as exc:
            msg = f"{prefix} Sync error for branch '{branch}': {exc}"
            logger.error(msg)
            if teams_webhook_url:
                notify_teams_sync(teams_webhook_url, provider, source_clone_url, destination_gitlab_url, msg, error=True)
            return {"status": "failed", "message": msg}

def print_summary(sync_results):
    successes = [r for r in sync_results if r['status'] == 'success']
    failures = [r for r in sync_results if r['status'] != 'success']

    logger.info("\n=== Sync cycle summary ===")
    logger.info(f"Total syncs: {len(sync_results)} | Successes: {len(successes)} | Failures: {len(failures)}")
    if successes:
        logger.info("Successful syncs:")
        for res in successes:
            logger.info(f"[{res['provider']}] [{res['repo']}] [{res['branch']}] OK: {res['message'][:100]}")
    if failures:
        logger.error("Failed syncs:")
        for res in failures:
            logger.error(f"[{res['provider']}] [{res['repo']}] [{res['branch']}] FAILED: {res['message'][:150]}")
    logger.info("=========================\n")

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
    SLEEP_SECONDS = int(os.environ.get("SYNC_INTERVAL", "300"))  # Default: 5 minutes

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
        sync_results = []
        for provider_label, source_provider in sources:
            logger.info(f"==== Syncing repositories from {provider_label.upper()} ====")
            repositories = source_provider.fetch_all_repositories()
            repo_total = len(repositories)
            for repo_idx, repo_info in enumerate(repositories, start=1):
                if provider_label == "bitbucket":
                    repo_path = f"{repo_info.get('workspace')}/{repo_info.get('slug')}"
                else:
                    repo_path = f"{repo_info.get('owner')}/{repo_info.get('name')}"

                source_clone_url = source_provider.get_clone_url(repo_info)
                destination_path = create_gitlab_destination_path(provider_label, repo_path)
                repo_dir_name = safe_dir_name(destination_path)
                
                if not gitlab_destination.ensure_project_exists(destination_path):
                    logger.error(f"Cannot sync to GitLab: project {destination_path} does not exist and could not be created.")
                    continue
                destination_gitlab_url = gitlab_destination.get_destination_url(destination_path)

                branches = source_provider.fetch_branches(repo_info)
                if not branches:
                    logger.info(f"No branches found for repo {repo_path}. Skipping.")
                    continue

                branch_total = len(branches)
                for branch_idx, branch in enumerate(branches, start=1):
                    result = sync_branch(
                        source_clone_url, branch, destination_gitlab_url, repo_dir_name,
                        teams_webhook_url=TEAMS_WEBHOOK_URL, provider=provider_label,
                        repo_idx=repo_idx, repo_total=repo_total,
                        repo_path=repo_path, branch_idx=branch_idx, branch_total=branch_total
                    )
                    sync_results.append({
                        "provider": provider_label,
                        "repo": repo_path,
                        "branch": branch,
                        "status": result.get('status', 'unknown'),
                        "message": result.get('message', '')
                    })
        print_summary(sync_results)
        logger.info(f"=== Sync cycle complete. Sleeping {SLEEP_SECONDS} seconds ===")
        time.sleep(SLEEP_SECONDS)

if __name__ == "__main__":
    main()
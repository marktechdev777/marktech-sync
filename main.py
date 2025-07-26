import os
import re
import subprocess
import tempfile
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from datetime import datetime, timezone
import time
import threading
import queue
import signal
import random
import hashlib
from typing import Optional
from urllib.parse import urlsplit, urlunsplit, quote

# =========================
# Logging
# =========================
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "sync.log")
os.makedirs(LOG_DIR, exist_ok=True)

# We print fully-formatted human messages ourselves:
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(LOG_FILE, encoding="utf-8")],
)
logger = logging.getLogger("MarktechSync")

# =========================
# Globals / Config
# =========================
REQUEST_TIMEOUT = 20
MAX_WORKERS = 10  # bounded concurrency: 10 worker threads
BACKOFF_BASE = 2
BACKOFF_MAX = 60
BACKOFF_JITTER = 0.25  # seconds (randomized up to this)

stop_event = threading.Event()

# =========================
# HTTP session with retries
# =========================
def build_session():
    s = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=50, pool_maxsize=50)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

SESSION = build_session()

# =========================
# Sanitization helpers
# =========================
def sanitize_url(u: str) -> str:
    try:
        p = urlsplit(u)
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
        return urlunsplit((p.scheme, host, p.path, p.query, p.fragment))
    except Exception:
        return re.sub(r"://[^@]+@", "://<redacted>@", u)

SECRETISH_URL = re.compile(r"https?://[^\s]+", re.IGNORECASE)

def scrub_text(s: str) -> str:
    if not isinstance(s, str):
        return s
    return SECRETISH_URL.sub(lambda m: sanitize_url(m.group(0)), s)

def redact_cmd_args(args):
    # Redact credentials in displayed command
    return [re.sub(r"://[^:]+:[^@]+@", "://<redacted>@", a) if isinstance(a, str) and "@" in a else a for a in args]

def oneline(s: str) -> str:
    if not isinstance(s, str):
        return s
    return re.sub(r"\s+", " ", s).strip()

# =========================
# Human log line helpers
# =========================
PROVIDER_NAME = {"github": "GitHub", "gitee": "Gitee", "bitbucket": "Bitbucket"}

def _thread_tag():
    name = threading.current_thread().name
    if name.startswith("worker-"):
        n = name.split("-", 1)[1]
        return f"worker: {n.zfill(2)}"
    return "main      "

def job_id(provider: str, repo_path: str) -> str:
    return hashlib.sha1(f"{provider}:{repo_path}".encode()).hexdigest()[:8]

def human_log(message: str, provider: Optional[str] = None, job: str = "--------", level: str = "info"):
    parts = [f"[MarktechSync] [{_thread_tag():<10}] [job: {job}]"]
    if provider:
        parts.append(f"[{provider}]")
    line = " ".join(parts) + f" {message}"
    getattr(logger, level)(line)

# =========================
# Slack notifications
# =========================
def _slack_post(webhook_url, payload):
    if not webhook_url:
        return
    try:
        resp = SESSION.post(webhook_url, headers={"Content-Type": "application/json"}, json=payload, timeout=REQUEST_TIMEOUT)
        if not (200 <= resp.status_code < 300):
            logger.error(f"Slack webhook failed: {resp.status_code} {resp.text}")
        elif resp.text and resp.text.strip().lower() != "ok":
            logger.info(f"Slack webhook response: {resp.text.strip()}")
    except Exception as exc:
        logger.error(f"Slack webhook exception: {exc}")

def notify_slack_sync(webhook_url, provider, source_repo_url, destination_repo_url, message, error=False):
    status_emoji = ":x:" if error else ":white_check_mark:"
    now = datetime.now(timezone.utc).isoformat() + " UTC"
    payload = {
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"{status_emoji} Repository Sync {'FAILED' if error else 'Completed'}"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Provider:*\n{provider}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{now}"},
                    {"type": "mrkdwn", "text": f"*Source:*\n`{sanitize_url(source_repo_url or '')}`"},
                    {"type": "mrkdwn", "text": f"*Destination:*\n`{sanitize_url(destination_repo_url or '')}`"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Result:*\n{scrub_text(message or '')}"}},
        ]
    }
    _slack_post(webhook_url, payload)

def notify_slack_summary(webhook_url, cycle_started_utc, results):
    if not webhook_url:
        return
    total = len(results)
    successes = [r for r in results if r["status"] == "success"]
    failures = [r for r in results if r["status"] != "success"]
    status_emoji = ":white_check_mark:" if not failures else ":x:"

    max_items = 15
    fail_lines = []
    for r in failures[:max_items]:
        fail_lines.append(f"• *[{r['provider']}]* {r['repo']} *[{r['branch']}]*: {scrub_text(r['message'])[:200]}")
    if len(failures) > max_items:
        fail_lines.append(f"_... and {len(failures) - max_items} more failures_")

    summary_blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{status_emoji} Repository Sync Summary"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Cycle start:*\n{cycle_started_utc} UTC"},
            {"type": "mrkdwn", "text": f"*Total syncs:*\n{total}"},
            {"type": "mrkdwn", "text": f"*Successes:*\n{len(successes)}"},
            {"type": "mrkdwn", "text": f"*Failures:*\n{len(failures)}"},
        ]},
    ]
    if fail_lines:
        summary_blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Failures:*\n" + "\n".join(fail_lines)}})

    _slack_post(webhook_url, {"blocks": summary_blocks})

# =========================
# Path helpers
# =========================
def create_gitlab_destination_path(provider, repo_path):
    # Preserve owner/repo hierarchy to avoid collisions: marktech-sync/{provider}/{owner}/{repo}
    provider = provider.lower()
    owner, name = repo_path.split("/", 1)
    return f"marktech-sync/{provider}/{owner}/{name}"

def safe_dir_name(path):
    return re.sub(r"[^a-zA-Z0-9_\-]", "-", path)

# =========================
# Commands with backoff & (optional) silent logging
# =========================
def _sleep_with_jitter(seconds):
    end = time.time() + seconds
    while not stop_event.is_set() and time.time() < end:
        time.sleep(min(0.1, end - time.time()))

def run_command(cmd, cwd=None, retries=3, base_delay=5, max_delay=BACKOFF_MAX, timeout=600,
                log_ctx="", operation_name="", attempt_offset=1, env=None, silent=False):
    display_cmd = redact_cmd_args(cmd)  # only used if not silent
    for attempt in range(attempt_offset, retries + attempt_offset):
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
            )
            elapsed = time.time() - start_time
            if result.returncode == 0:
                return result
            else:
                if not silent:
                    stderr = oneline(scrub_text(result.stderr.decode(errors="replace").strip()))
                    logger.error(f"{operation_name} failed (rc={result.returncode}) in {elapsed:.2f}s | Cmd: {' '.join(display_cmd)} | Stderr: {stderr}")
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            if not silent:
                logger.error(f"{operation_name} timed out after {elapsed:.2f}s (timeout={timeout}s) | Cmd: {' '.join(display_cmd)}")
        except Exception as exc:
            if not silent:
                logger.error(f"{operation_name} error: {exc} | Cmd: {' '.join(display_cmd)}")

        # backoff with randomized jitter
        if attempt < retries + attempt_offset - 1 and not stop_event.is_set():
            delay = min(max_delay, base_delay * (BACKOFF_BASE ** (attempt - attempt_offset)))
            delay += random.uniform(0, BACKOFF_JITTER)
            if not silent:
                logger.info(f"Retrying in {delay:.2f} seconds... | Cmd: {' '.join(display_cmd)}")
            _sleep_with_jitter(delay)
    return None

# =========================
# Author rewrite (filter-branch; consider filter-repo for speed)
# =========================
def rewrite_authors(repo_dir, new_name, new_email, logger, log_ctx=""):
    # logger.info(f"{log_ctx} Rewriting authorship: {new_name} <{new_email}> for all commits in {repo_dir}")
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = new_name
    env["GIT_AUTHOR_EMAIL"] = new_email
    env["GIT_COMMITTER_NAME"] = new_name
    env["GIT_COMMITTER_EMAIL"] = new_email
    cmd = [
        "git", "filter-branch", "--force", "--env-filter", "",
        "--tag-name-filter", "cat", "--", "--all"
    ]
    result = subprocess.run(cmd, cwd=repo_dir, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    # if result.returncode == 0:
    #     logger.info(f"{log_ctx} Successfully rewrote authorship in {repo_dir}")
    # else:
    #     logger.error(f"{log_ctx} Author rewrite failed: {scrub_text(result.stderr.decode(errors='replace').strip())}")
    return result.returncode == 0

# =========================
# Providers
# =========================
class GitHubSource:
    def __init__(self, access_token, username, session=None):
        self.api_url = "https://api.github.com"
        self.access_token = access_token
        self.headers = {"Authorization": f"token {access_token}"}
        self.username = username
        self.session = session or SESSION

    def fetch_all_repositories(self):
        repositories = []
        page = 1
        while True:
            url = f"{self.api_url}/user/repos"
            try:
                response = self.session.get(
                    url,
                    headers=self.headers,
                    params={"per_page": 100, "page": page, "affiliation": "owner,collaborator,organization_member"},
                    timeout=REQUEST_TIMEOUT,
                )
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
        return repositories

    def get_clone_url(self, repo):
        return f"https://{self.username}:{self.access_token}@github.com/{repo['owner']}/{repo['name']}.git"

    def fetch_branches(self, repo):
        branches, page = [], 1
        while True:
            url = f"{self.api_url}/repos/{repo['owner']}/{repo['name']}/branches"
            try:
                response = self.session.get(url, headers=self.headers, params={"per_page": 100, "page": page}, timeout=REQUEST_TIMEOUT)
                if response.status_code != 200:
                    logger.error(f"GitHub branch API error {response.status_code}: {response.text}")
                    return branches
                data = response.json()
                if not data:
                    break
                branches.extend([b["name"] for b in data])
                page += 1
            except Exception as exc:
                logger.error(f"GitHub branch fetch error: {exc}")
                return branches
        return branches

class GiteeSource:
    def __init__(self, access_token, username, session=None):
        self.api_url = "https://gitee.com/api/v5"
        self.access_token = access_token
        self.username = username
        self.session = session or SESSION

    def fetch_all_repositories(self):
        repositories = []
        page = 1
        while True:
            url = f"{self.api_url}/user/repos"
            try:
                response = self.session.get(
                    url,
                    params={"access_token": self.access_token, "page": page, "per_page": 100},
                    timeout=REQUEST_TIMEOUT,
                )
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
        return repositories

    def get_clone_url(self, repo):
        return f"https://{self.username}:{self.access_token}@gitee.com/{repo['owner']}/{repo['name']}.git"

    def fetch_branches(self, repo):
        branches, page = [], 1
        while True:
            url = f"{self.api_url}/repos/{repo['owner']}/{repo['name']}/branches"
            try:
                response = self.session.get(url, params={"access_token": self.access_token, "page": page, "per_page": 100}, timeout=REQUEST_TIMEOUT)
                if response.status_code != 200:
                    logger.error(f"Gitee branch API error {response.status_code}: {response.text}")
                    return branches
                data = response.json()
                if not data:
                    break
                branches.extend([b["name"] for b in data])
                page += 1
            except Exception as exc:
                logger.error(f"Gitee branch fetch error: {exc}")
                return branches
        return branches

class BitbucketSource:
    def __init__(self, access_token, username, session=None):
        self.api_url = "https://api.bitbucket.org/2.0"
        self.auth = (username, access_token)
        self.session = session or SESSION

    def fetch_all_repositories(self):
        repositories = []
        url = f"{self.api_url}/repositories/{self.auth[0]}?pagelen=100"
        while url:
            try:
                response = self.session.get(url, auth=self.auth, timeout=REQUEST_TIMEOUT)
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
        return repositories

    def get_clone_url(self, repo):
        return f"https://{self.auth[0]}:{self.auth[1]}@bitbucket.org/{repo['workspace']}/{repo['slug']}.git"

    def fetch_branches(self, repo):
        branches = []
        url = f"{self.api_url}/repositories/{repo['workspace']}/{repo['slug']}/refs/branches?pagelen=100"
        try:
            while url:
                response = self.session.get(url, auth=self.auth, timeout=REQUEST_TIMEOUT)
                if response.status_code != 200:
                    logger.error(f"Bitbucket branch API error {response.status_code}: {response.text}")
                    return branches
                data = response.json()
                branches.extend([b["name"] for b in data.get("values", [])])
                url = data.get("next")
        except Exception as exc:
            logger.error(f"Bitbucket branch fetch error: {exc}")
            return branches
        return branches

# =========================
# GitLab destination
# =========================
class GitLabDestination:
    def __init__(self, access_token, username, session=None):
        self.api_url = "https://gitlab.com/api/v4"
        self.headers = {"PRIVATE-TOKEN": access_token}
        self.username = username
        self.access_token = access_token
        self.session = session or SESSION

    def get_destination_url(self, repo_path):
        return f"https://{self.username}:{self.access_token}@gitlab.com/{repo_path}.git"

    def get_group(self, full_path):
        url = f"{self.api_url}/groups/{quote(full_path, safe='')}"
        r = self.session.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.json()
        return None

    def ensure_group_path(self, full_path):
        """
        Ensure a nested group path exists, creating missing segments.
        Returns the group id for the final path or None.
        """
        parts = full_path.split("/")
        current_path = ""
        parent_id = None
        for part in parts:
            current_path = part if not current_path else f"{current_path}/{part}"
            g = self.get_group(current_path)
            if g:
                parent_id = g["id"]
                continue
            # Create subgroup
            create_url = f"{self.api_url}/groups"
            payload = {"name": part, "path": part}
            if parent_id:
                payload["parent_id"] = parent_id
            r = self.session.post(create_url, headers=self.headers, data=payload, timeout=REQUEST_TIMEOUT)
            if r.status_code not in (201, 409):
                logger.error(f"Failed to create subgroup '{current_path}': {r.status_code} {r.text}")
                return None
            # fetch created/existing
            g = self.get_group(current_path)
            if not g:
                logger.error(f"Unable to verify subgroup '{current_path}' after creation.")
                return None
            parent_id = g["id"]
        return parent_id

    def ensure_project_exists(self, repo_path):
        try:
            namespace, name = repo_path.rsplit("/", 1)
            group_id = self.ensure_group_path(namespace)
            if not group_id:
                logger.error(f"GitLab group '{namespace}' missing and could not be created. Cannot create project '{name}'.")
                return False
            encoded = f"{quote(namespace, safe='')}" + "%2F" + quote(name, safe="")
            url = f"{self.api_url}/projects/{encoded}"
            r = self.session.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                return True  # Project exists
            create_url = f"{self.api_url}/projects"
            data = {"name": name, "namespace_id": group_id, "path": name, "visibility": "private"}
            r = self.session.post(create_url, headers=self.headers, data=data, timeout=REQUEST_TIMEOUT)
            if r.status_code == 201:
                human_log(f"Created GitLab project {namespace}/{name}")
                return True
            logger.error(f"Failed to create GitLab project {namespace}/{name}: {r.status_code} {r.text}")
            return False
        except Exception as exc:
            logger.error(f"Exception while ensuring GitLab project exists: {exc}")
            return False

    def count_projects_in_group(self, full_path: str) -> int:
        """Counts projects under a group (including subgroups)."""
        g = self.get_group(full_path)
        if not g:
            return 0
        gid = g["id"]
        total = 0
        page = 1
        while True:
            r = self.session.get(
                f"{self.api_url}/groups/{gid}/projects",
                headers=self.headers,
                params={"per_page": 100, "page": page, "include_subgroups": "true", "simple": "true"},
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code != 200:
                break
            data = r.json()
            if not data:
                break
            total += len(data)
            page += 1
        return total

# =========================
# Sync functions
# =========================
def sync_branch(source_clone_url, branch, destination_gitlab_url, repo_dir_name,
                slack_webhook_url=None, provider=None, repo_idx=None, repo_total=None, repo_path=None, branch_idx=None, branch_total=None,
                dest_author_name=None, dest_author_email=None, job=None):
    CLONE_RETRIES = 3
    PUSH_RETRIES = 3
    CLONE_TIMEOUT = 600
    PUSH_TIMEOUT = 600

    prov = PROVIDER_NAME.get(provider, (provider or "").capitalize())
    display_repo = repo_path

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir_path = os.path.join(temp_dir, repo_dir_name)
        try:
            # --- Clone with our own retry loop (silent command runner)
            last_err = ""
            ok = False
            for attempt in range(1, CLONE_RETRIES + 1):
                res = run_command(
                    ["git", "clone", "--single-branch", "--branch", branch, source_clone_url, repo_dir_path],
                    cwd=temp_dir, retries=1, base_delay=5, timeout=CLONE_TIMEOUT, silent=True,
                    operation_name="git clone"
                )
                if res and res.returncode == 0:
                    ok = True
                    break
                last_err = oneline(scrub_text(res.stderr.decode(errors="replace") if res else ""))
                human_log(f"Sync \"{display_repo}\" on branch \"{branch}\" failed! (attempt {attempt}/{CLONE_RETRIES})",
                          provider=prov, job=job, level="error")
                if last_err:
                    human_log(f"Error: {last_err}", provider=prov, job=job, level="error")
                if attempt < CLONE_RETRIES:
                    _sleep_with_jitter(5 * (2 ** (attempt - 1)))
            if not ok:
                msg = f"Clone failed for '{branch}' from {sanitize_url(source_clone_url)} after {CLONE_RETRIES} attempts. Last error: {last_err}"
                return {"status": "failed", "message": msg}

            if dest_author_name and dest_author_email:
                success = rewrite_authors(repo_dir_path, dest_author_name, dest_author_email, logger, log_ctx="")
                if not success:
                    msg = f"Author rewrite failed for branch '{branch}' in {repo_dir_path}."
                    human_log(f"Sync \"{display_repo}\" on branch \"{branch}\" failed!", provider=prov, job=job, level="error")
                    human_log(f"Error: {oneline(scrub_text(msg))}", provider=prov, job=job, level="error")
                    return {"status": "failed", "message": msg}

            # Set destination remote (silent)
            run_command(["git", "remote", "remove", "destination"], cwd=repo_dir_path, retries=1, silent=True,
                        operation_name="git remote remove")
            run_command(["git", "remote", "add", "destination", destination_gitlab_url], cwd=repo_dir_path, retries=1, silent=True,
                        operation_name="git remote add")

            # --- Push with our own retry loop
            push_result = None
            last_err = ""
            for attempt in range(1, PUSH_RETRIES + 1):
                res = run_command(
                    ["git", "push", "-u", "--force", "destination", f"{branch}:{branch}"],
                    cwd=repo_dir_path, retries=1, base_delay=5, timeout=PUSH_TIMEOUT, silent=True,
                    operation_name="git push"
                )
                if res and res.returncode == 0:
                    push_result = res
                    break
                last_err = oneline(scrub_text(res.stderr.decode(errors="replace") if res else ""))
                human_log(f"Sync \"{display_repo}\" on branch \"{branch}\" failed! (attempt {attempt}/{PUSH_RETRIES})",
                          provider=prov, job=job, level="error")
                if last_err:
                    human_log(f"Error: {last_err}", provider=prov, job=job, level="error")
                if attempt < PUSH_RETRIES:
                    _sleep_with_jitter(5 * (2 ** (attempt - 1)))
            if not push_result:
                msg = (f"Failed to push branch '{branch}' to {sanitize_url(destination_gitlab_url)} after {PUSH_RETRIES} attempts. "
                       f"Last error: {last_err}")
                return {"status": "failed", "message": msg}
            else:
                stdout = push_result.stdout.decode(errors="replace")
                stderr = push_result.stderr.decode(errors="replace")
                if ("Everything up-to-date" not in stdout) and ("Everything up-to-date" not in stderr):
                    msg = f"Branch '{branch}' changes pushed: {sanitize_url(source_clone_url)} -> {sanitize_url(destination_gitlab_url)}"
                    human_log(f"Sync \"{display_repo}\" on \"{branch}\" branch completed!", provider=prov, job=job, level="info")
                    return {"status": "success", "message": msg}
                else:
                    msg = f"No changes to sync for branch '{branch}' in {sanitize_url(source_clone_url)}"
                    human_log(f"No changes found of \"{display_repo}\" on \"{branch}\" branch. Skipping.", provider=prov, job=job, level="info")
                    return {"status": "success", "message": msg}

        except Exception as exc:
            msg = f"Sync error for branch '{branch}': {exc}"
            human_log(f"Sync \"{display_repo}\" on branch \"{branch}\" failed!", provider=prov, job=job, level="error")
            human_log(f"Error: {oneline(scrub_text(str(exc)))}", provider=prov, job=job, level="error")
            return {"status": "failed", "message": msg}

def print_summary(sync_results):
    successes = [r for r in sync_results if r['status'] == 'success']
    failures = [r for r in sync_results if r['status'] != 'success']

    human_log("=== Sync cycle summary ===")
    human_log(f"Total syncs: {len(sync_results)} | Successes: {len(successes)} | Failures: {len(failures)}")
    human_log("=========================")
    if successes:
        human_log("Successful syncs:")
        for res in successes[:25]:
            human_log(f"[{res['provider']}] [{res['repo']}] [{res['branch']}] OK: {scrub_text(res['message'])[:100]}")
        human_log("=========================")
    if failures:
        human_log("Failed syncs:")
        for res in failures[:50]:
            human_log(f"[{res['provider']}] [{res['repo']}] [{res['branch']}] FAILED: {scrub_text(res['message'])[:150]}")
        human_log("=========================")

# =========================
# Concurrent per-repo worker
# =========================
def sync_single_repo_task(task):
    """
    task: dict with keys:
      provider_label, source_provider, repo_info, repo_idx, repo_total,
      gitlab_destination, SLACK_WEBHOOK_URL, DEST_AUTHOR_NAME, DEST_AUTHOR_EMAIL,
      results, lock
    """
    if stop_event.is_set():
        return
    provider_label = task["provider_label"]
    source_provider = task["source_provider"]
    repo_info = task["repo_info"]
    repo_idx = task["repo_idx"]
    repo_total = task["repo_total"]
    gitlab_destination = task["gitlab_destination"]
    SLACK_WEBHOOK_URL = task["SLACK_WEBHOOK_URL"]
    DEST_AUTHOR_NAME = task["DEST_AUTHOR_NAME"]
    DEST_AUTHOR_EMAIL = task["DEST_AUTHOR_EMAIL"]
    results = task["results"]
    lock = task["lock"]

    # figure repo_path & clone URL
    if provider_label == "bitbucket":
        repo_path = f"{repo_info.get('workspace')}/{repo_info.get('slug')}"
    else:
        repo_path = f"{repo_info.get('owner')}/{repo_info.get('name')}"

    jid = job_id(provider_label, repo_path)
    prov = PROVIDER_NAME.get(provider_label, provider_label.capitalize())
    source_clone_url = source_provider.get_clone_url(repo_info)
    destination_path = create_gitlab_destination_path(provider_label, repo_path)
    repo_dir_name = safe_dir_name(destination_path)

    # Ensure destination project
    if not gitlab_destination.ensure_project_exists(destination_path):
        msg = f"Cannot sync: project {destination_path} missing and could not be created."
        human_log(f"{msg}", provider=prov, job=jid, level="error")
        with lock:
            results.append({
                "provider": provider_label, "repo": repo_path, "branch": "-", "status": "failed", "message": msg
            })
        return

    destination_gitlab_url = gitlab_destination.get_destination_url(destination_path)

    # Fetch branches (with pagination)
    branches = source_provider.fetch_branches(repo_info)
    if not branches:
        human_log(f"No branches found of \"{repo_path}\". Skipping.", provider=prov, job=jid, level="info")
        with lock:
            results.append({"provider": provider_label, "repo": repo_path, "branch": "-", "status": "success", "message": "No branches; skipped"})
        return

    branch_total = len(branches)
    for branch_idx, branch in enumerate(branches, start=1):
        if stop_event.is_set():
            break
        result = sync_branch(
            source_clone_url, branch, destination_gitlab_url, repo_dir_name,
            slack_webhook_url=None,  # per-branch Slack optional; summary is always sent
            provider=provider_label,
            repo_idx=repo_idx, repo_total=repo_total,
            repo_path=repo_path, branch_idx=branch_idx, branch_total=branch_total,
            dest_author_name=DEST_AUTHOR_NAME, dest_author_email=DEST_AUTHOR_EMAIL, job=jid
        )
        with lock:
            results.append({
                "provider": provider_label,
                "repo": repo_path,
                "branch": branch,
                "status": result.get('status', 'unknown'),
                "message": result.get('message', ''),
            })

# =========================
# Main
# =========================
def main():
    # --- Config & validation
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
    GITHUB_USERNAME = os.environ.get("GITHUB_USERNAME")
    GITEE_TOKEN = os.environ.get("GITEE_TOKEN")
    GITEE_USERNAME = os.environ.get("GITEE_USERNAME")
    BITBUCKET_TOKEN = os.environ.get("BITBUCKET_TOKEN")
    BITBUCKET_USERNAME = os.environ.get("BITBUCKET_USERNAME")
    GITLAB_TOKEN = os.environ.get("GITLAB_TOKEN")
    GITLAB_USERNAME = os.environ.get("GITLAB_USERNAME")
    # Prefer Slack; fallback to TEAMS for backward compatibility if Slack not set
    SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL") or os.environ.get("TEAMS_WEBHOOK_URL")
    if os.environ.get("TEAMS_WEBHOOK_URL") and not os.environ.get("SLACK_WEBHOOK_URL"):
        human_log("Using TEAMS_WEBHOOK_URL as fallback for Slack webhooks.")
    SLEEP_SECONDS = int(os.environ.get("SYNC_INTERVAL", "300"))  # Default: 5 minutes
    DEST_AUTHOR_NAME = os.environ.get("DEST_AUTHOR_NAME")
    DEST_AUTHOR_EMAIL = os.environ.get("DEST_AUTHOR_EMAIL")

    if not (GITLAB_TOKEN and GITLAB_USERNAME):
        logger.error("GITLAB_TOKEN and GITLAB_USERNAME are required. Exiting.")
        return

    sources = []
    if GITHUB_TOKEN and GITHUB_USERNAME:
        sources.append(("github", GitHubSource(GITHUB_TOKEN, GITHUB_USERNAME, SESSION)))
    if GITEE_TOKEN and GITEE_USERNAME:
        sources.append(("gitee", GiteeSource(GITEE_TOKEN, GITEE_USERNAME, SESSION)))
    if BITBUCKET_TOKEN and BITBUCKET_USERNAME:
        sources.append(("bitbucket", BitbucketSource(BITBUCKET_TOKEN, BITBUCKET_USERNAME, SESSION)))

    if not sources:
        logger.error("No source providers configured! Set credentials for at least one of: GitHub, Gitee, Bitbucket.")
        return

    human_log("Configured providers: " + ", ".join(lbl for lbl, _ in sources))
    if DEST_AUTHOR_NAME and DEST_AUTHOR_EMAIL:
        human_log(f"Commit author rewrite enabled: {DEST_AUTHOR_NAME} <{DEST_AUTHOR_EMAIL}>")

    gitlab_destination = GitLabDestination(GITLAB_TOKEN, GITLAB_USERNAME, SESSION)

    # Graceful shutdown
    def handle_signal(sig, frame):
        human_log(f"Received signal {sig}. Stopping after current operations...")
        stop_event.set()
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while not stop_event.is_set():
        cycle_start = datetime.now(timezone.utc).isoformat()
        results = []
        lock = threading.Lock()
        threads = []
        try:
            human_log("=== Starting full sync cycle ===")
            work_q = queue.Queue()

            # Enqueue per-repo tasks
            for provider_label, source_provider in sources:
                repositories = source_provider.fetch_all_repositories()
                repo_total = len(repositories)
                human_log(f"{PROVIDER_NAME.get(provider_label, provider_label.capitalize())}: Found {repo_total} repositories.")
                for repo_idx, repo_info in enumerate(repositories, start=1):
                    # Skip Bitbucket repos whose slug starts with "archived-"
                    if provider_label == "bitbucket":
                        slug = str(repo_info.get("slug", ""))
                        workspace = str(repo_info.get("workspace", ""))
                        repo_path_for_skip = f"{workspace}/{slug}" if workspace and slug else slug
                        if slug.lower().startswith("archived-"):
                            jid = job_id(provider_label, repo_path_for_skip or slug)
                            human_log(
                                f"Repository \"{repo_path_for_skip}\" is archived (slug starts with 'archived-'). Skipping.",
                                provider="Bitbucket",
                                job=jid,
                                level="info",
                            )
                            continue

                    work_q.put({
                        "provider_label": provider_label,
                        "source_provider": source_provider,
                        "repo_info": repo_info,
                        "repo_idx": repo_idx,
                        "repo_total": repo_total,
                        "gitlab_destination": gitlab_destination,
                        "SLACK_WEBHOOK_URL": SLACK_WEBHOOK_URL,
                        "DEST_AUTHOR_NAME": DEST_AUTHOR_NAME,
                        "DEST_AUTHOR_EMAIL": DEST_AUTHOR_EMAIL,
                        "results": results,
                        "lock": lock,
                    })

            # Start worker threads (bounded concurrency)
            worker_count = min(MAX_WORKERS, work_q.qsize() or 1)

            def worker():
                while not stop_event.is_set():
                    try:
                        task = work_q.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        sync_single_repo_task(task)
                    except Exception as exc:
                        # Robustly skip this repo and keep the worker alive
                        try:
                            provider_label = task.get("provider_label")
                            repo_info = task.get("repo_info", {})
                            if provider_label == "bitbucket":
                                repo_path = f"{repo_info.get('workspace')}/{repo_info.get('slug')}"
                            else:
                                repo_path = f"{repo_info.get('owner')}/{repo_info.get('name')}"
                            jid = job_id(provider_label, repo_path)
                            prov = PROVIDER_NAME.get(provider_label, provider_label.capitalize())
                            human_log(f"Unexpected error while syncing \"{repo_path}\". Skipping.", provider=prov, job=jid, level="error")
                            human_log(f"Error: {oneline(scrub_text(str(exc)))}", provider=prov, job=jid, level="error")
                            with task["lock"]:
                                task["results"].append({
                                    "provider": provider_label,
                                    "repo": repo_path,
                                    "branch": "-",
                                    "status": "failed",
                                    "message": f"Unhandled error: {oneline(scrub_text(str(exc)))}",
                                })
                        except Exception:
                            logger.exception("Worker error (and failed to log task context)")
                    finally:
                        work_q.task_done()

            for i in range(worker_count):
                t = threading.Thread(target=worker, daemon=True, name=f"worker-{i+1:02d}")
                t.start()
                threads.append(t)

            # Wait for all tasks to finish or stop requested
            while not stop_event.is_set():
                try:
                    work_q.join()
                    break
                except KeyboardInterrupt:
                    stop_event.set()
                    break
        except Exception as exc:
            human_log(f"Unexpected error in sync cycle: {oneline(scrub_text(str(exc)))}", level="error")
        finally:
            # Ensure threads exit
            for t in threads:
                t.join(timeout=1)

        # Summaries (even if cycle had partial failures)
        print_summary(results)
        notify_slack_summary(SLACK_WEBHOOK_URL, cycle_start, results)

        # Optional GitLab count for the root group
        try:
            gl_count = gitlab_destination.count_projects_in_group("marktech-sync")
            human_log(f"Gitlab: Found {gl_count} repositories.")
        except Exception:
            pass

        if stop_event.is_set():
            break
        human_log(f"=== Sync cycle complete. Sleeping {SLEEP_SECONDS} seconds ===")
        # Sleep in a stop-aware way
        waited = 0
        while waited < SLEEP_SECONDS and not stop_event.is_set():
            time.sleep(min(1, SLEEP_SECONDS - waited))
            waited += 1

if __name__ == "__main__":
    main()
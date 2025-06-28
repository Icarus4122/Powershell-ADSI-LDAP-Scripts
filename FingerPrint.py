import requests # type: ignore
from bs4 import BeautifulSoup # type: ignore
import re
import sys
import subprocess
import socket
from rich.console import Console # type: ignore
from rich.spinner import Spinner # type: ignore
from rich import print # type: ignore
console = Console()

CMS_PATTERNS = {
    "WordPress": [r"/wp-content/", r"wp-includes", r'generator" content="WordPress'],
    "Joomla": [r"/templates/", r"Joomla!", r"/media/system/js/"],
    "Drupal": [r"/sites/default/files/", r"Drupal.settings", r"drupal.js"],
    "Magento": [r"/skin/frontend/", r"/js/mage/", r"/index.php/store"],
    "Typo3": [r"/typo3/", r"typo3temp/", r"typo3_src"],
}

COMMON_FILES = [
    "robots.txt", ".htaccess", "sitemap.xml",
    "favicon.ico", "crossdomain.xml", "ads.txt"
]

def check_http_methods(url: str):
    print("[bold yellow][+] Checking supported HTTP methods...[/bold yellow]")
    try:
        r = requests.options(url)
        allowed = r.headers.get('Allow', 'Unknown')
        print(f"  · Allowed Methods: [cyan]{allowed}[/cyan]")
    except Exception as e:
        print(f"[!] Failed to fetch HTTP methods: {e}")

def find_subdomains(domain: str, wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"):
    print("[bold magenta][+] Brute-forcing subdomains...[/bold magenta]")
    try:
        with open(wordlist, 'r') as file:
            for sub in file:
                sub = sub.strip()
                fqdn = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(fqdn)
                    print(f"  · {fqdn} -> {ip}")
                except:
                    continue
    except Exception as e:
        print(f"[!] Subdomain brute-force failed: {e}")

def find_html_comments(html: str):
    print("[bold cyan][+] Searching for HTML comments/info leaks...[/bold cyan]")
    comments = re.findall(r"<!--(.*?)-->", html, re.DOTALL)
    for comment in comments:
        if comment.strip():
            print(f"  · [italic]{comment.strip()}[/italic]")

def detect_injection_points(html: str, base_url: str) -> None:
    soup = BeautifulSoup(html, 'html.parser')
    print("[bold magenta][+] Analyzing for potential injection points...[/bold magenta]")
    findings = {
        "forms_with_inputs": [],
        "suspicious_urls": [],
        "scripted_requests": [],
        "potential_file_includes": []
    }

    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        text_inputs = [inp for inp in inputs if inp.get("type") in [None, "text", "search", "email", "url", "password"]]
        if text_inputs:
            findings["forms_with_inputs"].append(str(form)[:200])

    for a in soup.find_all("a", href=True):
        href = a["href"]
        if "?" in href and "=" in href:
            findings["suspicious_urls"].append(href)

    scripts = soup.find_all("script")
    for script in scripts:
        if script.string:
            matches = re.findall(r'(fetch|ajax|get|post|open)\s*\([\'"]([^\'"]+)', script.string, re.IGNORECASE)
            for _, url in matches:
                findings["scripted_requests"].append(url)

    for link in findings["suspicious_urls"]:
        if any(keyword in link.lower() for keyword in ["file=", "page=", "path="]) and (
            "../" in link or "http://" in link or ".php" in link
        ):
            findings["potential_file_includes"].append(link)

    for category, entries in findings.items():
        if entries:
            print(f"  [cyan]- {category.replace('_', ' ').title()}:[/cyan]")
            for entry in entries:
                print(f"    · {entry}")
        else:
            print(f"  [yellow]- {category.replace('_', ' ').title()}: None found[/yellow]")

def identify_cms(html: str, headers: dict) -> dict:
    found = {}
    combined = html + '\n' + str(headers)
    for cms, patterns in CMS_PATTERNS.items():
        for pat in patterns:
            match = re.search(pat, combined, re.IGNORECASE)
            if match:
                version_match = re.search(rf'{cms}[ /]?([0-9\.]+)', combined, re.IGNORECASE)
                version = version_match.group(1) if version_match else None
                found[cms] = version
                break
    return found

def find_custom_paths(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html, 'html.parser')
    urls = set()

    default_keywords = [
        "s.w.org",
        "/wp-json",
        "/feed",
        "/comments/feed",
        "/wp-content/plugins/contact-form-7/",
        "/wp-content/plugins/elementor/",
        "/wp-content/themes/hello-elementor/"
    ]

    for tag in soup.find_all(['link', 'script', 'img', 'a']):
        attr = tag.get('href') or tag.get('src')
        if not attr:
            continue
        full_url = attr if attr.startswith("http") else base_url.rstrip("/") + "/" + attr.lstrip("/")
        if not any(x in full_url for x in default_keywords):
            urls.add(full_url)

    return sorted(urls)

def fetch_common_files(base_url: str) -> dict:
    res = {}
    for fname in COMMON_FILES:
        try:
            r = requests.get(f"{base_url.rstrip('/')}/{fname}", timeout=5)
            res[fname] = r.status_code
        except:
            res[fname] = None
    return res

def run_gobuster(url: str):
    print("[bold magenta][+] Running Gobuster (dir mode)...[/bold magenta]")
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    try:
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "30"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[!] Gobuster failed: {e}")

def simulate_client_side_checks(html, base_url):
    print("[bold magenta][+] Checking for Client-Side Issues (scripts/forms)...[/bold magenta]")
    soup = BeautifulSoup(html, 'html.parser')
    findings = []

    if soup.find_all('script'):
        findings.append("JavaScript Detected")
    if soup.find_all('form'):
        findings.append("Form Detected")
    if soup.find_all('input', {'type': 'file'}):
        findings.append("File Upload Detected")
    if soup.find_all('iframe'):
        findings.append("Iframe Detected")

    if findings:
        for f in findings:
            print(f"  · {f}")
    else:
        print("  No common client-side features detected.")

    print("[bold yellow][+] Scanning for potential injection points...[/bold yellow]")
    suspicious_keywords = ["id", "page", "file", "dir", "path", "search", "query"]
    params = set()

    for form in soup.find_all('form'):
        action = form.get('action') or base_url
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            if name and any(kw in name.lower() for kw in suspicious_keywords):
                full_url = f"{base_url.rstrip('/')}/{action.lstrip('/')}?{name}=<injection>"
                params.add(full_url)

    if params:
        for p in sorted(params):
            print(f"  · [bold cyan]{p}[/bold cyan]")
    else:
        print("  No suspicious parameters detected.")

def run_wpscan(url: str):
    print("[bold yellow][+] WordPress detected — launching WPScan… (this may take a while)[/bold yellow]")
    try:
        cmd = [
            "wpscan",
            "--url", url,
            "--disable-tls-checks",
            "--no-banner",
            "--random-user-agent",
            "--enumerate", "vp,vt,cb,dbe,u",  # vp = vulnerable plugins, vt = vulnerable themes, cb = config backups, dbe = db exports, u = users
            "--format", "json"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout

        try:
            import json
            data = json.loads(output)
            if data.get("version"):
                print(f"[bold green]  · WordPress Version:[/bold green] {data['version'].get('number', 'Unknown')}")

            if data.get("plugins"):
                print("[bold magenta]  · Vulnerable Plugins:[/bold magenta]")
                for plugin in data["plugins"]:
                    if plugin.get("vulnerabilities"):
                        print(f"    · {plugin['slug']}")
                        for vuln in plugin["vulnerabilities"]:
                            print(f"      [red]- {vuln.get('title')}[/red]")

            if data.get("themes"):
                print("[bold magenta]  · Vulnerable Themes:[/bold magenta]")
                for theme in data["themes"]:
                    if theme.get("vulnerabilities"):
                        print(f"    · {theme['slug']}")
                        for vuln in theme["vulnerabilities"]:
                            print(f"      [red]- {vuln.get('title')}[/red]")

            if data.get("users"):
                print("[bold cyan]  · Enumerated Users:[/bold cyan]")
                for user in data["users"]:
                    print(f"    · {user['username']}")

        except Exception as parse_error:
            print("[!] Could not parse WPScan JSON output. Displaying raw output:")
            print(output)

    except Exception as e:
        print(f"[!] WPScan failed: {e}")

def run_joomscan(url: str):
    print("[bold yellow][+] Joomla detected — launching JoomScan…[/bold yellow]")
    try:
        cmd = ["joomscan", "--url", url]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[!] JoomScan failed: {e}")

def run_droopescan(url: str):
    print("[bold yellow][+] Drupal detected — launching Droopescan…[/bold yellow]")
    try:
        cmd = ["droopescan", "scan", "drupal", "-u", url]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[!] Droopescan failed: {e}")

def run_whatweb(url: str):
    print("[bold blue][+] Running WhatWeb for tech stack detection...[/bold blue]")
    try:
        cmd = ["whatweb", "--color=never", url]
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[!] WhatWeb failed: {e}")

def extract_title(html: str):
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.title.string.strip() if soup.title else "No title found"
    return title

def search_exploits(keywords):
    print("[bold yellow][+] Searching for public exploits via SearchSploit...[/bold yellow]")
    try:
        for keyword in keywords:
            print(f"[bold cyan][*] Searching: {keyword}[/bold cyan]")
            cmd = ["searchsploit", keyword]
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(result.stdout)
    except Exception as e:
        print(f"[!] SearchSploit error: {e}")

def test_cors(url: str):
    print("[bold yellow][+] Testing CORS configuration...[/bold yellow]")
    headers = {"Origin": "http://evil.com"}
    try:
        r = requests.get(url, headers=headers)
        cors = r.headers.get("Access-Control-Allow-Origin", "")
        if "evil.com" in cors or cors == "*":
            print("  · [red]Potentially vulnerable CORS policy![/red]")
        else:
            print("  · CORS appears safe.")
    except Exception as e:
        print(f"[!] CORS check failed: {e}")

def fingerprint_site(url: str):
    try:
        with console.status("[cyan]Fetching target...[/cyan]", spinner="dots") as status:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
        console.print("[green]✔ Fetched[/green]")
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return

    print(f"[bold blue][*] Fetched:[/bold blue] {url} (HTTP {r.status_code})")
    print(f"[bold cyan][+] Page Title:[/bold cyan] {extract_title(r.text)}")
    print("[bold yellow][+] Server Headers:[/bold yellow]")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")

    cms_found = identify_cms(r.text, r.headers)
    if cms_found:
        print("[bold green][+] Detected CMS:[/bold green]")
        search_terms = []
        for cms, version in cms_found.items():
            if version:
                print(f"    · {cms} [version {version}]")
                search_terms.append(f"{cms} {version}")
            else:
                print(f"    · {cms}")
                search_terms.append(cms)

            # Run additional scans based on CMS
            if cms == "WordPress":
                run_wpscan(url)
            elif cms == "Joomla":
                run_joomscan(url)
            elif cms == "Drupal":
                run_droopescan(url)

        search_exploits(search_terms)
    else:
        print("[bold red][-] No common CMS detected.[/bold red]")

    find_html_comments(r.text)
    test_cors(url)
    check_http_methods(url)
    run_whatweb(url)

    with console.status("[magenta]Analyzing resources...[/magenta]", spinner="dots") as status:
        paths = find_custom_paths(r.text, url)
    console.print("[green]✔ Resources parsed[/green]")
    print("[bold magenta][+] Parsing resources/paths …[/bold magenta]")
    for p in paths[:20]:
        print(f"    {p}")
    if len(paths) > 20:
        print(f"    ... +{len(paths)-20} more")

    with console.status("[blue]Checking common files...[/blue]", spinner="dots") as status:
        file_statuses = fetch_common_files(url)
    console.print("[green]✔ File check complete[/green]")
    print("[bold blue][+] Common file status:[/bold blue]")
    for fname, code in file_statuses.items():
        status = code or "ERR"
        print(f"    {fname:15} => {status}")

    simulate_client_side_checks(r.text, url) # type: ignore
    detect_injection_points(r.text, url)
    run_gobuster(url)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} https://target.example.com/")
        sys.exit(1)
    fingerprint_site(sys.argv[1])

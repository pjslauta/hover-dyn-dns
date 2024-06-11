import os
import json
import requests
import datetime
import time
import argparse
from totp import totp  # Import the totp function from totp.py

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

CONFIG_FILE = "./config.json"
IP_FILE = "./IP"
LOG_FILE = "./hover-update.log"
COOKIES_FILE = "./cookies.json"
AUTH1URL = "https://www.hover.com/signin/auth.json"
AUTH2URL = "https://www.hover.com/signin/auth2.json"
DNS_UPDATE_URL = "https://www.hover.com/api/dns/{}"
DOMAIN_CHECK_URL = "https://www.hover.com/api/control_panel/domains"

# Proxy settings for mitmproxy
DEFAULT_PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

def log_output(message, logging):
    """
    Logs a message to the log file and prints it to the console if logging is enabled.
    """
    if logging:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_FILE, 'a') as log_file:
            log_file.write(f"{timestamp} - {message}\n")
        print(f"{timestamp} - {message}")

def load_config(config_file):
    """
    Loads the configuration from a JSON file.
    """
    try:
        with open(config_file, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        log_output(f"Error loading config file: {e}", logging)
        exit(1)

def get_external_ip(proxies):
    """
    Retrieves the external IP address using the ipify API.
    """
    response = requests.get("https://api.ipify.org", proxies=proxies, verify=False)
    return response.text

def get_dns_ip(domain):
    """
    Retrieves the IP address for a given domain using the getent hosts command.
    """
    response = os.popen(f"getent hosts {domain}").read().strip()
    return response.split()[0] if response else None

def resolve_current_ip():
    """
    Resolves the current IP address using the OpenDNS resolver.
    """
    response = os.popen("dig +short myip.opendns.com @resolver1.opendns.com").read().strip()
    return response

def init_session(proxies):
    """
    Initializes a session with Hover to retrieve cookies.
    """
    response = requests.get("https://www.hover.com/signin", proxies=proxies, verify=False)
    log_output(f"Init session response status code: {response.status_code}", logging)
    log_output(f"Init session response content: {response.content}", logging)
    return response.cookies

def login(username, password, cookies, proxies):
    """
    Logs in to Hover with the provided username and password.
    """
    login_payload = {
        "username": username,
        "password": password,
        "token": None
    }
    response = requests.post(AUTH1URL, json=login_payload, proxies=proxies, verify=False, cookies=cookies)
    log_output(f"Payload: {login_payload}", logging)
    log_output(f"Login response status code: {response.status_code}", logging)
    log_output(f"Login response content: {response.content}", logging)
    log_output(f"Cookies: {cookies}", logging)
    return response

def login2fa(totp_code, cookies, proxies):
    """
    Performs 2FA login with the provided TOTP code.
    """
    login_payload = {
        "code": totp_code
    }
    response = requests.post(AUTH2URL, json=login_payload, proxies=proxies, cookies=cookies, verify=False)
    log_output(f"Payload: {login_payload}", logging)
    log_output(f"Login 2FA response status code: {response.status_code}", logging)
    log_output(f"Login 2FA response content: {response.content}", logging)
    log_output(f"Cookies: {cookies}", logging)
    return response

def update_dns_record(dnsid, ipaddress, cookies, proxies):
    """
    Updates the DNS record with the provided IP address.
    """
    files = {
        'content': (None, ipaddress)
    }
    response = requests.put(DNS_UPDATE_URL.format(dnsid), files=files, cookies=cookies, proxies=proxies, verify=False)
    log_output(f"DNS update response status code: {response.status_code}", logging)
    log_output(f"DNS update response content: {response.content}", logging)
    return response

def save_cookies(cookies):
    """
    Saves cookies to a JSON file.
    """
    with open(COOKIES_FILE, 'w') as file:
        json.dump(cookies.get_dict(), file)

def load_cookies():
    """
    Loads cookies from a JSON file.
    """
    if os.path.isfile(COOKIES_FILE):
        with open(COOKIES_FILE, 'r') as file:
            cookies_dict = json.load(file)
            return requests.cookies.cookiejar_from_dict(cookies_dict)
    return None

def cookies_valid(cookies, proxies):
    """
    Checks if the cookies are still valid by making a request to an authenticated endpoint.
    """
    response = requests.get(DOMAIN_CHECK_URL, cookies=cookies, proxies=proxies, verify=False)
    if response.status_code == 200:
        return True
    return False

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Hover DNS Update Script')
    parser.add_argument('--logging', action='store_true', help='Enable logging to hover-update.log')
    parser.add_argument('--mitm', action='store_true', help='Enable mitmproxy for HTTP/HTTPS requests')
    parser.add_argument('--getDNS', action='store_true', help='Get the DNS Records in this account')
    args = parser.parse_args()
    logging = args.logging
    proxies = DEFAULT_PROXIES if args.mitm else None

    if(args.getDNS):
        login()
        login2fa()
        dnsRecords=getDNS()
        for(record in dnsRecords)
        {
            
        }
    # Check and delete log file if older than 7 days
    if os.path.isfile(LOG_FILE):
        log_age = (datetime.datetime.now() - datetime.datetime.fromtimestamp(os.path.getmtime(LOG_FILE))).days
        if log_age > 7:
            os.remove(LOG_FILE)
            open(LOG_FILE, 'w').close()
            log_output("Log file was older than 7 days and has been deleted.", logging)

    # Load configuration
    if os.path.isfile(CONFIG_FILE):
        config = load_config(CONFIG_FILE)
        log_output(f"Using configuration from {CONFIG_FILE}", logging)
    else:
        log_output("Configuration file not found. Exiting...", logging)
        exit(1)

    # Extract configuration values
    dnsid = config.get('dnsid')
    username = config.get('username')
    password = config.get('password')
    discoverip = config.get('discoverip')
    srcdomain = config.get('srcdomain')
    ipaddress = config.get('ipaddress')
    totp_secret = config.get('totp_secret')

    # Discover IP address if required
    if discoverip == "true":
        ipaddress = get_external_ip(proxies)
        log_output(f"IP DISCOVERED: {ipaddress}", logging)
    elif srcdomain:
        ipaddress = get_dns_ip(srcdomain)
        log_output(f"SOURCE DOMAIN: {srcdomain}", logging)
        log_output(f"IP: {ipaddress}", logging)
    else:
        ipaddress = ipaddress

    # Load saved IP address
    if os.path.isfile(IP_FILE):
        with open(IP_FILE, 'r') as file:
            saved_ip = file.read().strip()
        log_output(f"Saved IP: {saved_ip}", logging)
    else:
        saved_ip = ""

    # Resolve current IP address
    resolved_ip = resolve_current_ip()
    log_output(f"Resolved IP: {resolved_ip}", logging)

    # Check if the discovered IP matches the DNS lookup
    if ipaddress != resolved_ip:
        log_output("Discovered IP does not match DNS lookup. Updating...", logging)

    # Check for required configuration values
    if not dnsid:
        log_output("Exiting due to missing DNS_ID.", logging)
        exit(1)
    if not ipaddress:
        log_output("Exiting due to missing IP ADDRESS.", logging)
        exit(1)
    if not username:
        log_output("Exiting due to missing USERNAME.", logging)
        exit(1)
    if not password:
        log_output("Exiting due to missing PASSWORD.", logging)
        exit(1)
    if not totp_secret:
        log_output("Exiting due to missing TOTP_SECRET.", logging)
        exit(1)

    log_output(f"Using username: {username}", logging)

    # Initialize session to retrieve cookies
    session_cookies = init_session(proxies)

    # Load cookies
    cookies = load_cookies()

    # Check if cookies are valid
    if cookies and cookies_valid(cookies, proxies):
        log_output("Cookies are valid. Skipping login.", logging)
    else:
        # Generate TOTP code
        totp_code = totp(totp_secret)

        # Perform login
        login_response = login(username, password, session_cookies, proxies)
        
        try:
            login_response_json = login_response.json()
            login_success = login_response_json.get('succeeded')
            if login_response_json.get('status') == 'need_2fa':
                log_output("2FA required. Performing 2FA login.", logging)
                log_output(f"CODE: {totp_code}", logging)
                login2fa_response = login2fa(totp_code, session_cookies, proxies)
                login2fa_response_json = login2fa_response.json()
                login_success = login2fa_response_json.get('succeeded')
                cookies = login2fa_response.cookies
            else:
                cookies = login_response.cookies
        except json.JSONDecodeError:
            log_output(f"Login response is not in JSON format. Status code: {login_response.status_code}, Response text: {login_response.text}", logging)
            exit(3)

        log_output(f"Login response: {login_response_json}", logging)
        if not login_success:
            log_output("Login failure! Exiting...", logging)
            exit(3)
        else:
            log_output("Login success!", logging)
            save_cookies(cookies)

    # Update DNS record
    update_response = update_dns_record(dnsid, ipaddress, cookies, proxies)
    
    try:
        update_response_json = update_response.json()
        update_success = update_response_json.get('succeeded')
    except json.JSONDecodeError:
        log_output(f"Update response is not in JSON format. Status code: {update_response.status_code}, Response text: {update_response.text}", logging)
        exit(2)

    log_output(f"Update response: {update_response_json}", logging)
    if not update_success:
        log_output("Setting failure! Exiting...", logging)
        exit(2)
    else:
        log_output("Setting success!", logging)
        with open(IP_FILE, 'w') as file:
            file.write(ipaddress)
        exit(0)
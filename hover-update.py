import os
import json
import requests
import datetime
import time
import argparse
import urllib3
from totp import totp  # Import the totp function from totp.py
import certifi
from http.cookies import SimpleCookie
import logging
from logging.handlers import TimedRotatingFileHandler
import platform
import socket

abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)
#step 1: visit https://www.hover.com/signin
#step 2: extract cookies from response
#step 3: save cookies to cookies.json
#step 4: post https://www.hover.com/signin/auth.json with cookies and form encoded username and password
#step 5: if response is 200, extract cookies from response and save to cookies.json
#step 6: post https://www.hover.com/signin/auth2.json with cookies and form encoded 2fa code
#step 7: if response is 200, extract cookies from response and save to cookies.json
#step 8: get https://www.hover.com/control_panel/dns/{dnsid} with cookies and form encoded ipaddress
#step 9: if response is 200, extract cookies from response and save to cookies.json
CONFIG_FILE = "./config.json"
IP_FILE = "./IP"
LOG_FILE = "./hover-update.log"
COOKIES_FILE = "./cookie.json"
SIGIN_URL = "https://www.hover.com/signin"
AUTH1URL = "https://www.hover.com/signin/auth.json"
AUTH2URL = "https://www.hover.com/signin/auth2.json"
DNS_UPDATE_URL = "https://www.hover.com/api/control_panel/dns/"
DOMAIN_CHECK_URL = "https://www.hover.com/api/control_panel/domains"



def get_log_retention_days():
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as file:
                config = json.load(file)
                return int(config.get('logRetentionMaxDays', 7))
        except Exception:
            return 7
    return 7

def remove_endpoint_logs():
    for fname in ["hover-signin.log", "hover-auth.log", "hover-auth2.log", "hover-dns.log"]:
        try:
            os.remove(fname)
        except FileNotFoundError:
            pass
def get_log_level():
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as file:
                config = json.load(file)
                return config.get('loglevel', 'INFO').upper()
        except Exception:
            return 'INFO'
    return 'INFO'
def get_use_endpoint_logs():
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as file:
                config = json.load(file)
                return config.get('useEndpointLogs', False)
        except Exception:
            return False
    return False

# Configure main logging with daily rotation
def setup_main_logging():
    global console
    log_retention_days = get_log_retention_days()
    log_level=get_log_level()
    handler = TimedRotatingFileHandler(LOG_FILE, when='midnight', backupCount=log_retention_days)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root_logger = logging.getLogger()
    root_logger.handlers = []
    root_logger.addHandler(handler)
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    root_logger.addHandler(console)
    root_logger.setLevel(logging.INFO)

setup_main_logging()

def load_config(config_file):
    """
    Loads the configuration from a JSON file.
    """
    try:
        with open(config_file, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError as e:
        logging.error(f"Error loading config file: {e}")
        exit(1)

def get_external_ip(http):
    """
    Retrieves the external IP address using the ipify API.
    """
    response = http.request("GET", "https://api.ipify.org")
    if response.status!=200:
        logging.error(f"Error retrieving external IP: {response.status}")
        exit(1)
    return response.data.decode('utf-8')

def get_dns_ip(domain):
    """
    Retrieves the IP address for a given domain using socket.gethostbyname (cross-platform).
    """
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logging.error(f"DNS lookup failed for {domain}: {e}")
        return None

### Returns SimpleCookie object representing the cookies
def init_session(http):
    """
    Initializes a session with Hover to retrieve cookies and headers.
    Returns (cookies, headers) tuple.
    """
    response = http.request("GET","https://www.hover.com/signin")
    logging.info(f"Init session response status code: {response.status}")
    if(response.status!=200):
        logging.error(f"Error initializing session: {response.status}")
        exit(1)
    logging.debug(f"Init session headers: {response.headers}")
    if 'set-cookie' not in response.headers.keys():
        logging.error("No Set-Cookie header found in response.")
        return None, None
    logging.debug(f"Init session cookies: {response.headers['Set-Cookie']}")
    # Extract headers for reuse, excluding cookies
    session_headers = {k: v for k, v in response.headers.items() if k.lower() not in ['set-cookie', 'cookie']}
    return SimpleCookie(response.headers['Set-Cookie']), session_headers

def login(http, username, password, cookies):
    """
    Logs in to Hover with the provided username and password.
    """
    login_payload = {
        "username": username,
        "password": password,
        "remember": "true",
        "token": None
    }
    cookie_header = "; ".join([f"{k}={v.value}" for k, v in cookies.items()])
    # Prepare headers for POST
    headers = dict(session_headers) if session_headers else {}
    body = json.dumps(login_payload).encode('utf-8')
    update_headers_case_insensitive(headers, {
        "cookie": cookie_header,
        "content-type": "application/json;charset=UTF-8",
        "content-length": str(len(body)),
        "accept-encoding": "identity",
        "user-agent": user_agent
    })
    filter_allowed_headers(headers)
    logging.debug(f"Cookie header: {cookie_header}")
    response=None
    response = http.request(
        "POST",
        AUTH1URL,
        body=body,
        headers=headers
    )
    logging.debug(f"Login URL: {AUTH1URL}")
    logging.debug(f"Login Headers: {headers}")
    logging.debug(f"Payload: {body}")
    logging.info(f"Login response status code: {response.status}")
    logging.debug(f"Cookie: {cookies}")
    return response

def login2fa(http, totp_code, cookies):
    """
    Performs 2FA login with the provided TOTP code.
    """
    login_payload = {
        "code": totp_code
    }
    # Prepare headers for POST
    headers = dict(session_headers) if session_headers else {}
    body = json.dumps(login_payload).encode('utf-8')
    update_headers_case_insensitive(headers, {
        "cookie": "; ".join([f"{k}={v.value}" for k, v in cookies.items()]),
        "content-type": "application/json;charset=UTF-8",
        "content-length": str(len(body)),
        "accept-encoding": "identity",
        "user-agent": user_agent
    })
    filter_allowed_headers(headers)
    response = http.request("POST", AUTH2URL, body=body, headers=headers)
    logging.debug(f"Payload: {body}")
    logging.info(f"Login 2FA response status code: {response.status}")
    logging.debug(f"Login 2FA response content: {response.data}")
    logging.debug(f"Cookies: {cookies}")
    return response

def update_dns_record(http, dnsid, ipaddress, cookies, session_headers, domain_name="default_domain"):
    """
    Updates the DNS record with the provided IP address.
    """
    # Build the JSON payload as required
    payload = {
        "domain": {
            "id": f"domain-{domain_name}",
            "dns_records": [
                {
                    "id": f"{dnsid}"                   
                }
            ]
        },
        "fields": {
            "content": ipaddress
        }
    }
    encoded_data = json.dumps(payload).encode('utf-8')
    cookie_header = "; ".join([f"{k}={v.value}" for k, v in cookies.items()])
    # Prepare headers for POST
    headers = dict(session_headers)
    update_headers_case_insensitive(headers, {
        "cookie": cookie_header,
        "content-type": "application/json;charset=UTF-8",
        "content-length": str(len(encoded_data)),
        "accept-encoding": "identity",
        "user-agent": user_agent
    })
    filter_allowed_headers(headers)
    logging.debug(f"Cookie header: {cookie_header}")
    filter_allowed_headers(headers)
    response = http.request("PUT", DNS_UPDATE_URL, body=encoded_data, headers=headers)
    logging.debug(f"DNS URL: {DNS_UPDATE_URL}")
    logging.info(f"DNS update response status code: {response.status}")
    logging.debug(f"DNS update response content: {response.data}")
    return response

def save_cookies(cookies):
    """
    Saves cookies (as a key-value dictionary) to a JSON file.
    """
    cookies_dict = {key: morsel.value for key, morsel in cookies.items()}
    expires_dict = {key: morsel['expires'] for key, morsel in cookies.items() if morsel['expires']}
    with open(COOKIES_FILE, 'w') as file:
        json.dump({'cookies': cookies_dict, 'expires': expires_dict}, file)
    logging.info(f"Cookies saved to {COOKIES_FILE}")


def load_cookies():
    """
    Loads cookies from a JSON file as a SimpleCookie object and checks for expiration.
    """
    if os.path.isfile(COOKIES_FILE):
        with open(COOKIES_FILE, 'r') as file:
            data = json.load(file)
        cookies_dict = data.get('cookies', {})
        expires_dict = data.get('expires', {})
        cookie = SimpleCookie()
        for key, value in cookies_dict.items():
            cookie[key] = value
            if key in expires_dict:
                cookie[key]['expires'] = expires_dict[key]
        # Check expiration
        now = datetime.datetime.now(datetime.UTC)
        for key, morsel in cookie.items():
            expires = morsel['expires']
            if expires:
                try:
                    expires_dt = datetime.datetime.strptime(expires, '%a, %d-%b-%Y %H:%M:%S GMT')
                    if expires_dt < now:
                        logging.info(f"Cookie {key} expired at {expires_dt}, will not use cached cookies.")
                        return None
                except Exception:
                    continue
        logging.info(f"Loaded cookies from {COOKIES_FILE}")
        return cookie
    return None

def cookies_valid(http, cookies):
    """
    Checks if the cookies are still valid by making a request to an authenticated endpoint.
    """
    response = http.request("GET",DOMAIN_CHECK_URL, headers={"Cookie": "; ".join([f"{k}={v}" for k, v in cookies.items()])})
    if response.status == 200:        
        logging.info("Cookies are valid.")
        return True
    else:
        logging.info("Cookies are invalid.")
    return False

def get_dns_entries(http, cookies):
    """
    Retrieves the DNS entries for the account using urllib3 and logs details.
    """
    headers = {"Cookie": "; ".join([f"{k}={v.value}" for k, v in cookies.items()]), "user-agent": user_agent}
    remove_headers_case_insensitive(headers, ["transfer-encoding"])
    url = DOMAIN_CHECK_URL
    response = http.request("GET", url, headers=headers)
    if response.status == 200:
        try:
            dns_entries = json.loads(response.data)
            for entry in dns_entries.get('domains', []):
                logging.info('================')
                logging.info(f"Domain: {entry['name']}, DNSID: {entry['id']}")
                sub_url = f"https://www.hover.com/api/control_panel/domains/{entry['name']}"
                sub_response = http.request("GET", sub_url, headers=headers)
                if sub_response.status == 200:
                    logging.info("Subdomains:")
                    subdomains = json.loads(sub_response.data)
                    for e in subdomains['domain']['dns']:
                        logging.info(f"Domain: {e['name']}, DNSID: {e['id']}, IP: {e.get('content', 'N/A')}")
                else:
                    logging.info(f"No subdomains found for {sub_url}")
        except Exception as ex:
            logging.error(f"Failed to parse DNS entries: {ex}")
            exit(4)
    else:
        logging.error(f"Failed to retrieve DNS entries. Status code: {response.status}, Response text: {response.data}")
        exit(4)
def doLogin(http, cookies=None):
    if cookies is None:
        cookies = load_cookies()
    session_headers = None
    if not cookies:
        logging.info("Cookies are invalid or not found. Initializing session and logging in...")
        cookies, session_headers = init_session(http)
        if not cookies:
            logging.error("Failed to initialize session. Exiting...")
            return None, None
    if session_headers is None:
        session_headers = {}
    login_response = login(http, config.get('username'), config.get('password'), cookies)
    set_cookie_headers = login_response.headers.get_all('Set-Cookie') if hasattr(login_response.headers, 'get_all') else login_response.headers.get('Set-Cookie', '').split(',') if login_response.headers.get('Set-Cookie') else []
    for set_cookie in set_cookie_headers:
        if set_cookie.strip():
            cookies.load(set_cookie)
    save_cookies(cookies)
    try:
        login_response_json = login_response.json()
        login_success = login_response_json.get('succeeded')
        if login_response_json.get('status') == 'need_2fa':
            logging.info("2FA required. Performing 2FA login.")
            totp_code = totp(config.get('totp_secret'))
            logging.info(f"CODE: {totp_code}")
            login2fa_response = login2fa(http, totp_code, cookies)
            set_cookie2_headers = login2fa_response.headers.get_all('Set-Cookie') if hasattr(login2fa_response.headers, 'get_all') else login2fa_response.headers.get('Set-Cookie', '').split(',') if login2fa_response.headers.get('Set-Cookie') else []
            for set_cookie2 in set_cookie2_headers:
                if set_cookie2.strip():
                    cookies.load(set_cookie2)
            save_cookies(cookies)
            login2fa_response_json = login2fa_response.json()
            login_success = login2fa_response_json.get('succeeded')
        else:
            set_cookie = login_response.headers.get('Set-Cookie')
            if set_cookie:
                cookies.load(set_cookie)
    except json.JSONDecodeError:
        logging.error(f"Login response is not in JSON format. Status code: {login_response.status}, Response text: {login_response.body.decode()}")
        return None, None
   
    if 'hoverauth' not in cookies.keys():
        logging.error("Hover authentication cookie not found. Login failed.")
        return None, None
    return cookies, session_headers

def get_domains(http, cookies):
    """
    Retrieves the domains for the account using urllib3 and logs details.
    """
    if "hoverauth" not in cookies.keys():
        logging.error("Hover authentication cookie not found. Running login...")
        if not doLogin(http, cookies):
            logging.error("Login failed. Exiting...")
            exit(1)
    headers = {"Cookie": "; ".join([f"{k}={v.value}" for k, v in cookies.items()]), "user-agent": user_agent}
    filter_allowed_headers(headers)
    url = DOMAIN_CHECK_URL
    response = http.request("GET", url, headers=headers)
    if response.status == 200:
        try:
            domains = json.loads(response.data)
            for domain in domains.get('domains', []):
                print(f"Domain: {domain['name']}, DNSID: {domain['id']}\n")
        except Exception as ex:
            logging.error(f"Failed to parse domains: {ex}")
            exit(4)
    else:
        logging.error(f"Failed to retrieve domains. Status code: {response.status}, Response text: {response.data}")
        exit(4)
# --- Refactored HoverSession class ---
class HoverSession:
    def __init__(self, config, http):
        self.config = config
        self.http = http
        self.cookies = None
        self.session_headers = {}
        self.user_agent = config.get('userAgent', 'Chromium')

    def load_cookies(self):
        if os.path.isfile(COOKIES_FILE):
            with open(COOKIES_FILE, 'r') as file:
                data = json.load(file)
            cookies_dict = data.get('cookies', {})
            expires_dict = data.get('expires', {})
            cookie = SimpleCookie()
            for key, value in cookies_dict.items():
                cookie[key] = value
                if key in expires_dict:
                    cookie[key]['expires'] = expires_dict[key]
            now = datetime.datetime.now(datetime.UTC)
            for key, morsel in cookie.items():
                expires = morsel['expires']
                if expires:
                    try:
                        expires_dt = datetime.datetime.strptime(expires, '%a, %d-%b-%Y %H:%M:%S GMT')
                        if expires_dt < now:
                            logging.info(f"Cookie {key} expired at {expires_dt}, will not use cached cookies.")
                            return None
                    except Exception:
                        continue
            logging.info(f"Loaded cookies from {COOKIES_FILE}")
            return cookie
        return None

    def save_cookies(self):
        cookies_dict = {key: morsel.value for key, morsel in self.cookies.items()}
        expires_dict = {key: morsel['expires'] for key, morsel in self.cookies.items() if morsel['expires']}
        with open(COOKIES_FILE, 'w') as file:
            json.dump({'cookies': cookies_dict, 'expires': expires_dict}, file)
        logging.info(f"Cookies saved to {COOKIES_FILE}")

    def init_session(self):
        response = self.http.request("GET", SIGIN_URL)
        logging.info(f"Init session response status code: {response.status}")
        if response.status != 200:
            logging.error(f"Error initializing session: {response.status}")
            exit(1)
        if 'set-cookie' not in response.headers.keys():
            logging.error("No Set-Cookie header found in response.")
            return None, None
        self.session_headers = {k: v for k, v in response.headers.items() if k.lower() not in ['set-cookie', 'cookie']}
        self.cookies = SimpleCookie(response.headers['Set-Cookie'])
        return self.cookies, self.session_headers

    def login(self):
        login_payload = {
            "username": self.config.get('username'),
            "password": self.config.get('password'),
            "remember": "true",
            "token": None
        }
        cookie_header = "; ".join([f"{k}={v.value}" for k, v in self.cookies.items()])
        headers = dict(self.session_headers)
        headers["user-agent"] = self.user_agent
        body = json.dumps(login_payload).encode('utf-8')
        response = self.http.request("POST", AUTH1URL, body=body, headers=headers)
        logging.debug(f"Login URL: {AUTH1URL}")
        logging.debug(f"Login Headers: {headers}")
        logging.debug(f"Payload: {body}")
        logging.info(f"Login response status code: {response.status}")
        logging.debug(f"Cookie: {self.cookies}")
        self._update_cookies_from_response(response)
        return response

    def login2fa(self, totp_code):
        login_payload = {"code": totp_code}
        headers = dict(self.session_headers)
        headers["user-agent"] = self.user_agent
        body = json.dumps(login_payload).encode('utf-8')
        response = self.http.request("POST", AUTH2URL, body=body, headers=headers)
        logging.info(f"Login 2FA response status code: {response.status}")
        logging.debug(f"Login 2FA response content: {response.data}")
        logging.debug(f"Cookies: {self.cookies}")
        self._update_cookies_from_response(response)
        return response

    def update_dns_record(self, dnsid, ipaddress, domain_name="default_domain"):
        payload = {
            "domain": {
                "id": f"domain-{domain_name}",
                "dns_records": [
                    {"id": f"{dnsid}"}
                ]
            },
            "fields": {"content": ipaddress}
        }
        encoded_data = json.dumps(payload).encode('utf-8')
        cookie_header = "; ".join([f"{k}={v.value}" for k, v in self.cookies.items()])
        headers = dict(self.session_headers)
        headers["user-agent"] = self.user_agent
        response = self.http.request("PUT", DNS_UPDATE_URL, body=encoded_data, headers=headers)
        logging.debug(f"DNS URL: {DNS_UPDATE_URL}")
        logging.info(f"DNS update response status code: {response.status}")
        logging.debug(f"DNS update response content: {response.data}")
        self._update_cookies_from_response(response)
        return response

    def _update_cookies_from_response(self, response):
        set_cookie_headers = response.headers.get_all('Set-Cookie') if hasattr(response.headers, 'get_all') else response.headers.get('Set-Cookie', '').split(',') if response.headers.get('Set-Cookie') else []
        for set_cookie in set_cookie_headers:
            if set_cookie.strip():
                self.cookies.load(set_cookie)
        self.save_cookies()

    def cookies_valid(self):
        headers = {"Cookie": "; ".join([f"{k}={v.value}" for k, v in self.cookies.items()]), "user-agent": self.user_agent}
        response = self.http.request("GET", DOMAIN_CHECK_URL, headers=headers)
        if response.status == 200:
            logging.info("Cookies are valid.")
            return True
        else:
            logging.info("Cookies are invalid.")
        return False

    def get_dns_entries(self):
        headers = {"Cookie": "; ".join([f"{k}={v.value}" for k, v in self.cookies.items()]), "user-agent": self.user_agent}
        url = DOMAIN_CHECK_URL
        response = self.http.request("GET", url, headers=headers)
        if response.status == 200:
            try:
                dns_entries = json.loads(response.data)
                for entry in dns_entries.get('domains', []):
                    logging.info('================')
                    logging.info(f"Domain: {entry['name']}, DNSID: {entry['id']}")
                    sub_url = f"https://www.hover.com/api/control_panel/domains/{entry['name']}"
                    sub_response = self.http.request("GET", sub_url, headers=headers)
                    if sub_response.status == 200:
                        logging.info("Subdomains:")
                        subdomains = json.loads(sub_response.data)
                        for e in subdomains['domain']['dns']:
                            logging.info(f"Domain: {e['name']}, DNSID: {e['id']}")
                    else:
                        logging.info(f"No subdomains found for {sub_url}")
            except Exception as ex:
                logging.error(f"Failed to parse DNS entries: {ex}")
                exit(4)
        else:
            logging.error(f"Failed to retrieve DNS entries. Status code: {response.status}, Response text: {response.data}")
            exit(4)

    def get_domains(self):
        headers = {"Cookie": "; ".join([f"{k}={v.value}" for k, v in self.cookies.items()]), "user-agent": self.user_agent}
        url = DOMAIN_CHECK_URL
        response = self.http.request("GET", url, headers=headers)
        if response.status == 200:
            try:
                domains = json.loads(response.data)
                for domain in domains.get('domains', []):
                    print(f"Domain: {domain['domain_name']}, DNSID: {domain['id']}")
            except Exception as ex:
                logging.error(f"Failed to parse domains: {ex}")
                exit(4)
        else:
            logging.error(f"Failed to retrieve domains. Status code: {response.status}, Response text: {response.data}")
            exit(4)

class HoverUpdater:
    def __init__(self, config, http, logger=logging, ip_file=IP_FILE, cookies_file=COOKIES_FILE):
        self.config = config
        self.http = http
        self.logger = logger
        self.ip_file = ip_file
        self.cookies_file = cookies_file
        self.session_headers = {}
        self.user_agent = config.get('userAgent', 'Chromium')

    def get_external_ip(self):
        response = self.http.request("GET", "https://api.ipify.org")
        if response.status != 200:
            raise RuntimeError(f"Error retrieving external IP: {response.status}")
        return response.data.decode('utf-8')

    def get_dns_ip(self, domain):
        try:
            return socket.gethostbyname(domain)
        except Exception as e:
            self.logger.error(f"DNS lookup failed for {domain}: {e}")
            return None

    def load_saved_ip(self):
        if os.path.isfile(self.ip_file):
            with open(self.ip_file, 'r') as file:
                return file.read().strip()
        return ""

    def save_ip(self, ipaddress):
        with open(self.ip_file, 'w') as file:
            file.write(ipaddress)

    def should_update(self, ipaddress, srcdomain):
        saved_ip = self.load_saved_ip()
        dns_ip = self.get_dns_ip(srcdomain) if srcdomain else None
        external_ip=self.get_external_ip()
        self.logger.info(f"Saved IP: {saved_ip}, Discovered IP: {ipaddress}, DNS IP: {dns_ip}, External IP: {external_ip}")
        if dns_ip == saved_ip and saved_ip==external_ip:
            return False, "DNS IP matches saved IP. No update needed."
        return True, "Discovered IP does not match DNS lookup. Updating..."

    def run_once(self, args, cookies, session_headers):
        config = self.config
        ipaddress = config.get('ipaddress')
        srcdomain = config.get('srcdomain')
        discoverip = config.get('discoverip')
        dnsid = config.get('dnsid')
        username = config.get('username')
        password = config.get('password')
        totp_secret = config.get('totp_secret')
        domain_name = config.get('nakedDomain', 'default_domain')
        # Discover IP address if required
        if discoverip == "true":
            ipaddress = self.get_external_ip()
            self.logger.info(f"IP DISCOVERED: {ipaddress}")
        elif srcdomain:
            ipaddress = self.get_dns_ip(srcdomain)
            self.logger.info(f"SOURCE DOMAIN: {srcdomain}")
            self.logger.info(f"IP: {ipaddress}")
        # Check if update is needed
        should_update, msg = self.should_update(ipaddress, srcdomain)
        self.logger.info(msg)
        if not should_update:
            return False
        # Check for required configuration values
        if not dnsid and not getattr(args, 'getDNSID', False):
            raise ValueError("Missing DNS_ID.")
        if not ipaddress and not getattr(args, 'getDNSID', False):
            raise ValueError("Missing IP ADDRESS.")
        if not username:
            raise ValueError("Missing USERNAME.")
        if not password:
            raise ValueError("Missing PASSWORD.")
        if not totp_secret:
            raise ValueError("Missing TOTP_SECRET.")
        if not domain_name:
            raise ValueError("Missing DOMAIN_NAME.")
        # Generate TOTP code
        totp_code = totp(totp_secret)
        # Perform login and update cookies
        cookies,session_headers = doLogin(self.http, cookies)
        if not cookies:
            self.logger.error("Login failed or cookies not initialized.")
            return False
        # Ensure session_headers is a dict
        if session_headers is None:
            session_headers = {}
        # Update DNS record
        update_response = update_dns_record(self.http, dnsid, ipaddress, cookies, session_headers, domain_name=domain_name)
        try:
            update_response_json = update_response.json()
            update_success = update_response_json.get('succeeded')
        except json.JSONDecodeError:
            self.logger.error(f"Update response is not in JSON format. Status code: {update_response.status}, Response text: {update_response.data.decode()}")
            return False
        self.logger.info(f"Update response: {update_response_json}")
        if not update_success:
            self.logger.error("Setting failure!")
            return False
        else:
            self.logger.info("Setting success!")
            self.save_ip(ipaddress)
            return True

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Hover DNS Update Script')
    parser.add_argument('--loglevel', default='INFO', help='Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default is INFO. Overrides config.json log level.')
    parser.add_argument('--mitm', action='store_true', help='Enable mitmproxy for HTTP/HTTPS requests')
    parser.add_argument('--nocerts', action='store_true', help='Disable certificate verification for mitmproxy')
    parser.add_argument('--getDNSID', '--getdnsid', action='store_true', help='Get DNS IDs for all domains in the account')
    parser.add_argument('--interval', type=int, help='Run interval in seconds. Overrides config value runInterval.')
    parser.add_argument('--getDomains', '--getdomains', action='store_true', help='Get all domains in the account')
    parser.add_argument('--config', default='config.json', help='Path to configuration file (default: config.json)')
    args = parser.parse_args()
    getdnsid = getattr(args, 'getDNSID', False)
    getdomains = getattr(args, 'getDomains', False)

    global CONFIG_FILE
    CONFIG_FILE = args.config

    if not os.path.exists(IP_FILE):
        logging.info(f"IP file found: {IP_FILE}")
        logging.info("Creating IP file...")
        with open(IP_FILE, 'w') as file:
            file.write('')
# Load configuration
    global config
    config = {}
    if os.path.isfile(CONFIG_FILE):
        config = load_config(CONFIG_FILE)
        logging.info(f"Using configuration from {CONFIG_FILE}")
    else:
        logging.error(f"Configuration file {CONFIG_FILE} not found. Exiting...")
        exit(1)

    # Extract configuration values
    dnsid = config.get('dnsid')
    username = config.get('username')
    password = config.get('password')
    discoverip = config.get('discoverip')
    srcdomain = config.get('srcdomain')
    ipaddress = config.get('ipaddress')
    totp_secret = config.get('totp_secret')
    config_loglevel = config.get('loglevel', 'INFO').upper()
    logRetentionMaxDays = config.get('logRetentionMaxDays', 7)
    domain_name = config.get('nakedDomain', 'default_domain')
    global user_agent
    user_agent = config.get('userAgent', 'Chromium')
    global session_headers
    session_headers = {}
    # Set log level from command line or config
    loglevel_str = args.loglevel.upper() if args.loglevel else config_loglevel
    valid_levels = {'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NONE'}
    if loglevel_str == 'NONE':
        logging.info("Log level set to NONE. All logging is disabled.")
        logging.disable(logging.CRITICAL)
    else:
        if loglevel_str not in valid_levels:
            logging.warning(f"Invalid loglevel '{args.loglevel}', defaulting to INFO.")
            loglevel_str = 'INFO'
        loglevel = getattr(logging, loglevel_str, logging.INFO)
        logging.getLogger().setLevel(loglevel)
        console.setLevel(loglevel)
        logging.info(f"Log level set to {logging.getLevelName(loglevel)}")
        if loglevel == logging.DEBUG:
            logging.getLogger('urllib3').setLevel(logging.DEBUG)

    # Remove per-endpoint logs at startup
    remove_endpoint_logs()
    
    if args.mitm and not args.nocerts:
        if platform.system() == 'Windows':
            # Use the mitmproxy CA cert path for Windows
            ca_certs_path = os.path.expandvars(r"%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.pem")

        elif platform.system()== 'Linux':
            # Use the mitmproxy CA cert path for Linux
            ca_certs_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
            
        logging.info(f"Using mitmproxy CA cert at: {ca_certs_path}")
        http = urllib3.ProxyManager(
            proxy_url="http://127.0.0.1:8080",
            cert_reqs="CERT_REQUIRED",
            ca_certs=ca_certs_path
        )
    elif args.mitm and args.nocerts:
        http = urllib3.ProxyManager(
            proxy_url="http://127.0.0.1:8080",
            cert_reqs="CERT_NONE"
        )
    else:
        http = urllib3.PoolManager(
            cert_reqs='CERT_REQUIRED',
            ca_certs=certifi.where()
        )
    
    # Determine loglevel: use command line if specified, else config
    loglevel_str = args.loglevel.upper() if args.loglevel else config_loglevel
    valid_levels = {'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NONE'}
    if loglevel_str == 'NONE':
        logging.info("Log level set to NONE. All logging is disabled.")
        logging.disable(logging.CRITICAL)
    else:
        if loglevel_str not in valid_levels:
            logging.warning(f"Invalid loglevel '{args.loglevel}', defaulting to INFO.")
            loglevel_str = 'INFO'
        loglevel = getattr(logging, loglevel_str, logging.INFO)
        logging.getLogger().setLevel(loglevel)
        console.setLevel(loglevel)
        logging.info(f"Log level set to {logging.getLevelName(loglevel)}")
        if loglevel == logging.DEBUG:
            logging.getLogger('urllib3').setLevel(logging.DEBUG)

    if getdnsid:
        logging.info("Getting DNS IDs for all domains in the account...")
        if not doLogin(http):
            logging.error("Login failed. Exiting...")
            exit(1)
        get_dns_entries(http, load_cookies())
        exit(0)
    if getdomains:
        logging.info("Getting all domains in the account...")
        if not doLogin(http):
            logging.error("Login failed. Exiting...")
            exit(1)
        get_domains(http, load_cookies())
        exit(0)
    
    cookies = None
    session_headers = None
    updater = HoverUpdater(config, http, logger=logging, ip_file=IP_FILE, cookies_file=COOKIES_FILE)
    def run_once():
        updater.run_once(args, cookies, session_headers)
    # Determine run interval: use command line if specified, else config
    run_interval = args.interval if args.interval is not None else int(config.get('runInterval', 0)) if 'runInterval' in config else 0

    if run_interval > 0:
        logging.info(f"Running in interval mode: every {run_interval} seconds.")
        while True:
            run_once()
            logging.info(f"Sleeping for {run_interval} seconds before next run.")
            time.sleep(run_interval)
    else:
        logging.info("No interval specified, running once and exiting.")
        run_once()

def remove_headers_case_insensitive(headers, keys_to_remove):
    keys_lower = {k.lower() for k in keys_to_remove}
    to_delete = [k for k in list(headers.keys()) if k.lower() in keys_lower]
    for k in to_delete:
        headers.pop(k, None)
def update_headers_case_insensitive(headers, new_headers):
    for new_key in new_headers:
        to_remove = [k for k in list(headers.keys()) if k.lower() == new_key.lower()]
        for k in to_remove:
            headers.pop(k)
    headers.update(new_headers)

def filter_allowed_headers(headers):
    allowed = {
        'accept',
        'accept-language',
        'content-type',
        'origin',
        'priority',
        'referer',
        'sec-ch-ua',
        'sec-ch-ua-mobile',
        'sec-ch-ua-platform',
        'sec-fetch-dest',
        'sec-fetch-mode',
        'sec-fetch-site',
        'user-agent',
        'uzlc',
        'cookie',
        'host',
        'content-length',
        'x-request-id',
        'x-requested-with',
        'hoverauth'
    }
    to_delete = [k for k in list(headers.keys()) if k.lower() not in allowed]
    for k in to_delete:
        headers.pop(k, None)
if __name__ == "__main__":
    main()

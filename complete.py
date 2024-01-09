from pprint import pprint
from bs4 import BeautifulSoup as bs
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import whois
import threading
from urllib.parse import urljoin
import sys
from docx import Document
from docx2pdf import convert
import webbrowser
import os
import requests
import ssl
import socket
import urllib.parse
from lxml import html

document = Document()
user_agent = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36',
}


def get(websiteToScan):
    return requests.get(websiteToScan, allow_redirects=False, headers=user_agent)




def get_site_title(websiteToScan):
    try:
        response = requests.get(websiteToScan)
        response.raise_for_status()  # Check for errors in the request

        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.text.strip() if soup.title else "Title not found"
        print(f"Site Title: {title}")
    except requests.RequestException as e:
        print(f"Error retrieving site title: {e}")


def view_url_extensions(websiteToscan):
    extensions = websiteToscan.split(".")[-1]
    print("URL Extensions:", extensions)


def identify_http_methods(websiteToscan):
    try:
        # Send requests with different HTTP methods
        response_get = requests.get(websiteToscan)
        response_post = requests.post(websiteToscan)
        response_put = requests.put(websiteToscan)
        response_delete = requests.delete(websiteToscan)

        # Print the allowed methods based on the responses
        allowed_methods = []
        if response_get.status_code == 200:
            allowed_methods.append("GET")
        if response_post.status_code == 200:
            allowed_methods.append("POST")
        if response_put.status_code == 200:
            allowed_methods.append("PUT")
        if response_delete.status_code == 200:
            allowed_methods.append("DELETE")

        print(f"Allowed HTTP Methods: {', '.join(allowed_methods)}")
    except requests.RequestException as e:
        print(f"Error during request: {e}")

def extract_domain(websiteToScan):
    """
    Extracts the domain name from a full URL.
    """
    parsed_url = urlparse(websiteToScan)
    if parsed_url.scheme and parsed_url.netloc:
        return parsed_url.netloc
    else:
        return websiteToScan


def ip_addresses(websiteToScan):
    domain_name = extract_domain(websiteToScan)
    try:
        ais = socket.getaddrinfo(domain_name, 0, 0, 0, 0)
        ip_addresses = list(set(result[-1][0] for result in ais))

        # Concatenate IP addresses into a single string
        ip_addresses_str = ', '.join(ip_addresses)

        print(f"IP Addresses: {ip_addresses_str}")
        return ip_addresses
    except socket.error as e:
        print(f'Error during nslookup: {e}')
        return []

def IP2Location(ip_addresses):
    for ip_address in ip_addresses:
        try:
            adres = f"http://ip-api.com/json/{ip_address}"
            sonuc = requests.get(adres, verify=False).json()

            # Print location information
            print(f"[+]Location information for IP {ip_address}:")
            print("[+]City:", sonuc.get('city'))
            print("[+]Country:", sonuc.get('country'))
            print("[+]Time Zone:", sonuc.get('timezone'))

        except Exception as e:
            print(f"Error: {e}")
            print(f"Unable to get location information for IP {ip_address}")


def open_ports(websiteToScan):
    ports = {
        'http': 80,
        'https': 443,
        'ftp': 21,
        'ftps': 990,
        'ssh': 22,
        'smtp': 25,
        'pop3': 110,
        'imap': 143,
        'dns': 53,
        'mysql': 3306,
        'postgresql': 5432,
        'rdp': 3389,
        'mongodb': 27017
    }

    def ip_addresses(domain_name):
        try:
            ais = socket.getaddrinfo(domain_name, 0, 0, 0, 0)
            ip_addresses = list(set(result[-1][0] for result in ais))
            return ip_addresses  # Return the IP addresses for later use
        except socket.error as e:
            print(f'Error during nslookup: {e}')
            return None

    def port_scanner(ip, scheme):
        if ip is None:
            print("[!] Could not resolve the IP address.")
            return

        open_ports = set()  # Use a set to store unique open ports

        try:
            default_port = ports.get(scheme, None)
            if default_port:
                open_ports.add(str(default_port))

            for port in ports.values():
                sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sck.settimeout(1)  # Set a timeout for the connection attempt
                result = sck.connect_ex((ip, port))

                if result == 0:
                    open_ports.add(str(port))
                sck.close()

            if open_ports:
                print(f"Open Ports: {', '.join(open_ports)}")
            else:
                print("No open ports found.")

        except socket.error:
            print("Could not connect to host.")
        except KeyboardInterrupt:
            print("User interrupted.")
        except Exception as e:
            print(f"An error occurred: {str(e)}")

    # Main function logic
    parsed_url = urlparse(websiteToScan)
    domain_name = parsed_url.netloc
    scheme = parsed_url.scheme

    ip = ip_addresses(domain_name)

    if ip:
        port_scanner(ip[0], scheme)  # Assuming the first IP address for simplicity


def whois_info(websiteToScan):
    domain_name = extract_domain(websiteToScan)

    try:

        whois_info = whois.whois(domain_name)

        # Remove 'status' from the output
        whois_info.pop('status', None)

        # print("\nWhois Information:")
        for key, value in whois_info.items():
            if isinstance(value, list):
                print(f"  {key.capitalize()}: {', '.join(map(str, value))}")
            else:
                print(f"  {key.capitalize()}: {value}")

    except whois.parser.PywhoisError as e:
        print(f'Error during whois lookup: {e}')

def get_TLS(websiteToScan):
    try:
        with socket.create_connection((websiteToScan, 443), timeout=5) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=websiteToScan) as ssock:
                # Use ssock.cipher() to get the cipher suite, which includes the protocol
                cipher_suite = ssock.cipher()
                return cipher_suite[1], None
    except (socket.error, ssl.SSLError, TimeoutError) as e:
        return None, f"Error: {e}"


def certificate_information(extract_domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((extract_domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=extract_domain) as server:
                certificate = server.getpeercert()

                print("[+]Certificate Serial Number:", certificate.get('serialNumber'))
                print("[+]Certificate SSL Version:", certificate.get('version'))
                # print("[+]Certificate:", certificate)

    except Exception as e:
        print(f"Error: {e}")
        print("Please check the domain and try again.")


def check_protocol(websiteToScan):

    # Extract the hostname from the URL
    parsed_url = urllib.parse.urlparse(websiteToScan)
    hostname = parsed_url.hostname

    # Get the SSL/TLS protocol
    protocol, _ = get_TLS(hostname)

    if protocol:
        print(f"The SSL/TLS protocol for {websiteToScan} is: {protocol}")
    else:
        print(f"Failed to retrieve the SSL/TLS protocol for {websiteToScan}")


def check_http_headers(websiteToScan):
    # print("Checking HTTP headers for:", websiteToScan)

    try:
        onlineCheck = get(websiteToScan)
    except requests.exceptions.ConnectionError as ex:
        print("[!]" + websiteToScan + " appears to be offline.")
        return

    if onlineCheck.status_code == 200 or onlineCheck.status_code == 301 or onlineCheck.status_code == 302:
        print(" |  " + websiteToScan + " appears to be online.")
        # print()
        # print("Attempting to get the HTTP headers...")

        # Pretty print the headers - courtesy of Jimmy
        for header in onlineCheck.headers:
            try:
                print(" | " + header + " : " + onlineCheck.headers[header])
            except Exception as ex:
                print("[!] Error: " + str(ex))
    else:
        print(
            "[!] " + websiteToScan + " appears to be online but returned a " + str(onlineCheck.status_code) + "error.")
        print()


def crawl_and_check_sqli(websiteToScan, max_depth=3, visited_links=set()):
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Win64; x64) AppleWebKit/537.36 Chrome/87.0.4280.88"

    # List of 20 SQL injection payloads to test
    payloads = [
        "'",
        "\"",
        ";",
        "--",
        " OR 1=1",
        "' OR 'a'='a",
        "\" OR \"a\"=\"a",
        "' OR 'a'='a' --",
        "\" OR \"a\"=\"a\" --",
        "' OR 1=1 --",
        "\" OR 1=1 --",
        "'; DROP TABLE users; --",
        "\"; DROP TABLE users; --",
        "' UNION ALL SELECT NULL, CONCAT('admin:', user, ':', password), NULL FROM users --",
        "\" UNION ALL SELECT NULL, CONCAT('admin:', user, ':', password), NULL FROM users --",
        "'; EXEC xp_cmdshell('dir'); --",
        "\"; EXEC xp_cmdshell('dir'); --",
        "' OR EXISTS(SELECT * FROM users WHERE name='admin') --",
        "\" OR EXISTS(SELECT * FROM users WHERE name='admin') --",
        "' UNION ALL SELECT table_name, column_name FROM information_schema.columns --",
        "\" UNION ALL SELECT table_name, column_name FROM information_schema.columns --"
    ]

    def vulnerable(response):
        # Check if response content indicates a SQL injection vulnerability
        for payload in payloads:
            if payload in response.text.lower():
                return True
        return False

    if max_depth <= 0 or websiteToScan in visited_links:
        return
    visited_links.add(websiteToScan)

    try:
        response = s.get(websiteToScan)
        response.raise_for_status()  # Raise exception for non-2xx responses

        # Check for SQL injection vulnerabilities on the current page
        if vulnerable(response):
            print("SQLi vulnerability found:", websiteToScan)

        # Extract and crawl URLs on the current page
        soup = BeautifulSoup(response.content, "html.parser")
        for link in soup.find_all("a", href=True):
            url = urljoin(websiteToScan, link["href"])

            # Recursively crawl and check SQLi on the discovered URL with reduced depth
            crawl_and_check_sqli(url, max_depth - 1, visited_links)
    except requests.exceptions.RequestException:
        pass  # Ignore errors during crawling


def scan_xss(websiteToScan):
    def get_all_forms(websiteToScan):
        soup = bs(requests.get(websiteToScan).content, "html.parser")
        return soup.find_all("form")

    def get_form_details(form):
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(form_details, websiteToScan, value):
        websiteToScan = urljoin(websiteToScan, form_details["action"])
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value

        if form_details["method"] == "post":
            return requests.post(websiteToScan, data=data)
        else:
            return requests.get(websiteToScan, params=data)

    print(f"[+] Scanning for XSS vulnerabilities on {websiteToScan}...")

    forms = get_all_forms(websiteToScan)
    print(f"[+] Detected {len(forms)} forms on {websiteToScan}.")

    # Corrected XSS payloads
    js_payloads = [
        "<script>alert('hi')</script>",
        "<img src=x onerror=alert('hi')>",
        "<svg/onload=alert('hi')>",
        "'; alert('hi'); //",
        "<iframe src='javascript:alert(`hi`)'></iframe>",
        " <script>alert(document.head.innerHTML.substr(146,20));</script>",

    ]

    is_vulnerable = False

    for form in forms:
        form_details = get_form_details(form)
        for js_script in js_payloads:
            content = submit_form(form_details, websiteToScan, js_script).content.decode()
            if js_script in content:
                print("[+] XSS Detected on {websiteToScan}")
                print("[*] Form details:")
                pprint(form_details)
                is_vulnerable = True

    if is_vulnerable:
        print("[+] XSS Detected!")
    else:
        print("[+] XSS Not Detected.")

    return is_vulnerable


def check_outdated_dependencies(websiteToScan):
    try:
        # Fetch the webpage
        response = requests.get(websiteToScan)
        response.raise_for_status()  # Check for errors in the request

        # Parse the HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract script tags from the webpage
        script_tags = soup.find_all('script')

        # Check for mentions of library versions
        outdated_libraries = []

        for script_tag in script_tags:
            script_content = script_tag.get_text()
            if "version" in script_content.lower():
                outdated_libraries.append(script_content)

        if outdated_libraries:
            print("Potential outdated dependencies found on the website:")
            for library in outdated_libraries:
                print(library)
        else:
            print("No potential outdated dependencies found on the website.")

    except requests.exceptions.RequestException as e:
        print("Error:", e)

def check_x_frame_options_headers(websiteToscan):
    try:
        response = requests.get(websiteToscan)
        x_frame_options_header = response.headers.get('X-Frame-Options', '')

        if x_frame_options_header:
            print(f"'X-Frame-Options' header is present: {x_frame_options_header}")
        else:
            print("No 'X-Frame-Options' header found.")
    except requests.RequestException as e:
        print(f"Error during request: {e}")


def check_vulnerability(websiteToscan):
    try:
        response = requests.get(websiteToscan)
        if "X-Frame-Options" not in response.headers:
            return True
        else:
            return False
    except requests.RequestException as e:
        print(f"Error during request: {e}")
        return False


def create_poc(url):
    if check_vulnerability(websiteToScan):

        print(" [+] Website is vulnerable to Clickjacking!")
    else:
        print(" [-] Website is not vulnerable to Clickjacking.")

    print("[*] Clickjacking URL:", url)
    print("")


def directory_bruteforce(websiteToScan, threads, extensions=None):
    parsed_url = urlparse(websiteToScan)
    target = "{}://{}".format(parsed_url.scheme, parsed_url.netloc)

    common_directories = [
        "admin", "administrator", "login", "wp-admin", "wp-content", "wp-includes",
        "uploads", "images", "config", "css", "js", "fonts", "includes", "media",
        "backup", "temp", "users", "data", "scripts", "cgi-bin", "lib", "public",
        "private", "index", "test", "tmp", "dev", "sys", "tools", "web", "secure",
        ".git", ".svn"
    ]

    ext = extensions if extensions else [".php", ".bak", ".swp", ".old", ".zip", ".tar", ".tar.gz", ".sql", ".log",
                                         ".xml"]
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"

    def brut_dir():
        while common_directories:
            try_this = common_directories.pop(0)
            try_list = []

            if "." not in try_this:
                try_list.append("/{}/".format(try_this))
            else:
                try_list.append("/{}".format(try_this))

            if extensions:
                for extension in extensions:
                    try_list.append("/{}{}".format(try_this, extension))

            for brute in try_list:
                full_url = "{}{}".format(target, brute)

                try:
                    headers = {"User-Agent": user_agent}
                    response = requests.post(full_url, headers=headers)

                    if response.status_code == 200:
                        print("[{}] ==> {} - Status Code: {}".format(response.status_code, full_url,
                                                                     response.status_code))

                except requests.RequestException as e:
                    print("Error: {}".format(e))

    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=brut_dir)
        t.start()
        threads_list.append(t)

    for t in threads_list:
        t.join()



def checkFileUploadFunctionality(websiteToScan):
    try:
        # Remove the verify = False parameter to enable SSL certificate verification
        page = requests.get(websiteToScan)
        tree = html.fromstring(page.content)
        inputs = tree.xpath('//input[@name]')

        # Print input names and file upload information
        print("[+]Input names:")
        for input_element in inputs:
            startPoint = int(str(input_element).find("'")) + 1
            stopPoint = int(str(input_element).find("'", startPoint))
            input_name = str(input_element)[startPoint:stopPoint]
            print(input_name)

            # Check for file upload input
            if "type='file'" in str(input_element):
                print("[+]File Upload Function available")

    except Exception as e:
        print(f"Error: {e}")
        print("Please check the URL and try again.")


def cms_detect(websiteToScan):
    print("***********************************")
    print("[+] WORDPRESS SCAN")
    print("***********************************")

    wpLoginCheck = requests.get(websiteToScan + '/wp-login.php', headers=user_agent)
    if wpLoginCheck.status_code == 200 and "user_login" in wpLoginCheck.text and "404" not in wpLoginCheck.text:
        print("[!] Detected: WordPress WP-Login page: " + websiteToScan + '/wp-login.php')
    else:
        print(" |  Not Detected: WordPress WP-Login page: " + websiteToScan + '/wp-login.php')

    # Use requests.get allowing redirects otherwise will always fail
    wpAdminCheck = requests.get(websiteToScan + '/wp-admin', headers=user_agent)
    if wpAdminCheck.status_code == 200 and "user_login" in wpAdminCheck.text and "404" not in wpLoginCheck.text:
        print("[!] Detected: WordPress WP-Admin page: " + websiteToScan + '/wp-admin')
    else:
        print(" |  Not Detected: WordPress WP-Admin page: " + websiteToScan + '/wp-admin')

    wpAdminUpgradeCheck = get(websiteToScan + '/wp-admin/upgrade.php')
    if wpAdminUpgradeCheck.status_code == 200 and "404" not in wpAdminUpgradeCheck.text:
        print("[!] Detected: WordPress WP-Admin/upgrade.php page: " + websiteToScan + '/wp-admin/upgrade.php')
    else:
        print(" |  Not Detected: WordPress WP-Admin/upgrade.php page: " + websiteToScan + '/wp-admin/upgrade.php')

    wpAdminReadMeCheck = get(websiteToScan + '/readme.html')
    if wpAdminReadMeCheck.status_code == 200 and "404" not in wpAdminReadMeCheck.text:
        print("[!] Detected: WordPress Readme.html: " + websiteToScan + '/readme.html')
    else:
        print(" |  Not Detected: WordPress Readme.html: " + websiteToScan + '/readme.html')

    wpLinksCheck = get(websiteToScan)
    if 'wp-' in wpLinksCheck.text:
        print("[!] Detected: WordPress wp- style links detected on index")
    else:
        print(" |  Not Detected: WordPress wp- style links detected on index")

    print("")
    print("")
    print("***********************************")
    print("[+] JOOMLA SCAN")
    print("***********************************")
    joomlaAdminCheck = get(websiteToScan + '/administrator/')
    if joomlaAdminCheck.status_code == 200 and "mod-login-username" in joomlaAdminCheck.text and "404" not in joomlaAdminCheck.text:
        print("[!] Detected: Potential Joomla administrator login page: " + websiteToScan + '/administrator/')
    else:
        print(" |  Not Detected: Joomla administrator login page: " + websiteToScan + '/administrator/')

    joomlaReadMeCheck = get(websiteToScan + '/readme.txt')
    if joomlaReadMeCheck.status_code == 200 and "joomla" in joomlaReadMeCheck.text and "404" not in joomlaReadMeCheck.text:
        print("[!] Detected: Joomla Readme.txt: " + websiteToScan + '/readme.txt')
    else:
        print(" |  Not Detected: Joomla Readme.txt: " + websiteToScan + '/readme.txt')

    joomlaTagCheck = get(websiteToScan)
    if joomlaTagCheck.status_code == 200 and 'name="generator" content="Joomla' in joomlaTagCheck.text and "404" not in joomlaTagCheck.text:
        print("[!] Detected: Generated by Joomla tag on index")
    else:
        print(" |  Not Detected: Generated by Joomla tag on index")

    joomlaStringCheck = get(websiteToScan)
    if joomlaStringCheck.status_code == 200 and "joomla" in joomlaStringCheck.text and "404" not in joomlaStringCheck.text:
        print("[!] Detected: Joomla strings on index")
    else:
        print(" |  Not Detected: Joomla strings on index")

    joomlaDirCheck = get(websiteToScan + '/media/com_joomlaupdate/')
    if joomlaDirCheck.status_code == 403 and "404" not in joomlaDirCheck.text:
        print("[!] Detected: Joomla media/com_joomlaupdate directories: " + websiteToScan + '/media/com_joomlaupdate/')
    else:
        print(
            " |  Not Detected: Joomla media/com_joomlaupdate directories: " + websiteToScan + '/media/com_joomlaupdate/')
    print("")
    print("")
    print("***********************************")
    print("[+] MAGNETO SCAN")
    print("***********************************")

    magentoAdminCheck = get(websiteToScan + '/index.php/admin/')
    if magentoAdminCheck.status_code == 200 and 'login' in magentoAdminCheck.text and "404" not in magentoAdminCheck.text:
        print("[!] Detected: Potential Magento administrator login page: " + websiteToScan + '/index.php/admin')
    else:
        print(" |  Not Detected: Magento administrator login page: " + websiteToScan + '/index.php/admin')

    magentoRelNotesCheck = get(websiteToScan + '/RELEASE_NOTES.txt')
    if magentoRelNotesCheck.status_code == 200 and 'magento' in magentoRelNotesCheck.text:
        print("[!] Detected: Magento Release_Notes.txt: " + websiteToScan + '/RELEASE_NOTES.txt')
    else:
        print(" |  Not Detected: Magento Release_Notes.txt: " + websiteToScan + '/RELEASE_NOTES.txt')

    magentoCookieCheck = get(websiteToScan + '/js/mage/cookies.js')
    if magentoCookieCheck.status_code == 200 and "404" not in magentoCookieCheck.text:
        print("[!] Detected: Magento cookies.js: " + websiteToScan + '/js/mage/cookies.js')
    else:
        print(" |  Not Detected: Magento cookies.js: " + websiteToScan + '/js/mage/cookies.js')

    magStringCheck = get(websiteToScan + '/index.php')
    if magStringCheck.status_code == 200 and '/mage/' in magStringCheck.text or 'magento' in magStringCheck.text:
        print("[!] Detected: Magento strings on index")
    else:
        print(" |  Not Detected: Magento strings on index")

    magentoStylesCSSCheck = get(websiteToScan + '/skin/frontend/default/default/css/styles.css')
    if magentoStylesCSSCheck.status_code == 200 and "404" not in magentoStylesCSSCheck.text:
        print("[!] Detected: Magento styles.css: " + websiteToScan + '/skin/frontend/default/default/css/styles.css')
    else:
        print(
            " |  Not Detected: Magento styles.css: " + websiteToScan + '/skin/frontend/default/default/css/styles.css')
    mag404Check = get(websiteToScan + '/errors/design.xml')
    if mag404Check.status_code == 200 and "magento" in mag404Check.text:
        print("[!] Detected: Magento error page design.xml: " + websiteToScan + '/errors/design.xml')
    else:
        print(" |  Not Detected: Magento error page design.xml: " + websiteToScan + '/errors/design.xml')

    print("")
    print("")
    print("***********************************")
    print("[+] DRUPAL SCAN")
    print("***********************************")
    drupalReadMeCheck = get(websiteToScan + '/readme.txt')
    if drupalReadMeCheck.status_code == 200 and 'drupal' in drupalReadMeCheck.text and '404' not in drupalReadMeCheck.text:
        print("[!] Detected: Drupal Readme.txt: " + websiteToScan + '/readme.txt')
    else:
        print(" |  Not Detected: Drupal Readme.txt: " + websiteToScan + '/readme.txt')

    drupalTagCheck = get(websiteToScan)
    if drupalTagCheck.status_code == 200 and 'name="Generator" content="Drupal' in drupalTagCheck.text:
        print("[!] Detected: Generated by Drupal tag on index")
    else:
        print(" |  Not Detected: Generated by Drupal tag on index")

    drupalCopyrightCheck = get(websiteToScan + '/core/COPYRIGHT.txt')
    if drupalCopyrightCheck.status_code == 200 and 'Drupal' in drupalCopyrightCheck.text and '404' not in drupalCopyrightCheck.text:
        print("[!] Detected: Drupal COPYRIGHT.txt: " + websiteToScan + '/core/COPYRIGHT.txt')
    else:
        print(" |  Not Detected: Drupal COPYRIGHT.txt: " + websiteToScan + '/core/COPYRIGHT.txt')

    drupalReadme2Check = get(websiteToScan + '/modules/README.txt')
    if drupalReadme2Check.status_code == 200 and 'drupal' in drupalReadme2Check.text and '404' not in drupalReadme2Check.text:
        print("[!] Detected: Drupal modules/README.txt: " + websiteToScan + '/modules/README.txt')
    else:
        print(" |  Not Detected: Drupal modules/README.txt: " + websiteToScan + '/modules/README.txt')

    drupalStringCheck = get(websiteToScan)
    if drupalStringCheck.status_code == 200 and 'drupal' in drupalStringCheck.text:
        print("[!] Detected: Drupal strings on index")
    else:
        print(" |  Not Detected: Drupal strings on index")

    print("")
    print("")
    print("***********************************")
    print("[+] PHP MY ADMIN SCAN")
    print("***********************************")

    phpMyAdminCheck = get(websiteToScan)
    if phpMyAdminCheck.status_code == 200 and 'phpmyadmin' in phpMyAdminCheck.text:
        print("[!] Detected: phpMyAdmin index page")
    else:
        print(" |  Not Detected: phpMyAdmin index page")

    pmaCheck = get(websiteToScan)
    if pmaCheck.status_code == 200 and 'pmahomme' in pmaCheck.text or 'pma_' in pmaCheck.text:
        print("[!] Detected: phpMyAdmin pmahomme and pma_ style links on index page")
    else:
        print(" |  Not Detected: phpMyAdmin pmahomme and pma_ style links on index page")

    phpMyAdminConfigCheck = get(websiteToScan + '/config.inc.php')
    if phpMyAdminConfigCheck.status_code == 200 and '404' not in phpMyAdminConfigCheck.text:
        print("[!] Detected: phpMyAdmin configuration file: " + websiteToScan + '/config.inc.php')
    else:
        print(" |  Not Detected: phpMyAdmin configuration file: " + websiteToScan + '/config.inc.php')


def scan_subdomains(websiteToScan):
    print('----URLs after scanning subdomains----')

    # Extracting the domain from the URL
    parsed_url = urlparse(websiteToScan)
    domain_name = parsed_url.netloc

    # Removing "www" if present at the beginning
    if domain_name.startswith('www.'):
        domain_name = domain_name[4:]

    # Printing the extracted domain
    print(f'The extracted domain is: {domain_name}')

    # Common subdomains
    subdomains = [
        'wordlist', 'mail', 'mail2', 'www', 'ns2', 'ns1', 'blog', 'localhost', 'm', 'ftp',
        'mobile', 'ns3', 'smtp', 'search', 'api', 'dev', 'secure', 'webmail', 'admin', 'img',
        'news', 'sms', 'marketing', 'test', 'video', 'www2', 'media', 'static', 'ads', 'mail2',
        'beta', 'wap', 'blogs', 'download', 'dns1', 'www3', 'origin', 'shop', 'forum', 'chat',
        'www1', 'image', 'new', 'tv', 'dns', 'services', 'music', 'images', 'pay', 'ddrint', 'conc'
    ]

    # Flag to check if any subdomains were found
    subdomains_found = False

    # Scanning subdomains
    for sub_domain in subdomains:
        # Try both HTTP and HTTPS schemes
        for scheme in ['http', 'https']:
            url = f"{scheme}://{sub_domain}.{domain_name}"

            try:
                requests.get(url)
                print(f'[+] {url}')
                subdomains_found = True
            except requests.ConnectionError:
                pass

    # Print message if no subdomains were found
    if not subdomains_found:
        print("No subdomains were found.")

def sitemapxml_available(websiteToscan):
    websiteToscan += "/sitemap.xml"
    try:
        check_file = requests.get(websiteToscan, verify=True)
        check_file.raise_for_status()

        if check_file.status_code == 200:
            print(f"[+] Sitemap.xml is available on {websiteToscan}")
        else:
            print(f"[-] Sitemap.xml isn't available on {websiteToscan}")
    except requests.RequestException as e:
        if "404" in str(e):
            print(f"[-] Sitemap.xml not found on {websiteToscan}")
        else:
            print(f"Error: {e}")
            print(f"[-] Failed to check Sitemap.xml on {websiteToscan}")


def robotstxt_available(websiteToscan):
    websiteToscan += "/robots.txt"
    try:
        file = requests.get(websiteToscan, verify=True)  # Set verify=True to enable SSL/TLS certificate verification
        file.raise_for_status()  # Raise an error for bad responses (4xx and 5xx status codes)

        if file.status_code == 200:
            print("[+]robots.txt available")
            print("robots.txt:", file.content.decode('utf-8'))
        else:
            print("[-]robots.txt isn't available")
    except requests.RequestException as e:
        print(f"Error: {e}")
        print("[-]Failed to check robots.txt")


# Function to create
def redirect_stdout_to_file(file_path):
    sys.stdout = open(file_path, 'w')


def restore_stdout():
    sys.stdout.close()
    sys.stdout = sys.__stdout__


def save_output_to_word(output_file_path, content):
    # Add the content to the Word document
    document.add_picture(r"G://pythonProject//code//FYP//logoimage.jpg", width=Inches(6.0))
    last_paragraph = document.paragraphs[-1]
    last_paragraph.alignment = WD_ALIGN_PARAGRAPH.CENTER
    document.add_paragraph(content)

    # Save the Word document
    document.save(output_file_path)


def convert_word_to_pdf(word_file_path, pdf_file_path):
    convert(word_file_path, pdf_file_path)


if __name__ == "__main__":
    print(r"""

                            *******************************************************************************************
                            *                                                                                         *  
                            *          ███╗   ██╗███████╗████████╗    ███╗   ██╗██╗███╗   ██╗     ██╗ █████╗          *
                            *          ████╗  ██║██╔════╝╚══██╔══╝    ████╗  ██║██║████╗  ██║     ██║██╔══██╗         * 
                            *          ██╔██╗ ██║█████╗     ██║       ██╔██╗ ██║██║██╔██╗ ██║     ██║███████║         *
                            *          ██║╚██╗██║██╔══╝     ██║       ██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║         *         
                            *          ██║ ╚████║███████╗   ██║       ██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║         *
                            *          ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝         *    
                            *                                                                                         *        
                            *******************************************************************************************
        """)

    websiteToScan = input("Enter the URL of the website: ")

    output_docx_path = "output.docx"

    redirect_stdout_to_file(output_docx_path)

    print("***********************************")
    print("[+] BASIC INFORMATION")
    print("***********************************")
    get_site_title(websiteToScan)
    view_url_extensions(websiteToScan)
    ip_addresses(websiteToScan)
    print("")
    ip_addresses_list = ip_addresses(websiteToScan)
    IP2Location(ip_addresses_list)
    open_ports(websiteToScan)
    print("")
    print("----HTTPS HEADERS----")
    check_http_headers(websiteToScan)
    print()
    check_protocol(websiteToScan)
    print("")
    print("")

    print("***********************************")
    print("[+] WHOIS INFORMATION")
    print("***********************************")
    whois_info(websiteToScan)
    print("")
    print("")



    print("***********************************")
    print("[+] SQL INJECTION")
    print("***********************************")
    crawl_and_check_sqli(websiteToScan)
    print("")
    print("")


    print("***********************************")
    print("[+] CROSS SITE SCRIPTING")
    print("***********************************")
    scan_xss(websiteToScan)
    print("")
    print("")

    print("***********************************")
    print("[+] CLICK JACKING ")
    print("***********************************")
    check_x_frame_options_headers(websiteToScan)
    create_poc(websiteToScan)
    print("")
    print("")


    print("***********************************")
    print("[+] DIRECTORY BRUTEFORCE")
    print("***********************************")
    directory_bruteforce(websiteToScan, threads=5, extensions=[".php", ".txt", ".html"])
    print("")
    print("")

    print("***********************************")
    print("[+] CHECK SUBDOMAINS ")
    print("***********************************")
    scan_subdomains(websiteToScan)
    print("")
    print("")


    print("***********************************")
    print("[+] SECURITY MISCONFIGURATION ")
    print("***********************************")
    print('----FILE DISCOVERY----')
    sitemapxml_available(websiteToScan)
    robotstxt_available(websiteToScan)
    print("")
    print('----HTTP METHODS----')
    identify_http_methods(websiteToScan)
    print("")
    print('----CHECK TLS ----')
    check_protocol(websiteToScan)
    certificate_information(extract_domain)
    print("")
    print("")

    print("***********************************")
    print("[+]FILE UPLOAD VULNERABILITY")
    print("***********************************")
    checkFileUploadFunctionality(websiteToScan)
    print("")
    print("")

    cms_detect(websiteToScan)
    print("")
    print("")

    print("***********************************")
    print("[+]OUTDATED DEPENDENCIES")
    print("***********************************")
    check_outdated_dependencies(websiteToScan)
    print("")
    print("")

    restore_stdout()

    # Save the output to a Word document
    save_output_to_word(output_docx_path, open(output_docx_path).read())
    print(f"Output saved to {output_docx_path}")
    current_directory = os.path.dirname(os.path.abspath(__file__))
    output_docx_path = os.path.join(current_directory, "output.docx")
    output_pdf_path = os.path.join(current_directory, "output.pdf")

    # Convert the Word document to PDF
    convert_word_to_pdf(output_docx_path, output_pdf_path)

    # print(f"Output Word document saved to {output_docx_path}")
    print(f"Output PDF saved to {output_pdf_path}")
    os.remove(output_docx_path)
    webbrowser.open(output_pdf_path)

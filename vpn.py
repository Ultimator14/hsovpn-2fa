#!/usr/bin/python

import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from urllib.parse import urlparse

import pyotp
import requests

with open("secrets.json", encoding="utf-8") as afile:
    json_data = json.load(afile)

# mandatory values (crash if missing)
CONF_USERNAME = json_data["username"]  # username
CONF_PASSWORD = json_data["password"]  # password
CONF_VPN_URL = json_data["login-url"]  # sso-v2-login url
CONF_SSO_COOKIE_NAME = json_data["sso-cookie-name"]  # name for the sso cookie
# optional values
CONF_TOTP_SECRET = json_data.get("totp")  # totp secret
CONF_DEBUG = json_data.get("debug", False)
CONF_OC_DICT = json_data.get("openconnect")

if CONF_OC_DICT:
    CONF_OC_PREFIX = CONF_OC_DICT["prefix"]
    CONF_OC_SUFFIX = CONF_OC_DICT["suffix"]
    CONF_OC_VPN_DOMAIN = CONF_OC_DICT["vpn-domain"]


base_url = "https://" + urlparse(CONF_VPN_URL).netloc

totp = pyotp.TOTP(CONF_TOTP_SECRET) if CONF_TOTP_SECRET else input("Please enter your 6 digit TOTP password")

s = requests.Session()


def log(msg):
    if CONF_DEBUG:
        print(msg)


def request_with_method(method, url, data):
    # fix relative urls
    if url.startswith("https://"):
        global base_url
        base_url = "https://" + urlparse(url).netloc
    else:
        url = base_url + url

    log(f"Doing request with url {url}")
    if method == "GET":
        if data:
            print("WARNING! Data is not supported for GET request!")

        return s.get(url)

    if method == "POST":
        return s.post(url, data=data)

    print("Unkown requests method!")
    sys.exit(1)


class Form:
    def __init__(self, url="", method=""):
        self.url = url
        self.method = method
        self.input_elements = {}
        self.input_elements_incomplete = {}
        self.input_data = []

    def merge_input_elements(self):
        for elem in self.input_elements_incomplete:
            if self.input_elements_incomplete[elem] is None:
                self.input_elements[elem] = ""
            elif type(self.input_elements_incomplete) is tuple:
                # default to first value in tuple
                self.input_elements[elem] = self.input_elements_incomplete[elem][0]

    def fill_form(self, name, value):
        dict_value = self.input_elements_incomplete.get(name, None)

        if dict_value is None:
            return  # value is not in dict

        if type(dict_value) is tuple:
            # multiple options given
            if value in dict_value:
                log(f"Selecting form value {name}: {value}")
                self.input_elements[name] = value
                del self.input_elements_incomplete[name]
        else:
            # empty value, add
            log(f"Inserting form value {name}: {value}")
            self.input_elements[name] = value
            del self.input_elements_incomplete[name]


class FormMTMLParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.forms = []

        self.current_form = None
        self.in_form = False

        self.in_select = False
        self.select_name = None
        self.select_options = None

    def get_forms(self, page_content):
        self.feed(page_content)
        return self.forms

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        if tag == "form":
            if self.in_form:
                print("WARNING! Nested forms are not supported!!")
                sys.exit(1)
            else:
                self.in_form = True
                self.current_form = Form()

                self.current_form.url = attr_dict.get("action")
                self.current_form.method = attr_dict.get("method", "GET")
        elif tag == "input" and self.in_form:
            ad_name = attr_dict.get("name")
            ad_value = attr_dict.get("value")

            if ad_name is not None and ad_value is not None:
                # hidden form element, add to input_elements
                self.current_form.input_elements[ad_name] = ad_value
            elif ad_name is not None and ad_value is None:
                # user input or no value
                self.current_form.input_elements_incomplete[ad_name] = ""
        elif tag == "select" and self.in_form:
            if self.in_select:
                print("WARNING! Nested selects are not supported")
                sys.exit(1)
            else:
                self.in_select = True
                self.select_name = attr_dict.get("name")
                self.select_options = []

        elif tag == "option" and self.in_form and self.in_select:
            self.select_options.append(attr_dict.get("value"))

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False
            self.forms.append(self.current_form)
            self.current_form = None
        elif tag == "select":
            self.in_select = False
            self.current_form.input_elements_incomplete[self.select_name] = self.select_options
            self.select_name = None
            self.select_options = None

    def handle_data(self, data):
        if self.in_form and data.strip():
            self.current_form.input_data.append(data)


def get_form_data(page_content):
    parser = FormMTMLParser()
    forms = parser.get_forms(page_content)

    if len(forms) > 1:
        print("Multiple forms found! This is not supported!")
        sys.exit(1)
    elif len(forms) == 1:
        return forms[0]

    return None


def fill_form(form):
    """Add user input to form"""
    form.fill_form("Ecom_User_ID", CONF_USERNAME)  # username prompt
    form.fill_form("nfchn", "PW+TOTP")  # select totp

    authmethod = form.input_elements.get("nfmt")
    if authmethod == "LDAP_PASSWORD:1":  # password
        form.fill_form("nffc", CONF_PASSWORD)
    elif authmethod == "TOTP:1":  # totp pin
        form.fill_form("nffc", totp.now())


def extract_multi(pattern_str, content):
    pattern = re.compile(pattern_str)
    return re.findall(pattern, content)


def extract_single(pattern_str, content):
    matches = extract_multi(pattern_str, content)

    if len(matches) != 1:
        print("Multiple or no matches found! This is not supported!")
        sys.exit(1)

    return matches[0]


# Initial requst
form = Form(CONF_VPN_URL, "GET")

print("Authenticating...")
counter = 1

while form is not None:
    print(f"Step {counter!s}")
    r = request_with_method(form.method, form.url, form.input_elements)
    con = r.content.decode()

    if CONF_DEBUG:
        log(f"Dumping page content to page{counter!s}.html")
        with open(f"./page{counter!s}.html", "wb") as bfile:
            bfile.write(r.content)

    if (form := get_form_data(con)) is not None:
        fill_form(form)

        if "document.cookie" in con:
            # During all these redirections, there are some cookies set via js
            # which are required to continue. Handle this case here manually.
            # We use regex instead of a proper javascript parser here so
            #
            # ! THIS WILL BREAK EARLY !
            #
            # Adapt the DOCUMENT_COOKIE_PATTERN regex if the website uses
            # another method/structure to set the cookies
            cookie_url = urlparse(
                base_url
            ).netloc  # use base_url, not form.url because form.url might contain relative url

            # pattern to extract document.cookie content
            # e.g. document.cookie = "CSRFtoken=" + "tokenhere" + "; path=/; secure";
            # extraction is "CSRFtoken=" + "tokenhere" + "; path=/; secure"
            DOCUMENT_COOKIE_PATTERN = r"""document\.cookie\s*=\s*(("[^"]*")(\s?\+\s?("[^"]*"))*);"""
            cookie_matches = extract_multi(DOCUMENT_COOKIE_PATTERN, con.replace("\n", ""))
            cookie_matches = [x[0] for x in cookie_matches]  # extract outermost group (group 1)

            for cookie_match in cookie_matches:
                # transform "abc" + "def" to abcdef, extract name and value, set cookie in session
                cookie_match = "".join([x for x in cookie_match.split('"') if x.strip() not in ["+", ""]])
                name, value = cookie_match.split("=", maxsplit=1)

                log(f"Inserting cookie {name}: {value}")
                s.cookies.set(domain=cookie_url, name=name, value=value)
    elif "top.location.href" in con:
        # Extract redirection url
        redirection_url = extract_single(r"top\.location\.href='([^']+)'", r.content.decode())
        form = Form(redirection_url, "GET")
        log(f"Found redirection url {redirection_url}")
    elif "document.location.replace" in con:
        redirection_url = extract_single(r'document\.location\.replace\("([^\)]+)\);', r.content.decode())
        redirection_url = redirection_url.replace("\n", "").replace('"+"', "").strip('"')
        form = Form(redirection_url, "GET")
        log(f"Found redirection url {redirection_url}")

    counter += 1

    if counter > 10:
        # 9 should be enough, increase the limit if required
        print("ERROR! Too many steps. 9 should be enough. There is something wrong here...")
        print("Check your username, password and TOTP token. Debug output might also help.")
        sys.exit(1)

if b"You have successfully authenticated" not in r.content:
    print("Authentication failed.")
    sys.exit(1)

print("Authentication successful.")

cookies = s.cookies.get_dict()

if CONF_SSO_COOKIE_NAME not in cookies:
    print("Could not retrieve cookie")
    sys.exit(1)

SSO_COOKIE = cookies[CONF_SSO_COOKIE_NAME]
print("Cookie retrieved")
print(SSO_COOKIE)

if CONF_OC_DICT:
    print("Runing openconnect")
    command_line = [
        *CONF_OC_PREFIX,
        "openconnect",
        "--useragent=AnyConnect",
        "--protocol=anyconnect",
        "--token-mode=anyconnect-sso",
        "--token-secret=" + SSO_COOKIE,
        CONF_OC_VPN_DOMAIN,
        *CONF_OC_SUFFIX,
    ]
    log("Command line:")
    log(" ".join(command_line))

    p = subprocess.run(command_line)

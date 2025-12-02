import requests
from bs4 import BeautifulSoup

session = requests.Session()

def login_dvwa(security_level="medium"):
    login_url = "http://localhost/dvwa/login.php"

    # Get login page (to retrieve user_token)
    login_page = session.get(login_url)
    soup = BeautifulSoup(login_page.text, "lxml")

    token = soup.find("input", {"name": "user_token"})["value"]

    payload = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }

    # Log in
    session.post(login_url, data=payload)

    # Set the DVWA security level cookie
    session.cookies.set("security", security_level, domain="localhost", path="/")

    print(f"[+] DVWA security set to: {security_level}")



def send_payload(url, param, payload):
    page = session.get(url)
    soup = BeautifulSoup(page.text, "lxml")

    user_token = soup.find("input", {"name": "user_token"})["value"]

    data = {
        param: payload,
        "user_token": user_token
    }

    # GET request with params
    response = session.get(url, params=data)
    return response.text

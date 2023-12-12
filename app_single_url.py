import sys
import requests as req
import pandas as pd

def check_for_wildcard(value):
    found = value.find("* ")
    if found >= 0:
        return True
    else:
        return False
    
print("#"*90)
print("     Author: Tal Sperling")
print("     This code is to be used for educational purposes or legal penetration testing only")
print("     I do not take responsibility for any misuse or illegal action/use of this code")
print("#"*90+"\n")

print("")
print("")

url = input("Please enter the url: https://")
url = "https://" + url


while True:
    try:
        print("[1] GET")
        print("[2] POST")
        req_type = int(input("Please choose request type: "))

        if req_type > 2 or req_type < 1:
            print("Invalid input")
        else:
            break
    except:
        print("Invalid input")

try:
    print("[+] Starting scan...")
    cookies = {'test_cookie': 'test'}
    headers = {
        'User-agent': 'Mozilla/5.0'
    }

    session = req.Session()

    if req_type == 1:
        req_headers = session.get(url, headers=headers)
    elif req_type == 2:
        req_headers = session.post(url, cookies=cookies, headers=headers)

    x_frame = False
    x_frame_vuln = "Not Vulnerable"

    csp = False
    csp_vuln = "Not Vulnerable"

    server = False
    server_data = ""

    x_powered_by = False
    x_powered_by_data=  ""

    cookies_data = []


    for header, value in req_headers.headers.items():
        if header == "X-FRAME-OPTIONS":
            x_frame = True
            x_frame_result = check_for_wildcard(value)

            if x_frame_result:
                x_frame_vuln = "Wildcard exists"

        if header == "Content-Security-Policy":
            csp = True
            csp_result = check_for_wildcard(value)

            if x_frame_result:
                csp_vuln = "Wildcard exists"
        
        if header == "Server":
            server = True
            server_data = value

        if header == "X-Powered-By":
            x_powered_by = True
            x_powered_by_data = value


   
    for cookie in req_headers.cookies:
        cookie_att = {"Cookie":[], "Vulnerability":[]}
        if not cookie.expires or not cookie.secure or not cookie.has_nonstandard_attr('httponly'):
            if not cookie.expires:
                cookie_att['Cookie'].append(cookie.name)
                cookie_att['Vulnerability'].append("Expiration date missing")
            
            if not cookie.secure:
                cookie_att['Cookie'].append(cookie.name)
                cookie_att['Vulnerability'].append("Secure tag missing")
            
            if not cookie.has_nonstandard_attr('httponly'):
                cookie_att['Cookie'].append(cookie.name)
                cookie_att['Vulnerability'].append("Httponly tag missing")

            cookies_data.append(cookie_att)

    clickjacking = False
    exposed_data = False

    if not x_frame or x_frame_vuln != "Not Vulnerable" and not csp or csp_vuln != "Not Vulnerable":
        clickjacking = True


    print("[+] Scan successful...")
    print("_______________________")
    print("")
    print("[+] Results:")
    print("")

    if clickjacking:
        print("Vulnerable to clickjacking:")
        
        if not x_frame:
            print("- X-FRAME-OPTIONS missing")
        else:
            print("- {}".format(x_frame_vuln))

        if not csp:
            print("- CONTENT-SECURITY-POLICY missing")
        else:
            print("- {}",format(csp_vuln))

    if server:
        print("")
        print("Data is exposed:")
        print("- Server: {}".format(server_data))

    if x_powered_by:
        print("")
        print("Data is exposed:")
        print("- X-Powered-By: {}".format(x_powered_by_data))

    print("")
    print("Cookies")
    print("-------")

    cookiedDF = pd.DataFrame(cookies_data)

    print(cookiedDF)

except Exception as e:
    print("[-] Scan failed...")
    print(f"Error: {e}")

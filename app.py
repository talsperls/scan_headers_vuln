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

try:

    urls_to_scan = open(sys.argv[1], 'r')
    Lines = urls_to_scan.readlines()

    header_data = {"Hostname":[],"Header Vulnerabilities":[]}
    cookie_data = {"Hostname":[], "Cookie Name":[], "Cookie Vulnerabilities":[]}

except Exception as e:
    print("[-] Error reading data")
    print(e)
    sys.exit()

for line in Lines:
    url = line.strip()
    url = "https://" + url

    print(f"[+] Scanning {url}")

    cookies = {'test_cookie': 'test'}
    headers = {
        'User-agent': 'Mozilla/5.0'
    }

    try:

        session = req.Session()

        req_headers = session.get(url, cookies=cookies, headers=headers)

        x_frame = False
        x_frame_vuln = "Not Vulnerable"

        csp = False
        csp_vuln = "Not Vulnerable"

        server = False
        server_data = ""

        x_powered_by = False
        x_powered_by_data=  ""

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
                    cookie_data["Hostname"].append(url)
                    cookie_data["Cookie Name"].append(cookie.name)
                    cookie_data['Cookie Vulnerabilities'].append("Expiration date missing")
                
                if not cookie.secure:
                    cookie_data["Hostname"].append(url)
                    cookie_data["Cookie Name"].append(cookie.name)
                    cookie_data['Cookie Vulnerabilities'].append("Secure tag missing")
                
                if not cookie.has_nonstandard_attr('httponly'):
                    cookie_data["Hostname"].append(url)
                    cookie_data["Cookie Name"].append(cookie.name)
                    cookie_data['Cookie Vulnerabilities'].append("Httponly tag missing")
                    

        clickjacking = False
        exposed_data = False

        if not x_frame or x_frame_vuln != "Not Vulnerable" and not csp or csp_vuln != "Not Vulnerable":
            clickjacking = True

        if clickjacking:
            
            if not x_frame:
                header_data["Hostname"].append(url)
                header_data["Header Vulnerabilities"].append("Clickjacking - X-FRAME-OPTIONS missing")
            else:
                header_data["Hostname"].append(url)
                header_data["Header Vulnerabilities"].append(f"Clickjacking - {x_frame_vuln}")

            if not csp:
                header_data["Hostname"].append(url)
                header_data["Header Vulnerabilities"].append("Clickjacking - CONTENT-SECURITY-POLICY missing")
            else:
                header_data["Hostname"].append(url)
                header_data["Header Vulnerabilities"].append(f"Clickjacking - {csp_vuln}")

        if server:
            header_data["Hostname"].append(url)
            header_data["Header Vulnerabilities"].append(f"Data is exposed - Server: {server_data}")

        if x_powered_by:
            header_data["Hostname"].append(url)
            header_data["Header Vulnerabilities"].append(f"Data is exposed - X-Powered-By: {x_powered_by_data}")


        header_data_df = pd.DataFrame(header_data)
        cookie_data_df = pd.DataFrame(cookie_data)

        print(f"[+] Finished scanning {url}")

    

    except Exception as e:
        print(f"[-] Scan for {url} failed")
        print(e)
        


print(header_data_df)
print("________")
print(cookie_data_df)
print(" ")

try:
    header_data_df.to_csv('header_results.csv', index=False)
    print("[+] Exported to csv... header_results.csv")

    cookie_data_df.to_csv('cookie_results.csv', index=False)
    print("[+] Exported to csv... cookie_results.csv")
except Exception as e:
    print("[-] Failed to export to csv")
    print(e)




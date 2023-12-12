
# Header Vulnerability Scanner

Author: Tal Sperling

This code is to be used for educational purposes or legal penetration testing only.
I do not take responsibility for any misuse or illegal action/use of this code.

## Description

Scans URLs for vulnerabilities in the headers

## Use

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the requirements.

```bash
pip install -r requirements.txt
```
Option 1
- Scans a list of URLs from a file

```bash
python app.py url_list.txt
```

Option 1
- Scans 1 URL from user's input

```bash
python app_single_url.py
```

The app exports the data to an excel file therefore Microsoft Excel is needed to view the exported data
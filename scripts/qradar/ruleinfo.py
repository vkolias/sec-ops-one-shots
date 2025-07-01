 #!/usr/bin/python3
# ------------------------------------------------------------------------------
# Script:     ruleinfo.py
# Purpose:    Generates a csv file with the properties of all rules in a QRadar deployment
# Author:     Vasilis Kolias (https://github.com/vkolias)
# Created:    2025-07-01
# License:    MIT License
# ------------------------------------------------------------------------------


import os
import urllib.request
import urllib.parse
import json
import ssl
import logging
import sys
import argparse
import zipfile
import xml.etree.ElementTree as ET
import io
import html
import base64
import re
import uuid
import mimetypes
import time
from datetime import datetime
import csv


class BaseClient:
    """
    A simple REST API client using urllib for making GET, POST, PUT, and DELETE requests.

    Supports:
    - JSON requests and responses
    - Multipart file uploads
    - Optional SSL verification
    - Timeout handling
    """
    def __init__(self, base_url, headers=None, timeout=10, verify_ssl=False, ca_cert_path=None):
        """
        Initializes the BaseClient.

        Args:
            base_url (str): The root URL of the API.
            headers (dict, optional): Default headers to include in each request.
            timeout (int, optional): Timeout for API requests in seconds.
            verify_ssl (bool, optional): Whether to verify SSL certificates.
            ca_cert_path (str, optional): Path to a custom CA certificate.
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.headers = headers or {}

        # SSL context setup
        if verify_ssl:
            if ca_cert_path:
                self.ssl_context = ssl.create_default_context(cafile=ca_cert_path)
            else:
                self.ssl_context = ssl.create_default_context()
        else:
            self.ssl_context = ssl._create_unverified_context()

    def _build_url(self, path, params=None):
        """
        Builds the full URL by combining the base URL with the path and query parameters.

        Args:
            path (str): API endpoint path.
            params (dict, optional): Dictionary of query parameters.

        Returns:
            str: The complete URL.
        """
        url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            query = urllib.parse.urlencode(params)
            url += f"?{query}"
        return url
    
    def _encode_multipart(self, fields, files, boundary):
        """
        Encodes fields and files for a multipart/form-data request.

        Args:
            fields (dict): Non-file form fields.
            files (dict): File fields in the form {'field_name': (filename, file_obj)}.
            boundary (str): Boundary string for multipart encoding.

        Returns:
            bytes: Encoded multipart body.
        """
        lines = []
        boundary_line = f"--{boundary}"

        # Add form fields
        if fields:
            for key, value in fields.items():
                lines.append(boundary_line)
                lines.append(f'Content-Disposition: form-data; name="{key}"')
                lines.append("")
                lines.append(str(value))

        # Add files
        for key, file_info in files.items():
            filename, file_obj = file_info
            mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            lines.append(boundary_line)
            lines.append(f'Content-Disposition: form-data; name="{key}"; filename="{filename}"')
            lines.append(f"Content-Type: {mimetype}")
            lines.append("")

            # Ensure file_obj is raw string content
            if hasattr(file_obj, 'read'):  # e.g., BytesIO or file object
                file_bytes = file_obj.read()
            elif isinstance(file_obj, bytes):
                file_bytes = file_obj
            else:
                file_bytes = str(file_obj).encode('utf-8')

            lines.append(file_bytes.decode('latin1'))

        lines.append(f"--{boundary}--")
        lines.append("")

        return "\r\n".join(lines).encode('latin1')



    def _make_request(self, method, url, data=None, headers=None, files=None):
        """
        Makes an HTTP request with the given method and parameters.

        Handles:
        - JSON encoding
        - Multipart encoding
        - Binary or text response parsing

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE).
            url (str): Fully constructed API URL.
            data (dict, str, bytes, optional): Request body or form data.
            headers (dict, optional): Additional headers.
            files (dict, optional): Files for multipart upload.

        Returns:
            dict, str, or bytes: Parsed response based on content type.

        Raises:
            RuntimeError: If an HTTP or URL error occurs.
        """
        all_headers = self.headers.copy()
        if headers:
            all_headers.update(headers)
        body = None
        # Handle file upload (multipart/form-data)
        if files:
            boundary = uuid.uuid4().hex
            all_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            body = self._encode_multipart(data, files, boundary)
        # Handle JSON
        elif isinstance(data, dict):
            body = json.dumps(data).encode('utf-8')
            all_headers['Content-Type'] = 'application/json'
        # Handle raw strings
        elif isinstance(data, str):
            body = data.encode('utf-8')
        # Already bytes or None
        elif isinstance(data, bytes) or data is None:
            body = data
        # Logging (safe)
        # print("==== Final request ====")
        # print("URL:", url)
        # print("Method:", method)
        # print("Headers:", all_headers)
        # try:
        #     print("Body:", body.decode('utf-8') if body else "(none)")
        # except UnicodeDecodeError:
        #     print("Body: (binary data)")
        # Send request
        req = urllib.request.Request(url, data=body, headers=all_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
                content = response.read()
                content_type = response.getheader("Content-Type", "")
                if content_type.startswith("application/json"):
                    return json.loads(content)
                elif content_type.startswith("text/"):
                    return content.decode()
                else:
                    return content  # binary (e.g. zip)
        except urllib.error.HTTPError as e:
            error_message = e.read().decode()
            raise RuntimeError(f"HTTP Error {e.code}: {error_message}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"URL Error: {e.reason}")

    def get(self, path, params=None, headers=None):
        """
        Sends an HTTP GET request.

        Args:
            path (str): API endpoint path.
            params (dict, optional): Query parameters.
            headers (dict, optional): Additional headers.

        Returns:
            dict, str, or bytes: Parsed response.
        """
        url = self._build_url(path, params)
        return self._make_request('GET', url, headers=headers)

    def post(self, path, data=None, headers=None, files=None):
        """
        Sends an HTTP POST request.

        Args:
            path (str): API endpoint path.
            data (dict, str, bytes, optional): Request body.
            headers (dict, optional): Additional headers.
            files (dict, optional): Files for multipart upload.

        Returns:
            dict, str, or bytes: Parsed response.
        """
        url = self._build_url(path)
        return self._make_request('POST', url, data=data, headers=headers, files=files)

    def put(self, path, data=None, headers=None):
        """
        Sends an HTTP PUT request.

        Args:
            path (str): API endpoint path.
            data (dict, str, bytes, optional): Request body.
            headers (dict, optional): Additional headers.

        Returns:
            dict, str, or bytes: Parsed response.
        """
        url = self._build_url(path)
        return self._make_request('PUT', url, data=data, headers=headers)

    def delete(self, path, headers=None):
        """
        Sends an HTTP DELETE request.

        Args:
            path (str): API endpoint path.
            headers (dict, optional): Additional headers.

        Returns:
            dict, str, or bytes: Parsed response.
        """
        url = self._build_url(path)
        return self._make_request('DELETE', url, headers=headers)
    
class App:
    _instance = None 

    def __init__(self):
        self.qradar_key = os.environ.get("QRADAR_KEY")
        self.qradar_base_url = os.environ.get("QRADAR_BASE_URL")
        if not self.qradar_key:
            raise ValueError("QRADAR_KEY environment variable is not set")
        elif not self.qradar_base_url:
            raise ValueError("QRADAR_BASE_URL environment variable is not set")      
        self.qradar_headers = {'Accept': 'application/json', 'Connection': 'keep-alive', 'SEC': f"{self.qradar_key}"}
        self.qradar_client = BaseClient(self.qradar_base_url, self.qradar_headers)

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(App, cls).__new__(cls)
        return cls._instance
    
    def fetch_all_rules(self):
        endpoint = 'analytics/rules'
        rules = self.qradar_client.get(endpoint)
        return rules

    def fetch_offense_type_name_by_offense_type_id(self, offense_type_id):
        endpoint = "/siem/offense_types"
        params = {'filter' : f"id={offense_type_id}"}
        response = self.qradar_client.get(endpoint, params=params)
        return response[0]['name']

    def fetch_all_rule_info(self, rules):
        """
        Downloads, extracts, and parses QRadar custom rules based on rule IDs.

        Args:
            ruleIDs (list): A list of rule ID strings.

        Returns:
            list: A list of dictionaries with rule names and parsed rule logic.
        """
        ruleIDs = []
        for r in rules:
            ruleIDs.append(str(r["id"]))
        
        #create a download rule task       
        logging.info(f"Total rules to download: {len(ruleIDs)}\nDownloading rules...")
        endpoint = "config/extension_management/extension_export_tasks"
        data = {
                "export_contents": [
                        { 
                        "content_item_ids": ruleIDs, 
                        "content_type": "CUSTOM_RULES", 
                        "related_content": [] 
                        }
                ]
            }
        response = self.qradar_client.post(endpoint, data=data)
        task_id = response["task_id"]
        
        #check status of task
        endpoint = f"config/extension_management/extensions_task_status/{task_id}"
        while True:
            status_response = self.qradar_client.get(endpoint)
            status = status_response['status']
            if status == "COMPLETED":
                    break
        
        #download the actual rule payload
        endpoint = f"config/extension_management/extension_export_tasks/{task_id}/extension_export"
        self.qradar_headers["Accept"] = 'application/zip'
        self.qradar_headers["Content-Type"] = 'application/zip'
        content = self.qradar_client.get(endpoint)
        logging.info("Download complete...")
        self.qradar_headers["Accept"] = 'application/json'
        self.qradar_headers["Content-Type"] = 'application/json'
        
        logging.info("Processing rules...")
        zip_file = zipfile.ZipFile(io.BytesIO(content))
        rulelist = []
        rulelist.append(["ID", "Name", "Enabled", "Type", "Owner", "Index", "Tests", "Creation_Date", "Modification_Date", "Notes"])
        offense_types = {}
        for name in zip_file.namelist():
            with zip_file.open(name) as f:
                content = f.read()
                content = content.decode(errors='ignore')
                try:
                    root = ET.fromstring(content)
                except ET.ParseError as e:
                    logging.warning(f"Failed to parse XML: {e}")
                    continue
                for custom_rule in root.findall("custom_rule"):
                    rule_id = custom_rule.find("id").text                                       #rule_id
                    
                    if rule_id is not None and rule_id in ruleIDs:
                        rule_data = custom_rule.find("rule_data")
                        if rule_data is not None:
                            rule =  base64.b64decode(rule_data.text).decode('utf-8')
                            try:
                                rule_root = ET.fromstring(rule)
                            except ET.ParseError as e:
                                logging.warning(f"Failed to parse XML: {e}")
                                continue
                            
                            rule_enabled = rule_root.get("enabled", "")                             #rule_enabled
                            
                            rule_type = rule_root.get("type", "")                                  #rule_type
                            
                            rule_owner = rule_root.get("owner", "")                                 #rule_owner
                            
                            print(rule_id, rule_enabled, rule_type, rule_owner)
                            rule_name = rule_root.findtext("name", default="")                  #rule_name
                            logging.info(f"    New rule extracted: {rule_name}")
                            rule_notes = rule_root.findtext("notes", default="")                #rule_notes
                            rule_notes = re.sub(r'\s+', ' ', rule_notes).strip()
                            
                            offense_type = ""                                                   #offense_type
                            newevents = rule_root.findall(".//newevent")
                            
                            if len(newevents) > 0:
                                for newevent in rule_root.findall(".//newevent"):
                                    offense_type_id = newevent.get('offenseMapping')
                                    if not offense_type_id in offense_types:
                                        offense_type = self.fetch_offense_type_name_by_offense_type_id(offense_type_id)
                                        offense_types[offense_type_id] = offense_type
                                    else:
                                        offense_type = offense_types[offense_type_id]

                            number_of_tests = len(rule_root.findall(".//test"))                 #number of tests
                            
                            
                            creation_date = ""
                            modification_date = ""
                            for rule in rules:
                                if str(rule['id']) == rule_id:
                                    dt = datetime.fromtimestamp(int(rule['creation_date']) / 1000)
                                    creation_date = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    dt = datetime.fromtimestamp(int(rule['modification_date']) / 1000)
                                    modification_date = dt.strftime("%Y-%m-%d %H:%M:%S")
                                    break 
                            rulelist.append([rule_id, rule_name, rule_enabled, rule_type, rule_owner, offense_type, number_of_tests, creation_date, modification_date, rule_notes])
        
            logging.info("Rule processing complete.")
            return rulelist
        


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    app = App()
    logging.info(f"Collecting rule info...")
    try:
        rules = app.fetch_all_rules()
        rulelist = app.fetch_all_rule_info(rules)

        with open("output.tsv", "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter='\t')
            writer.writerows(rulelist)

        
    except Exception as e:
        logging.error(f"Failed to fetch offense: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
 #!/usr/bin/python3
# ------------------------------------------------------------------------------
# Script:     offensetoopenai.py
# Purpose:    Analyzes a QRadar offense with the Openai API
# Author:     Vasilis Kolias (https://github.com/vkolias)
# Created:    2025-06-09
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

        self.openai_token = os.environ.get("OPENAI_TOKEN")
        self.openai_base_url = os.environ.get("OPENAI_BASE_URL")
        if not self.openai_token:
            raise ValueError(f"OPENAI_TOKEN environment variable is not set")
        if not self.openai_base_url:
            raise ValueError(f"OPENAI_BASE_URL environment variable is not set")
        
        self.openai_headers = {'Accept': 'application/json', "Content-Type": "application/json", "OpenAI-Beta": "assistants=v2", 'Authorization': "Bearer " + str(self.openai_token)}
        self.openai_client = BaseClient(self.openai_base_url, self.openai_headers)

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(App, cls).__new__(cls)
        return cls._instance
    
    def fetch_offense_by_id(self, offense_id):
        """
        Fetches details of a QRadar offense by ID using the QRadar API.

        Returns:
            json: the qradar api response representing offense information.
        """
        endpoint = "/siem/offenses"
        params = {'fields' : "description, start_time, categories, magnitude, source_network, destination_networks, offense_source, rules, log_sources", 'filter' : f"id='{offense_id}'"}
        response = self.qradar_client.get(endpoint, params=params)
        return response
    
    def fetch_rules_by_ids(self, ruleIDs):
        """
        Downloads, extracts, and parses QRadar custom rules based on rule IDs.

        Args:
            ruleIDs (list): A list of rule ID strings.

        Returns:
            list: A list of dictionaries with rule names and parsed rule logic.
        """
        #create a download rule task
        logging.info("Downloading rules...")
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
        rules = []
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
                    rule_id = custom_rule.find("id")
                    if rule_id is not None and rule_id.text in ruleIDs:
                        rule_data = custom_rule.find("rule_data")
                        if rule_data is not None:
                            rule =   base64.b64decode(rule_data.text).decode('utf-8')
                            try:
                                rule_root = ET.fromstring(rule)
                            except ET.ParseError as e:
                                logging.warning(f"Failed to parse XML: {e}")
                                continue
                            rule_name = rule_root.findtext("name")
                            logging.info(f"    New rule extracted: {rule_name}")
                            
                            test_outputs = []
                            for test in rule_root.findall(".//test"):
                                # Get raw HTML text and decode HTML entities
                                raw_text = test.findtext("text")
                                if not raw_text:
                                    continue
                                decoded_text = html.unescape(raw_text)

                                def keep_anchor_label(match):
                                    return match.group(1)

                                # Replace all <a ...>label</a> with just label
                                clean_text = re.sub(r"<a [^>]+>(.*?)</a>", keep_anchor_label, decoded_text)
                                test_outputs.append("AND " + clean_text.strip())
                            rules.append({'name':rule_name, 'tests':test_outputs})
            logging.info("Rule processing complete.")
            return rules
        
    def getEventsByOffenseID(self, offense_id, start_time):
        """
        Initiates an Ariel search and retrieves events related to a specific offense.

        Args:
            offense_id (str): The QRadar offense ID.
            start_time (int): Epoch timestamp in milliseconds indicating start time for event search.

        Returns:
            dict: Dictionary containing 'events' field with QRadar logs.
        """
        endpoint = "ariel/searches"
        query = f'select utf8(payload) from events where inoffense({offense_id}) start {start_time}'
        data = {'query_expression':f"{query}"}
        data = urllib.parse.urlencode(data).encode('utf-8')
        self.qradar_headers["Content-Type"] = "application/x-www-form-urlencoded"

        response = self.qradar_client.post(endpoint, data)
        search_id = response["search_id"]
        
        endpoint = f"ariel/searches/{search_id}"
        logging.info("Downloading events...")
        self.qradar_headers["Content-Type"] = "application/json"
        while True:
            response = self.qradar_client.get(endpoint)
            status = response['status']
            if status == "COMPLETED":
                logging.info("Download complete.")
                break
        
        endpoint = f"ariel/searches/{search_id}/results"
        events = self.qradar_client.get(endpoint)

        logging.info(f"Number of events downloaded: {len(events['events'])}")
        return events

    def uploadFile(self, filename, file):
        """
        Uploads a local file to OpenAI's file API for use with assistants.

        Args:
            filename (str): Name of the file to register.
            file (dict): JSON-serializable object representing the file contents.

        Returns:
            str: File ID returned by OpenAI.
        """
        endpoint = "files"

        file = io.BytesIO(json.dumps(file).encode('utf-8'))
        files={"file": (filename, file)}
        data={"purpose": "assistants"}

        logging.info(f"Uploading {filename}...")
        # self.openai_client.setHeaders(self.openai_headers_post)
        response = self.openai_client.post(endpoint, data=data, files=files)
        # self.openai_client.setHeaders(self.openai_headers_json)
        logging.info("Upload complete.")
        file_id = response["id"]

        return file_id

    def analyze_files(self, files):
        """
        Creates an OpenAI assistant and thread to analyze uploaded QRadar rule and event files,
        submits an analysis prompt, polls for the result, and prints the assistant's reply.

        Args:
            files (list): A list of file IDs to attach to the assistant thread.
        """

        # 1. Create Assistant
        logging.info("Creating Assistant...")
        endpoint = "assistants"
        assistant_payload = {
            "name": "QRadar Analyst",
            "instructions": "You're a cybersecurity analyst expert in QRadar. You are good in analyzing qradar offenses based on rules and events from various log sources.",
            "model": "gpt-4-1106-preview",
            "tools": [{"type": "file_search"}]
        }

        response = self.openai_client.post(endpoint, data=assistant_payload)
        assistant_id = response["id"]
        logging.info(f"Assistant {assistant_id} created")

        logging.info("Creating a thread...")
        # 2. Create Thread
        endpoint = "threads"
        response = self.openai_client.post(endpoint)
        thread_id = response["id"]
        logging.info(f"Thread {thread_id} created")
        
        # 3. Post to thread
        logging.info(f"Posting to thread {thread_id}...")
        endpoint = f"threads/{thread_id}/messages"
        message_payload = {
            "role": "user",
            "content": """Given rules.json and events.json:
                a) Is this a true or false positive and why?
                b) Summarize what happened in one paragraph.
                c) Provide remediation actions.""",
                "attachments": [{"file_id": fid, "tools": [{"type": "file_search"}]} for fid in files]
        }
        response = self.openai_client.post(endpoint, data=message_payload)
        logging.info(f"Posted.")

        # 4. Get thread response
        logging.info(f"Getting response...")
        endpoint = f"threads/{thread_id}/runs"  
        data={"assistant_id": assistant_id}  
        response = self.openai_client.post(endpoint, data=data)
        run_id = response['id']
        status = "in_progress"
        while status != "completed":
            time.sleep(2)
            endpoint = f"threads/{thread_id}/runs/{run_id}"
            response = self.openai_client.get(endpoint)
            status = response['status']
            logging.info(f"Status: {status}. Retrying...")

        endpoint = f"threads/{thread_id}/messages"
        response = self.openai_client.get(endpoint)
        messages = response["data"]

        for msg in messages:
            print(f"{msg['role']}: {msg['content'][0]['text']['value']}")

        # 5. Cleanup
        if thread_id:
            try:
                self.openai_client.delete(f"threads/{thread_id}")
                logging.info(f"Deleted thread {thread_id}")
            except Exception as e:
                logging.info(f"Failed to delete thread {thread_id}: {e}")

        if assistant_id:
            try:
                self.openai_client.delete(f"assistants/{assistant_id}")
                logging.info(f"Deleted assistant {assistant_id}")
            except Exception as e:
                logging.info(f"Failed to delete assistant {assistant_id}: {e}")



def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    parser = argparse.ArgumentParser(description="Analyze a QRadar offense with OpenAI")
    parser.add_argument("--offense-id", required=True, help="QRadar offense ID")
    args = parser.parse_args()

    app = App()
    logging.info(f"Collecting offense info for offense id {args.offense_id}...")
    try:
        offense = app.fetch_offense_by_id(args.offense_id)
        logging.info(f"Offense info for offense id {args.offense_id} successfully collected")

        offense_rule_ids = offense[0]["rules"]
        ids = []
        for r in offense_rule_ids:
            ids.append(str(r["id"]))
        rules = app.fetch_rules_by_ids(ids)

        offense_start = offense[0]["start_time"]
        events = app.getEventsByOffenseID(args.offense_id, offense_start)

        file_id = app.uploadFile("rules.json", rules)
        events_id = app.uploadFile("events.json", events)
        
        app.analyze_files([file_id, events_id])

        
    except Exception as e:
        logging.error(f"Failed to fetch offense: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
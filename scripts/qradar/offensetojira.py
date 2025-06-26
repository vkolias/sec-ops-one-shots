 #!/usr/bin/python3
# ------------------------------------------------------------------------------
# Script:     offensetojira.py
# Purpose:    Creates a JIRA ticket based on a QRadar offense
# Author:     Vasilis Kolias (@vkolias)
# Created:    2025-06-26
# License:    MIT License
# ------------------------------------------------------------------------------

import os
import urllib.request
import urllib.parse
import json
import ssl
import base64
import argparse
import logging
from dataclasses import dataclass
from typing import List
import sys

class BaseClient:
    def __init__(self, base_url, headers=None, timeout=10, verify_ssl=False, ca_cert_path=None):
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
        Constructs a full URL using the base URL and optional query parameters.
        """
        url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            query = urllib.parse.urlencode(params)
            url += f"?{query}"
        return url

    def _make_request(self, method, url, data=None, headers=None):
        """
        Makes an HTTP request with the given method, headers, and data, and handles the response.
        """
        all_headers = self.headers.copy()
        if headers:
            all_headers.update(headers)

        if data is not None:
            if isinstance(data, dict):
                data = json.dumps(data).encode('utf-8')
                all_headers['Content-Type'] = 'application/json'
            elif isinstance(data, str):
                data = data.encode('utf-8')

        req = urllib.request.Request(url, data=data, headers=all_headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
                content = response.read()
                return json.loads(content) if response.getheader("Content-Type", "").startswith("application/json") else content.decode()
        except urllib.error.HTTPError as e:
            error_message = e.read().decode()
            raise RuntimeError(f"HTTP Error {e.code}: {error_message}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"URL Error: {e.reason}")

    def get(self, path, params=None, headers=None):
        """
        Sends a GET request to the specified path with optional headers and query parameters.
        """
        url = self._build_url(path, params)
        return self._make_request('GET', url, headers=headers)

    def post(self, path, data=None, headers=None):
        """
        Sends a POST request to the specified path with optional data and headers.
        """
        url = self._build_url(path)
        return self._make_request('POST', url, data=data, headers=headers)

    def put(self, path, data=None, headers=None):
        """
        Sends a PUT request to the specified path with optional data and headers.
        """
        url = self._build_url(path)
        return self._make_request('PUT', url, data=data, headers=headers)

    def delete(self, path, headers=None):
        """
        Sends a DELETE request to the specified path with optional headers.
        """
        url = self._build_url(path)
        return self._make_request('DELETE', url, headers=headers)

@dataclass
class Offense:
    id: int
    description: str
    source: str
    magnitude: int
    log_sources: List[str]
    type: str
    domain: str

class App:
    _instance = None 

    def __init__(self):
        """
        Initializes the class and configures API headers and clients using environment variables.
        """
        self.qradar_key = os.environ.get("QRADAR_KEY")
        self.qradar_base_url = os.environ.get("QRADAR_BASE_URL") # f"https://{self.qradar_ip}/api"
        if not self.qradar_key:
            raise ValueError("QRADAR_KEY environment variable is not set")
        elif not self.qradar_base_url:
            raise ValueError("QRADAR_BASE_URL environment variable is not set")      
        
        self.qradar_headers = {"Accept": "application/json", "Connection": "keep-alive", "SEC": f"{self.qradar_key}"}
        self.qradar_client = BaseClient(self.qradar_base_url, self.qradar_headers)

        self.jira_token = os.environ.get("JIRA_API_TOKEN")
        self.jira_email = os.environ.get("JIRA_EMAIL")
        self.jira_base_url = os.environ.get("JIRA_BASE_URL")
        if not self.jira_token:
            raise ValueError("JIRA_API_TOKEN environment variable is not set")
        elif not self.jira_email:
            raise ValueError("JIRA_EMAIL environment variable is not set")
        elif not self.jira_base_url:
            raise ValueError("JIRA_BASE_URL environment variable is not set")
        encoded = base64.b64encode(f"{self.jira_email}:{self.jira_token}".encode("utf-8")).decode("utf-8")
        self.jira_headers = {"Accept": "application/json", "Connection": "keep-alive", "Content-Type": "application/json", "Authorization": f"Basic {encoded}"}
        self.jira_client = BaseClient(self.jira_base_url, self.jira_headers)
        
    def __new__(cls, *args, **kwargs):
        """
        Implements the singleton pattern to return a shared App instance.
        """
        if cls._instance is None:
            cls._instance = super(App, cls).__new__(cls)
        return cls._instance
    
    def __repr__(self):
        """
        Returns a string representation of the App instance showing configured endpoints.
        """
        return f"<App(qradar='{self.qradar_base_url}', jira='{self.jira_base_url}')>"

    def get_offense(self, offense_id):
        """
        Fetches and formats a specific offense from QRadar including log sources, offense type, and domain name.

        Args:
            offense_id (str): The ID of the offense to retrieve.

        Returns:
            Offense: Structured offense data.
        """
        params = {'fields' : "id, description, magnitude, domain_id, offense_type, offense_source, log_sources", 'filter' : f"id='{offense_id}'"}
        res_offense = self.qradar_client.get("siem/offenses",params)
        if len(res_offense) == 0:
            raise Exception(f"Empty Response: Offense {offense_id} may not exist")
        description = res_offense[0]['description'].replace('\n', '')
        source = res_offense[0]["offense_source"]
        magnitude = res_offense[0]["magnitude"]
        log_sources = []
        for log_source in res_offense[0]["log_sources"]:
            log_sources.append(f"{log_source['name']} ({log_source['type_name']})")

        type = ""
        params = {'fields':"name", 'filter' : f"id='{res_offense[0]['offense_type']}'"}
        res_offensetype = self.qradar_client.get("siem/offense_types", params)
        if len(res_offensetype) > 0:
            type = res_offensetype[0]["name"].rstrip()

        domain = ""
        params = {'fields' : "name", 'filter' : f"id='{res_offense[0]['domain_id']}'"}
        res_domain = self.qradar_client.get("config/domain_management/domains",params)
        if len(res_domain) > 0:
            domain = res_domain[0]['name']
        
        return Offense(
            id=offense_id,
            description=description,
            source=source,
            magnitude=magnitude,
            log_sources=log_sources,
            type=type,
            domain=domain
        )
    
    def create_issue(self, offense, project, issuetype):
        """
        Creates a JIRA issue using the offense data, project key, and issue type.

        Args:
            offense (Offense): Offense dataclass object.
            project (str): JIRA project key.
            issuetype (str): JIRA issue type.

        Returns:
            dict: JIRA issue response.
        """
        payload = {
            "fields": {
                "project": {"key": project},
                "summary": f"TEST - Security Incident on {offense.type} {offense.source} - {offense.id}",
                "description": f"Description:\n{offense.description}\nMagnitude: {offense.magnitude}\nDomain: {offense.domain}\nType: {offense.type}\nSource: {offense.source}",
                "issuetype": {"name": issuetype}
            }
        }
        res = self.jira_client.post("issue", data=payload)
        return res

def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    parser = argparse.ArgumentParser(description="Create a JIRA ticket from QRadar offense.")
    parser.add_argument("--offense-id", required=True, help="QRadar offense ID")
    parser.add_argument("--jira-project", required=True, help="Jira project ID")
    parser.add_argument("--jira-issue-type", required=True, help="Jira issue type")
    args = parser.parse_args()

    
    app = App()
    logging.info(f"Collecting offense info for offense id {args.offense_id}...")
    try:
        offense = app.get_offense(args.offense_id)
        logging.info(f"Offense info for offense id {args.offense_id} successfully collected")
    except Exception as e:
        logging.error(f"Failed to fetch offense: {e}")
        sys.exit(1)
    
    
    logging.info("Creating jira issue...")
    try:
        res = app.create_issue(offense, args.jira_project, args.jira_issue_type)
        if res and isinstance(res, dict) and "key" in res:
            logging.info(f"Jira issue {res['key']} successfully created.")
        else:
            logging.warning("JIRA issue was not created or response format is unexpected.")
    except Exception as e:
        logging.error(f"Failed to create jira issue: {e}")
        sys.exit(1)

if __name__ == "__main__":
    """
    Main function that handles argument parsing and orchestrates the offense-to-JIRA ticket creation flow.
    """
    main()
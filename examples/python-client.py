#!/usr/bin/env python3
"""
Vultrino Python Client Example

This script demonstrates how to use Vultrino's HTTP API from Python.
Requires: pip install requests
"""

import os
import requests
from typing import Optional

# Configuration
VULTRINO_URL = os.getenv("VULTRINO_URL", "http://127.0.0.1:7879")
VULTRINO_API_KEY = os.getenv("VULTRINO_API_KEY", "")


class VultrinoClient:
    """Simple Vultrino API client."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        })

    def health(self) -> dict:
        """Check server health."""
        response = requests.get(f"{self.base_url}/api/v1/health")
        response.raise_for_status()
        return response.json()

    def list_credentials(self) -> list:
        """List available credentials (filtered by API key scope)."""
        response = self.session.get(f"{self.base_url}/api/v1/credentials")
        response.raise_for_status()
        return response.json()["credentials"]

    def execute(
        self,
        credential: str,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[dict] = None,
        query: Optional[dict] = None
    ) -> dict:
        """Execute an authenticated HTTP request."""
        payload = {
            "credential": credential,
            "method": method,
            "url": url,
            "headers": headers or {},
            "query": query or {}
        }
        if body is not None:
            payload["body"] = body

        response = self.session.post(
            f"{self.base_url}/api/v1/execute",
            json=payload
        )
        response.raise_for_status()
        return response.json()


def main():
    # Check for API key
    if not VULTRINO_API_KEY:
        print("Error: Set VULTRINO_API_KEY environment variable")
        print("  export VULTRINO_API_KEY=vk_your_key_here")
        return

    # Create client
    client = VultrinoClient(VULTRINO_URL, VULTRINO_API_KEY)

    # Check health
    print("Checking Vultrino health...")
    health = client.health()
    print(f"  Status: {health['status']}")
    print(f"  Version: {health['version']}")
    print()

    # List credentials
    print("Available credentials:")
    credentials = client.list_credentials()
    for cred in credentials:
        print(f"  - {cred['alias']} ({cred['credential_type']})")
    print()

    # Example: Make an authenticated request
    if credentials:
        cred_alias = credentials[0]["alias"]
        print(f"Making request with credential '{cred_alias}'...")

        # Example: GitHub API request
        # Adjust URL based on your credential type
        try:
            result = client.execute(
                credential=cred_alias,
                method="GET",
                url="https://api.github.com/user"
            )
            print(f"  Status: {result['status']}")
            print(f"  Body preview: {result['body'][:200]}...")
        except requests.HTTPError as e:
            print(f"  Error: {e}")


if __name__ == "__main__":
    main()

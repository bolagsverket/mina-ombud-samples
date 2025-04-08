#
# Sample demonstrating using the API to request packages
# for archiving.
#
import json
import os
import sys
import uuid

import requests

from pathlib import Path
from minaombud import defaults


def sample():
    ### 1. Request API access token
    # The access token should be requested and reused for subsequent requests
    # until it expires at which point a new token must be requested.
    tredjeman = defaults.MINA_OMBUD_TREDJE_MAN
    client_id = defaults.MINA_OMBUD_API_CLIENT_ID
    client_secret = defaults.MINA_OMBUD_API_CLIENT_SECRET
    token_url = defaults.MINA_OMBUD_API_TOKEN_URL
    token_request = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "fullmakt:arkivering",
    }
    token_response = requests.post(token_url, token_request).json()
    access_token = token_response["access_token"]

    ### 2. Invoke API
    # List packages and then download each one.
    api_url = defaults.MINA_OMBUD_API_URL
    paket_url = f"{api_url}/tredjeman/{tredjeman}/arkivering/paket"
    headers = {
        "authorization": f"Bearer {access_token}",
        "x-service-name": "arkivering_sample",
        "x-request-id": str(uuid.uuid4()),
    }
    list_response = requests.get(paket_url, headers=headers)
    content_type = list_response.headers.get("content-type")
    if content_type == "application/json":
        list_response_json = list_response.json()
        print(json.dumps(list_response_json, indent=2))
        output_dir = "archive"
        for pkg in list_response_json["paket"]:
            pkg_id = pkg["id"]
            pkg_name = pkg["namn"]
            zip_dir = os.path.join(output_dir, pkg_name)
            zip_name = f"{pkg_id}.zip"
            Path(zip_dir).mkdir(parents=True, exist_ok=True)
            pkg_response = requests.get(f"{paket_url}/{pkg_id}", headers=headers)
            zip_path = os.path.join(zip_dir, zip_name)
            with open(zip_path, "wb") as f:
                f.write(pkg_response.content)
    else:
        for k, v in list_response.headers.items():
            print(f"{k}: {v}", file=sys.stderr)
        print(file=sys.stderr)
        print(list_response.text, file=sys.stderr)


if __name__ == "__main__":
    sample()

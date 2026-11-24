#!/usr/bin/env python3

import base64
from datetime import datetime, timedelta
import json
import os
from typing import Any

from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import dotenv
import requests

dotenv.load_dotenv()

hostname = os.environ["FMD_HOSTNAME"]
username = os.environ["FMD_USERNAME"]
password = os.environ["FMD_PASSWORD"]

allowed_age = timedelta(seconds=int(os.environ["FMD_ALLOWED_AGE_SECONDS"]))
healthcheck_url = os.environ["FMD_HEALTHCHECK_URL"]

session = requests.Session()


def request(method: str, route: str, data: Any = None, headers: Any = None) -> Any:
    resp = session.request(
        method,
        f"https://{hostname}/api/v2/{route}",
        json=data,
        headers=headers,
    )
    resp.raise_for_status()
    return resp.json()


username_hash = Hash.hash(SHA256(), username.encode())

salt_resp = request("GET", f"account/{username}/salt")
if salt_resp["protoVersion"] != 2:
    raise RuntimeError(f"Unexpected salt response: {salt_resp}")
password_salt = base64.b64decode(salt_resp["salt64"])

password_key = Argon2id(
    salt=password_salt,
    length=32,
    iterations=1,
    lanes=4,
    memory_cost=131072,
).derive(b"fmd_v2_password" + username_hash + password.encode())

auth_key = HKDF(
    SHA256(), length=32, salt=None, info=b"fmd_v2_auth" + username_hash
).derive(password_key)

auth_resp = request(
    "POST",
    "account/login",
    data={
        "username": username,
        "passwordHash64": base64.b64encode(auth_key).decode(),
        "sessionDurationSeconds": 60,
    },
)

access_token = auth_resp["accessToken"]

locations_resp = request(
    "GET",
    "data/location",
    headers={
        "authorization": f"Bearer {access_token}",
    },
)

last_update_time = datetime.fromtimestamp(
    max(item["unixMillis"] for item in locations_resp["items"]) / 1000
)
last_update_age = datetime.now() - last_update_time

if last_update_age > allowed_age:
    raise RuntimeError(f"Most recent health check was {last_update_age} ago")

session.get(healthcheck_url).raise_for_status()

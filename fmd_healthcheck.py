#!/usr/bin/env python3

import base64
from datetime import datetime, timedelta
import json
import os

from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import dotenv
import requests

dotenv.load_dotenv()

hostname = os.environ["FMD_HOSTNAME"]
username = os.environ["FMD_USERNAME"]
password = os.environ["FMD_PASSWORD"]

allowed_age = timedelta(seconds=int(os.environ["FMD_ALLOWED_AGE_SECONDS"]))
healthcheck_url = os.environ["FMD_HEALTHCHECK_URL"]

session = requests.Session()


def request(method: str, route: str, idt: str, data: str = "unused") -> str:
    resp = session.request(
        method,
        f"https://{hostname}/api/v1/{route}",
        json={
            "Data": data,
            "IDT": idt,
        },
    )
    resp.raise_for_status()
    return resp.json()["Data"]


def base64_decode(data: str) -> bytes:
    return base64.b64decode(data + "==")


password_salt = base64_decode(request("PUT", "salt", username))

authentication_kdf = Argon2id(
    salt=password_salt,
    length=32,
    iterations=1,
    lanes=4,
    memory_cost=131072,
)

authentication_symmetric_key = authentication_kdf.derive_phc_encoded(
    b"context:loginAuthentication" + password.encode()
)

session_token = request(
    "put",
    "requestAccess",
    username,
    authentication_symmetric_key,
)

encrypted_private_key = base64.b64decode(request("PUT", "key", session_token))

private_key_salt = encrypted_private_key[:16]
private_key_iv = encrypted_private_key[16:28]
private_key_ciphertext = encrypted_private_key[28:]

decryption_kdf = Argon2id(
    salt=private_key_salt,
    length=32,
    iterations=1,
    lanes=4,
    memory_cost=131072,
)

decryption_symmetric_key = decryption_kdf.derive(
    b"context:asymmetricKeyWrap" + password.encode()
)

private_key = load_pem_private_key(
    AESGCM(decryption_symmetric_key).decrypt(
        private_key_iv, private_key_ciphertext, associated_data=None
    ),
    password=None,
)
assert isinstance(private_key, RSAPrivateKey)

location_size = int(request("PUT", "locationDataSize", session_token))

encrypted_location = base64_decode(
    request("put", "location", session_token, str(location_size - 1))
)

encrypted_location_key = encrypted_location[:384]
location_iv = encrypted_location[384:396]
location_ciphertext = encrypted_location[396:]

location_key = private_key.decrypt(
    encrypted_location_key, OAEP(MGF1(SHA256()), SHA256(), label=None)
)

location = json.loads(
    AESGCM(location_key).decrypt(location_iv, location_ciphertext, associated_data=None)
)

# https://gitlab.com/fmd-foss/fmd-android/-/blob/81d8f1550f587b75488e0edf10e0ee48e65e0fc0/app/src/main/java/de/nulide/findmydevice/net/FMDServerApiRepository.kt#L649
# https://docs.oracle.com/javase/8/docs/api/java/util/Date.html#toString--
last_update_time = datetime.strptime(location["time"], "%a %b %d %H:%M:%S %Z %Y")
last_update_age = datetime.now() - last_update_time

if last_update_age > allowed_age:
    raise RuntimeError(f"Most recent health check was {last_update_age} ago")

session.get(healthcheck_url).raise_for_status()

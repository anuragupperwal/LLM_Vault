from jose import jwt
from jose.exceptions import JWTError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests
import base64

# Auth0 config
AUTH0_DOMAIN = "dev-r742tubun7igvzc2.us.auth0.com"
API_AUDIENCE = "https://llm.api"
ALGORITHMS = ["RS256"]

# Bearer token scheme
auth_scheme = HTTPBearer()

# Fetch JWKS once at startup
jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
jwks = requests.get(jwks_url).json()

def get_public_key(token):
    try:
        unverified_header = jwt.get_unverified_header(token)
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                n = int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=="), "big")
                e = int.from_bytes(base64.urlsafe_b64decode(key["e"] + "=="), "big")
                public_numbers = rsa.RSAPublicNumbers(e, n)
                public_key = public_numbers.public_key(default_backend())
                return public_key
    except Exception:
        raise HTTPException(status_code=401, detail="Unable to parse public key")
    raise HTTPException(status_code=401, detail="Public key not found.")

def verify_token(token: str):
    try:
        key = get_public_key(token)
        payload = jwt.decode(
            token,
            key=key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/"
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# FastAPI dependency
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    return verify_token(credentials.credentials)

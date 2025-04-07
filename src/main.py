import jwt
import requests
from jwt.algorithms import RSAAlgorithm
from fastapi import FastAPI, HTTPException, Request, Depends
import logging

app = FastAPI()

KEYCLOAK_CLIENT_ID="fastapi-client"
KEYCLOAK_CLIENT_SECRET="85N066Xagyzks9a6UWPnk1damixeVWnx"

KEYCLOAK_CERTS_URL = "http://keycloak-server:8080/realms/myrealm/protocol/openid-connect/certs"
KEYCLOAK_TOKEN_URL = "http://keycloak-server:8080/realms/myrealm/protocol/openid-connect/token"

logging.basicConfig(level=logging.DEBUG)

def get_key_from_certs(keys, kid):
    for key in keys:
        if key["kid"] == kid:
            return RSAAlgorithm.from_jwk(key)
    return None

def verify_keycloak_token(request: Request) -> dict:
    token = request.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token missing or invalid")

    token = token[len("Bearer "):]

    response = requests.get(KEYCLOAK_CERTS_URL)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Failed to fetch Keycloak public keys")
    
    keys = response.json().get("keys")
    if not keys:
        raise HTTPException(status_code=401, detail="No keys found in Keycloak certs response")
    
    try:
        decoded_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Error decoding JWT header: {str(e)}")

    kid = decoded_header.get("kid")

    public_key = get_key_from_certs(keys, kid)
    if not public_key:
        raise HTTPException(status_code=401, detail="Unable to find public key for the token")

    try:
        # needed to add Audience mapper in Keycloak with KEYCLOAK_CLIENT_ID as custom audience
        decoded_token = jwt.decode(token, public_key, algorithms=["RS256"], audience=KEYCLOAK_CLIENT_ID)
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=401, detail="Invalid audience in token")

    return decoded_token

@app.get("/protected")
async def protected(token_info: dict = Depends(verify_keycloak_token)):
    return {"token_info": token_info}

@app.get("/unprotected")
async def unprotected():
    return {"message": "unprotected endpoint"}

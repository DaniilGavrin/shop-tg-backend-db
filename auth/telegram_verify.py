import os
import json
import hashlib
import hmac
from urllib.parse import parse_qsl
import requests
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError

BOT_TOKEN = os.getenv("BOT_TOKEN")
TG_BOT_ID = BOT_TOKEN.split(':')[0] if BOT_TOKEN else None

def verify_telegram_webapp(init_data: str) -> dict | None:
    """Криптографически проверяет initData от Telegram Mini App."""
    try:
        parsed_data = dict(parse_qsl(init_data))
        received_hash = parsed_data.pop("hash", None)
        
        if not received_hash:
            return None
        
        data_check_string = "\n".join(
            f"{k}={v}"
            for k, v in sorted(parsed_data.items())
        )
        
        secret_key = hmac.new(
            b"WebAppData",
            BOT_TOKEN.encode(),
            hashlib.sha256
        ).digest()
        
        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(calculated_hash, received_hash):
            return None
        
        user_data = json.loads(parsed_data.get("user", "{}"))
        return user_data
        
    except Exception as e:
        print(f"[TELEGRAM VERIFY ERROR] {e}")
        return None


def verify_telegram_oidc(id_token: str) -> dict | None:
    """
    Проверяет id_token от Telegram Login Widget (OIDC).
    Использует стандартный JWKS endpoint Telegram.
    """
    try:
        jwks_url = "https://oauth.telegram.org/.well-known/jwks.json"
        print(f"[OIDC] Fetching JWKS from: {jwks_url}")
        
        jwks_response = requests.get(jwks_url, timeout=5)
        print(f"[OIDC] JWKS Response Status: {jwks_response.status_code}")
        print(f"[OIDC] JWKS Response Text: {jwks_response.text[:200]}")
        
        if jwks_response.status_code != 200:
            print(f"[OIDC ERROR] Failed to fetch JWKS: {jwks_response.status_code}")
            jwks_url = "https://oauth.telegram.org/.well-known/openid-configuration"
            jwks_response = requests.get(jwks_url, timeout=5)
            if jwks_response.status_code == 200:
                config = jwks_response.json()
                jwks_url = config.get("jwks_uri")
                jwks_response = requests.get(jwks_url, timeout=5)
        
        jwks_response.raise_for_status()
        jwks_data = jwks_response.json()
        print(f"[OIDC] JWKS Keys: {len(jwks_data.get('keys', []))}")
        
        # 2. Декодируем заголовок токена для получения kid
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get("kid")
        print(f"[OIDC] Token kid: {kid}")
        
        if not kid:
            print("[OIDC ERROR] No kid in token header")
            return None
        
        public_key_pem = None
        for key_data in jwks_data.get("keys", []):
            if key_data.get("kid") == kid:
                # Конвертируем JWK dict в PEM строку
                public_key_pem = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
                break

        if not public_key_pem:
            print(f"[OIDC ERROR] Key with kid={kid} not found in JWKS")
            return None

        payload = jwt.decode(
            id_token,
            public_key_pem,  # ✅ Теперь это PEM строка
            algorithms=["RS256"],
            audience=TG_BOT_ID,
            issuer="https://oauth.telegram.org"
        )
        
        print(f"[OIDC] Token payload: {payload}")

        tg_id = payload.get("id") or payload.get("sub")
        
        return {
            "id": int(tg_id),
            "first_name": payload.get("given_name", payload.get("first_name", "User")),
            "last_name": payload.get("family_name", payload.get("last_name", "")),
            "username": payload.get("preferred_username", ""),
            "photo_url": payload.get("picture", ""),
            "phone": payload.get("phone_number", "")
        }
        
    except ExpiredSignatureError:
        print("[OIDC ERROR] Token expired")
        return None
    except JWTError as e:
        print(f"[OIDC ERROR] JWT validation failed: {e}")
        return None
    except Exception as e:
        print(f"[OIDC ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return None
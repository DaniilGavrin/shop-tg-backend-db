# auth/telegram_verify.py
import os
import json
import hashlib
import hmac
from urllib.parse import parse_qsl
import requests
from jose import jwt, jwk
from jose.exceptions import JWTError, ExpiredSignatureError

BOT_TOKEN = os.getenv("BOT_TOKEN")
TG_CLIENT_ID = os.getenv("NEXT_PUBLIC_TG_CLIENT_ID")

def verify_telegram_webapp(init_data: str) -> dict | None:
    """
    Криптографически проверяет initData от Telegram Mini App.
    Возвращает данные пользователя или None.
    """
    try:
        parsed_data = dict(parse_qsl(init_data))
        received_hash = parsed_data.pop("hash", None)
        
        if not received_hash:
            return None
        
        # Формируем строку для проверки
        data_check_string = "\n".join(
            f"{k}={v}"
            for k, v in sorted(parsed_data.items())
        )
        
        # Вычисляем HMAC-SHA256
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
        
        # Сравниваем хэши (timing-safe)
        if not hmac.compare_digest(calculated_hash, received_hash):
            return None
        
        # Парсим данные пользователя
        user_data = json.loads(parsed_data.get("user", "{}"))
        return user_data
        
    except Exception as e:
        print(f"[TELEGRAM VERIFY ERROR] {e}")
        return None


def verify_telegram_oidc(id_token: str) -> dict | None:
    """
    Проверяет id_token от Telegram Login Widget (OIDC).
    Использует python-jose для проверки JWKS.
    """
    try:
        # 1. Получаем публичные ключи Telegram
        jwks_url = "https://oauth.telegram.org/auth/getkeys"
        jwks_response = requests.get(jwks_url, timeout=5)
        jwks_response.raise_for_status()
        jwks_data = jwks_response.json()
        
        # 2. Декодируем заголовок токена для получения kid (key ID)
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get("kid")
        
        if not kid:
            print("[OIDC ERROR] No kid in token header")
            return None
        
        # 3. Находим нужный ключ в JWKS
        public_key = None
        for key_data in jwks_data.get("keys", []):
            if key_data.get("kid") == kid:
                # python-jose может работать с JWK dict напрямую!
                public_key = key_data
                break
        
        if not public_key:
            print(f"[OIDC ERROR] Key with kid={kid} not found in JWKS")
            return None
        
        # 4. Проверяем подпись и claims
        # python-jose принимает JWK dict напрямую в jwt.decode!
        payload = jwt.decode(
            id_token,
            public_key,  # Передаём dict с JWK данными
            algorithms=["RS256"],
            audience=TG_CLIENT_ID,
            issuer="https://oauth.telegram.org"
        )
        
        # 5. Извлекаем данные пользователя
        return {
            "id": int(payload.get("sub")),
            "first_name": payload.get("given_name", payload.get("first_name", "User")),
            "last_name": payload.get("family_name", payload.get("last_name", "")),
            "username": payload.get("preferred_username", ""),
            "photo_url": payload.get("picture", ""),
            "phone": payload.get("phone", "")
        }
        
    except ExpiredSignatureError:
        print("[OIDC ERROR] Token expired")
        return None
    except JWTError as e:
        print(f"[OIDC ERROR] JWT validation failed: {e}")
        return None
    except Exception as e:
        print(f"[OIDC ERROR] Unexpected error: {e}")
        return None
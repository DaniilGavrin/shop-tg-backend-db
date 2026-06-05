import os
from upstash_redis import Redis

# Upstash Redis для хранения refresh tokens
redis_client = Redis(
    url=os.getenv("shop_KV_REST_API_URL"),
    token=os.getenv("shop_KV_REST_API_TOKEN")
)

# Константы для сессий
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30
REFRESH_TOKEN_EXPIRE_SECONDS = REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60

def store_refresh_token(tg_id: int, refresh_token: str):
    """Сохраняет refresh token в Redis с привязкой к tg_id"""
    key = f"refresh:{refresh_token}"
    redis_client.set(key, str(tg_id), ex=REFRESH_TOKEN_EXPIRE_SECONDS)
    
    # Также храним обратную ссылку для возможности отзыва всех сессий пользователя
    session_key = f"session:{tg_id}"
    redis_client.set(session_key, refresh_token, ex=REFRESH_TOKEN_EXPIRE_SECONDS)

def get_tg_id_by_refresh_token(refresh_token: str) -> int | None:
    """Получает tg_id по refresh token"""
    key = f"refresh:{refresh_token}"
    tg_id = redis_client.get(key)
    return int(tg_id) if tg_id else None

def revoke_refresh_token(refresh_token: str):
    """Отзывает конкретный refresh token"""
    key = f"refresh:{refresh_token}"
    redis_client.delete(key)

def revoke_all_user_sessions(tg_id: int):
    """Отзывает все сессии пользователя (мгновенный бан/logout)"""
    session_key = f"session:{tg_id}"
    refresh_token = redis_client.get(session_key)
    if refresh_token:
        redis_client.delete(f"refresh:{refresh_token}")
        redis_client.delete(session_key)
# main.py
import os
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from database.db import db
from database.catalog_repository import catalog_repo
from models import TelegramUserVerify, TelegramWebAppAuth, TelegramOIDCAuth
from auth.jwt_utils import create_access_token, create_refresh_token, verify_access_token
from auth.redis_client import (
    store_refresh_token, 
    get_tg_id_by_refresh_token, 
    revoke_refresh_token,
    revoke_all_user_sessions
)
from auth.telegram_verify import verify_telegram_webapp, verify_telegram_oidc
from auth.dependencies import get_current_user, get_optional_user

from dotenv import load_dotenv

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    yield
    await db.disconnect()

app = FastAPI(lifespan=lifespan)

# CORS для cross-domain cookies
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://shop.bytewizard.ru",  # Для локальной разработки
    ],
    allow_credentials=True,  # ВАЖНО для cookies!
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# PUBLIC ROUTES (каталог доступен всем)
# ============================================

@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "FastAPI Telegram Backend Running"
    }

@app.get("/catalog")
async def catalog_get():
    return {
        "items": await catalog_repo.get_catalog()
    }

@app.get("/catalog/featured")
async def catalog_featured_get():
    return {
        "items": await catalog_repo.get_featured_catalog()
    }

@app.get("/catalog/{item_id}")
async def catalog_item_get(item_id: int):
    item = await catalog_repo.get_catalog_item(item_id)
    
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    if item.get("metadata"):
        item["metadata"] = json.loads(item["metadata"])
    
    return {"item": item}

# ============================================
# AUTH ROUTES (авторизация)
# ============================================

def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    """Устанавливает HttpOnly cookies для токенов"""
    # Access Token (15 минут)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,  # Только HTTPS
        samesite="none",  # Для cross-domain cookies
        max_age=15 * 60,  # 15 минут
        path="/",
        domain=".bytewizard.ru"
    )
    
    # Refresh Token (30 дней)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=30 * 24 * 60 * 60,  # 30 дней
        path="/",
        domain=".bytewizard.ru"
    )

@app.post("/auth/telegram/webapp")
async def telegram_webapp_auth(data: TelegramWebAppAuth, response: Response):
    """Авторизация через Telegram Mini App (initData)"""
    user_data = verify_telegram_webapp(data.init_data)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid Telegram auth")
    
    tg_id = int(user_data["id"])
    username = user_data.get("username")
    photo_url=user_data.get("photo_url")
    
    # Создаем токены
    access_token = create_access_token(tg_id, username)
    refresh_token = create_refresh_token()
    
    # Сохраняем refresh token в Redis
    store_refresh_token(tg_id, refresh_token)
    
    # Устанавливаем cookies
    set_auth_cookies(response, access_token, refresh_token)
    
    return {
        "success": True,
        "user": {
            "id": tg_id,
            "first_name": user_data.get("first_name"),
            "last_name": user_data.get("last_name"),
            "username": username,
            "photo_url": user_data.get("photo_url")
        }
    }

@app.post("/auth/telegram/oidc")
async def telegram_oidc_auth(data: TelegramOIDCAuth, response: Response):
    """Авторизация через Telegram Login Widget (OIDC id_token)"""
    try:
        print("[OIDC AUTH] Step 1: Verifying token...")
        user_data = verify_telegram_oidc(data.id_token)
        
        if not user_data:
            print("[OIDC AUTH] Token verification failed")
            raise HTTPException(status_code=401, detail="Invalid Telegram OIDC token")
        
        print(f"[OIDC AUTH] Step 2: Token verified, user_id={user_data['id']}")
        
        tg_id = user_data["id"]
        username = user_data.get("username")
        
        print("[OIDC AUTH] Step 3: Upserting user to database...")
        await db.upsert_telegram_user(
            tg_id=tg_id,
            first_name=user_data.get("first_name"),
            username=username,
            last_name=user_data.get("last_name"),
            phone=user_data.get("phone"),
            photo_url=user_data.get("photo_url")
        )
        print("[OIDC AUTH] Step 4: User upserted successfully")
        
        print("[OIDC AUTH] Step 5: Creating tokens...")
        access_token = create_access_token(tg_id, username)
        refresh_token = create_refresh_token()
        print("[OIDC AUTH] Step 6: Tokens created")
        
        print("[OIDC AUTH] Step 7: Storing refresh token in Redis...")
        store_refresh_token(tg_id, refresh_token)
        print("[OIDC AUTH] Step 8: Refresh token stored")
        
        print("[OIDC AUTH] Step 9: Setting cookies...")
        set_auth_cookies(response, access_token, refresh_token)
        print("[OIDC AUTH] Step 10: Cookies set")
        
        print("[OIDC AUTH] Step 11: Returning response")
        return {
            "success": True,
            "user": user_data
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[OIDC AUTH ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/refresh")
async def refresh_access_token(
    response: Response,
    refresh_token: Optional[str] = Cookie(None)
):
    """Обновление access token через refresh token"""
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token missing")
    
    # Проверяем refresh token в Redis
    tg_id = get_tg_id_by_refresh_token(refresh_token)
    
    if not tg_id:
        # Токен недействителен или истек
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # Получаем данные пользователя из БД для username
    user = await db.get_user_by_tg_id(tg_id)
    username = user.get("username") if user else None
    
    # Создаем новый access token
    new_access_token = create_access_token(tg_id, username)
    
    # Обновляем cookie
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=15 * 60,
        path="/",
        domain=".bytewizard.ru"
    )
    
    return {
        "success": True,
        "message": "Token refreshed"
    }

@app.post("/auth/logout")
async def logout(
    response: Response,
    refresh_token: Optional[str] = Cookie(None)
):
    """Выход из системы (отзыв refresh token)"""
    if refresh_token:
        revoke_refresh_token(refresh_token)
    
    # Удаляем cookies
    response.delete_cookie("access_token", path="/", domain=".bytewizard.ru")
    response.delete_cookie("refresh_token", path="/", domain=".bytewizard.ru")
    
    return {
        "success": True,
        "message": "Logged out"
    }

# ============================================
# PROTECTED ROUTES (требуют авторизации)
# ============================================

@app.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    # Получаем полные данные пользователя из БД
    user_data = await db.get_user_by_tg_id(current_user["tg_id"])
    
    return {
        "authorized": True,
        "user": {
            "tg_id": current_user["tg_id"],
            "username": current_user["username"],
            "first_name": user_data.get("first_name") if user_data else "User",
            "last_name": user_data.get("last_name") if user_data else "",
            "photo_url": user_data.get("photo_url") if user_data else "",
        }
    }

@app.post("/users/verify")
async def verify_telegram_user(
    user: TelegramUserVerify,
    current_user: dict = Depends(get_current_user)
):
    """
    Обновление данных пользователя в БД.
    Требует авторизации (защита от подделки tg_id).
    """
    if current_user["tg_id"] != user.tg_id:
        raise HTTPException(
            status_code=403,
            detail="Cannot update another user's data"
        )
    
    try:
        await db.upsert_telegram_user(
            tg_id=user.tg_id,
            first_name=user.first_name,
            username=user.username,
            last_name=user.last_name,
            phone=user.phone
        )
        
        return {
            "ok": True,
            "user": {
                "id": user.tg_id,
                "first_name": user.first_name,
                "username": user.username,
                "phone": user.phone
            }
        }
    except Exception as e:
        print("UPSERT ERROR:", e)
        raise HTTPException(status_code=500, detail=str(e))

# ============================================
# ADMIN ROUTES (требуют авторизации)
# ============================================

@app.get("/admin/catalog")
async def admin_catalog_get(current_user: dict = Depends(get_current_user)):
    """Админский доступ к каталогу (требует авторизации)"""
    # TODO: Добавить проверку роли администратора
    return {
        "items": await catalog_repo.admin_get_catalog()
    }
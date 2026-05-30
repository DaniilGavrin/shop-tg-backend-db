import os
import json
import time
import hashlib
import hmac

from urllib.parse import parse_qsl

import jwt

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from database.db import db
from database.catalog_repository import catalog_repo
from models import TelegramUserVerify
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
JWT_SECRET = os.getenv("JWT_SECRET")
DATABASE_URL = os.getenv("DATABASE_URL")

@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    yield
    await db.disconnect()

app = FastAPI(lifespan=lifespan)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_telegram_webapp(init_data: str):
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

    if not hmac.compare_digest(
        calculated_hash,
        received_hash
    ):
        return None

    user_data = json.loads(parsed_data["user"])

    return user_data


def create_jwt(user_data: dict):
    payload = {
        "user_id": user_data["id"],
        "username": user_data.get("username"),
        "exp": int(time.time()) + (60 * 60 * 24 * 7)
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )


def verify_jwt(token: str):
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )
    except:
        return None


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

@app.get("/admin/catalog")
async def admin_catalog_get():
    return {
        "items": await catalog_repo.admin_get_catalog()
    }

@app.get("/catalog/{item_id}")
async def catalog_item_get(item_id: int):

    item = await catalog_repo.get_catalog_item(item_id)

    if not item:
        raise HTTPException(
            status_code=404,
            detail="Item not found"
        )

    if item.get("metadata"):
        item["metadata"] = json.loads(item["metadata"])

    return {
        "item": item
    }

@app.post("/auth/telegram/webapp")
async def telegram_webapp_auth(data: dict):

    init_data = data.get("init_data")

    if not init_data:
        raise HTTPException(
            status_code=400,
            detail="init_data missing"
        )

    user_data = verify_telegram_webapp(init_data)

    if not user_data:
        raise HTTPException(
            status_code=401,
            detail="Invalid Telegram auth"
        )

    token = create_jwt(user_data)

    return {
        "success": True,
        "token": token,
        "user": user_data
    }


@app.get("/me")
async def me(authorization: str = Header(None)):

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing token"
        )

    try:
        scheme, token = authorization.split(" ")
    except:
        raise HTTPException(
            status_code=401,
            detail="Invalid auth header"
        )

    payload = verify_jwt(token)

    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )

    return {
        "authorized": True,
        "payload": payload
    }


@app.post("/users/verify")
async def verify_telegram_user(user: TelegramUserVerify):
    """
    Принимает данные от виджета Телеграма и делает UPSERT в БД.
    Возвращает актуального юзера.
    """
    try:
        # 🔹 Вызываем метод БД (код ниже)
        await db.upsert_telegram_user(
            tg_id=user.tg_id,
            first_name=user.first_name,
            username=user.username,
            last_name=user.last_name,
            phone=user.phone,
            photo_url=user.photo_url
        )

        # 🔹 Возвращаем фронтенду подтверждение
        return {
            "ok": True,
            "user": {
                "id": user.tg_id,
                "first_name": user.first_name,
                "username": user.username,
                "phone": user.phone,  # Можно вернуть, если нужно показать в профиле
            }
        }
    except Exception as e:
        # Логируем ошибку, но не светим детали наружу
        raise HTTPException(status_code=500, detail="Database error")
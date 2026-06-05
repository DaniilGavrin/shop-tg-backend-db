from pydantic import BaseModel, Field

class TelegramUserVerify(BaseModel):
    tg_id: int = Field(..., gt=0)
    first_name: str = Field(..., min_length=1)
    username: str | None = None
    last_name: str | None = None
    phone: str | None = None
    photo_url: str | None = None
    id_token: str | None = None

class TelegramWebAppAuth(BaseModel):
    init_data: str = Field(..., min_length=1)

class TelegramOIDCAuth(BaseModel):
    id_token: str = Field(..., min_length=1)

class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=1)
from pydantic import BaseModel, Field

class TelegramUserVerify(BaseModel):
    tg_id: int = Field(..., gt=0)           # REQUIRED
    first_name: str = Field(..., min_length=1) # REQUIRED
    username: str | None = None
    last_name: str | None = None
    phone: str | None = None
    photo_url: str | None = None
    id_token: str | None = None  # Опционально для проверки
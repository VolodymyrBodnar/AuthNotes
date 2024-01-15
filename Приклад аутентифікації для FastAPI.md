Ось простий приклад авторизації за допомогою логіна та паролю у FastAPI. Ми будемо зберігати дані користувачів у пам'яті програми (не використовуючи базу даних).

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

# Простий словник для зберігання даних користувачів (не використовуйте такий підхід у реальному проекті)
users_db = {
    "user1": {
        "username": "user1",
        "password": "password1"
    },
    "user2": {
        "username": "user2",
        "password": "password2"
    }
}

class UserCreate(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password


def get_user(username: str):
    if username in users_db:
        user_dict = users_db[username]
        return User(**user_dict)

def create_access_token(data: dict):
    token_data = {
        "sub": str(data["username"]),
    }
    return token_data

# Маркери для авторизації та отримання даних користувача
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/register/", response_model=User)
async def register(user: UserCreate):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Користувач з таким іменем вже існує")
    
    # В реальному проекті потрібно безпечно зберігати паролі (хешування)
    users_db[user.username] = {
        "username": user.username,
        "password": user.password
    }
    
    return User(**user.dict())

@app.post("/token/", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if user is None or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неправильний логін або пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token({"username": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/protected-resource/", response_model=User)
async def protected_resource(current_user: User = Depends(get_current_user)):
    return current_user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = get_user(token.get("sub"))
    if user is None:
        raise HTTPException(status_code=401, detail="Недійсний токен")
    return user

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
```

У цьому прикладі ми використовуємо базовий підхід до авторизації без додаткових бібліотек. Зберігайте паролі користувачів у безпечному вигляді (хешовані) в реальному проекті, оскільки в цьому прикладі ми їх зберігаємо у простому словнику.
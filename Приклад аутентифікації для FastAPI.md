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

# Обмеження доступу по ролям
Реалізація різних ролей та рівнів доступу в вашому додатку може бути досягнута за допомогою механізму ролей та прав доступу. У вас може бути кілька ролей, таких як адміністратори, звичайні користувачі та інші, і кожна роль може мати свої дозволи на доступ до різних функцій вашого додатку.

Ось кроки для створення ролей та реалізації різних рівнів доступу:

1. **Створення ролей в додатку:**

   Визначте список можливих ролей, які існують в вашому додатку. Наприклад, "Адміністратор", "Модератор", "Звичайний користувач".

2. **Налаштування ролей в Google API (для випадку з [[SSO]]):**

   Ви можете використовувати ролі Google для надання різних рівнів доступу. Перейдіть до [Google Cloud Console](https://console.cloud.google.com/), оберіть ваш проект, та у розділі "IAM та адміністрування" надайте ролі вашим користувачам або сервісним обліковим записам.

3. **Реалізація контролю доступу в додатку:**

   У вашому FastAPI додатку визначте функції-декоратори, які будуть використовуватися для перевірки прав доступу користувачів. Ось приклад:

   ```python
   from fastapi import FastAPI, Depends, HTTPException
   from functools import wraps
   
   app = FastAPI()
   
   # Ролі користувачів (за замовчуванням всі користувачі мають роль "user")
   USER_ROLES = {
       "admin": ["admin"],
       "moderator": ["admin", "moderator"],
   }
   
   # Функція для перевірки ролі користувача
   def check_role(role):
       def decorator(func):
           @wraps(func)
           def wrapper(*args, **kwargs):
               # Отримання ролі користувача (ваша реалізація)
               user_role = get_user_role()  # Наприклад, отримуємо роль з JWT токену або бази даних
               if user_role not in USER_ROLES.get(role, []):
                   raise HTTPException(status_code=403, detail="Access denied")
               return func(*args, **kwargs)
           return wrapper
       return decorator
   
   # Приклад використання декоратора для захищеного маршруту
   @app.get("/admin")
   @check_role("admin")
   async def admin_route():
       return {"message": "Admin access granted"}
   ```

   У цьому прикладі визначається функція `check_role`, яка перевіряє, чи має користувач необхідну роль для доступу до конкретного маршруту. За допомогою декоратора `@check_role`, ви можете застосовувати цю перевірку до різних маршрутів у вашому додатку.

Це загальний підхід до реалізації ролей та рівнів доступу у FastAPI додатку. Вам слід адаптувати його до своїх потреб та реалізації контролю доступу.

## Перевірка ролей за допомогою Depends

Також популярний підхід, коли ви вказуєте тип користувача (наприклад, `AdminUser` або `ManagerUser`) як аргумент функції ендпоінта, і за допомогою цього тайпхінту перевіряєте рівень доступу. Ось приклад цього підходу:

```python
from fastapi import FastAPI, Depends, HTTPException
from enum import Enum

app = FastAPI()

# Визначаємо можливі ролі як перелік
class UserRole(str, Enum):
    admin = "admin"
    manager = "manager"
    user = "user"

# Клас користувача з вказаним рівнем доступу
class User:
    def __init__(self, username: str, role: UserRole):
        self.username = username
        self.role = role

# Функція, яка повертає імітованого користувача
def get_user(username: str):
    # Реалізуйте логіку отримання користувача з бази даних або іншим способом
    # У цьому прикладі ми повертаємо користувача з фіксованою роллю "admin"
    return User(username=username, role=UserRole.admin)

# Перевірка ролі користувача для адміністратора
def check_admin(user: User = Depends(get_user)):
    if user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Admin access denied")

# Перевірка ролі користувача для менеджера
def check_manager(user: User = Depends(get_user)):
    if user.role != UserRole.manager:
        raise HTTPException(status_code=403, detail="Manager access denied")

# Захищений маршрут для адміністратора
@app.get("/admin")
async def admin_route(user: User = Depends(check_admin)):
    return {"message": "Admin access granted"}

# Захищений маршрут для менеджера
@app.get("/manager")
async def manager_route(user: User = Depends(check_manager)):
    return {"message": "Manager access granted"}

# Захищений маршрут для звичайного користувача
@app.get("/user")
async def user_route(user: User):
    return {"message": "User access granted"}
```

У цьому прикладі ми використовуємо тайпхінт `user: User` для кожного ендпоінта, і за допомогою Dependency Injection ми отримуємо інформацію про користувача та перевіряємо його рівень доступу відповідно до ролі. Функції `check_admin` та `check_manager` використовуються для перевірки ролі користувача.

Також рекомендую глянути ось цей варіант з використнням анотацій:
https://intility.github.io/fastapi-azure-auth/usage-and-faq/locking_down_on_roles
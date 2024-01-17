SSO - це метод, за допомогою якого користувач може увійти до кількох різних систем або служб, використовуючи один і той же набір авторизаційних даних, таких як ім'я користувача і пароль. Замість того, щоб вводити ці дані для кожної окремої системи, користувач авторизується лише один раз і має доступ до всіх інтегрованих додатків або ресурсів без повторного введення авторизаційних даних.

SSO використовується для полегшення роботи користувачів і підвищення безпеки, оскільки вони можуть керувати доступом до своїх облікових записів усередині одного централізованого механізму авторизації. Це також допомагає зменшити необхідність управління багатьма паролями для різних систем, що полегшує життя як користувачам, так і адміністраторам систем.



## How to use Google SSO in your (FastAPI) application

1. Create a Google Project:
   - Go to the Google Developer Console (https://console.developers.google.com/).
   - Create a new project or select an existing one where you want to set up SSO.

2. Configure OAuth 2.0:
   - From the "APIs & Services" menu, select "Credentials."
   - Click on "Create credentials" and choose the "Web application" option.
   - Enter your application's name and add a list of authorized URLs where SSO authentication will be available.

3. Obtain the Client ID:
   - After creating OAuth 2.0 credentials, you'll receive a Client ID and a Client Secret. Keep them secure, as you'll need them to configure your FastAPI application.

4. Configure your FastAPI Application:
   - Add the Google authentication library to your FastAPI application. For Python, it's recommended to use the `oauthlib` library or another library that supports OAuth 2.0.
   - Use the Client ID and Client Secret obtained from Google to configure authentication in your FastAPI application. Implement the ability for users to authenticate via Google SSSO.
   - Ensure that you handle and store the user identifiers received from Google for further use within your application.

5. Testing:
   - Make sure that the Google SSO authentication works correctly in your FastAPI application, allowing users to log in and access your application's functionality.

6. Protection Against Unauthorized Access:
   - Ensure that your FastAPI application has proper security mechanisms in place to protect user information and personal data.

This is a general guide on setting up Google SSO in your FastAPI application. Specific details and implementation may vary depending on the programming language and framework you are using.

### Блок 1: Змінні для налаштування

```python
# Replace with your actual Google OAuth 2.0 credentials
GOOGLE_CLIENT_ID = "YOUR_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "YOUR_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:8000/auth/google/callback"  # Update with your callback URL

# Secret key for signing JWT tokens
SECRET_KEY = "YOUR_SECRET_KEY"
ALGORITHM = "HS256"
```

У цьому блоку визначаються імпорти та глобальні налаштування, такі як клієнтські ідентифікатори та секрети, секретний ключ для підпису JWT токенів.

### Блок 2: Схеми даних

```python
# User model (replace with your actual user model)
class User(BaseModel):
    username: str
    email: str

# JWT Token model
class Token(BaseModel):
    access_token: str
    token_type: str
```

У цьому блоку визначаються структури даних за допомогою Pydantic моделей. Модель `User` визначає структуру користувача, а модель `Token` - структуру JWT токену.

### Блок 3: Функції для створення та перевірки JWT токенів

```python
# Generate JWT token for a user
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
```

У цьому блоку визначається функція `create_access_token`, яка генерує JWT токен на основі користувацьких даних та часу дії токену.

### Блок 4: Маршрути для авторизації

```python
  

def get_google_sso() -> GoogleSSO:

return GoogleSSO(GSSO_CLIENT_ID, GSSO_CLIENT_SECRET, redirect_uri=REDIRECT_URI)

  
  
  

@app.get("/auth/google")

async def login_with_google():

google_auth_url = f"https://accounts.google.com/o/oauth2/auth?client_id={urllib.parse.quote(GSSO_CLIENT_ID)}&redirect_uri={urllib.parse.quote(REDIRECT_URI)}&scope=openid%20profile%20email&response_type=code"

return {"message": "Redirecting to Google for authentication...", "auth_url": google_auth_url}

  
  

@app.get("/google/callback")

async def complete_google_login(request: Request, google_sso: GoogleSSO = Depends(get_google_sso), db: SessionLocal = Depends(get_db)):

google_user = await google_sso.verify_and_process(request)

  

user_service = UserService(db)

user = user_service.get_by_username(google_user.email)

access_token = create_access_token(username= user.username, role=user.role)

return {"access_token": access_token, "token_type": "bearer"}
```

У цьому блоку визначаються маршрути, які використовуються для ініціювання та обробки Google SSO авторизації.

#### Блок 5: Захищені маршрути

```python
# Protected route that requires authentication
@app.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    # ...
    # Here, you can decode and verify the JWT token and retrieve user information
    # ...
```

У цьому блоку визначено маршрут `/protected`, який потребує аутентифікації через JWT токен.

#### Блок 6: Запуск додатку

```python
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
```

У цьому блоку визначено код для запуску FastAPI додатку зі змінними параметрами, такими як хост і порт.

Кожен з цих блоків має свою функцію та відповідає за певний аспект авторизації через Google SSO та захисту маршрутів.
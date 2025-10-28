#Все неправильные адреса - 404
#Хэширование паролей(hashlib)
#Логирование в файл
#Автообновление сессии(примерно 3 минуты бездействия)
#В файл users.csv добавить поле role(admin or user)
#Реализовать разграничение доступа к страницам по ролям
#В куки записывать кроме сессии еще и user_name, role 
#Реализовать 403-forbidden
#Поднять https

import csv
import hashlib
import uuid
from datetime import timedelta, datetime
import pandas as pd
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

USERS = "users.csv"
SESSION_TTL = timedelta(minutes=3)
sessions = {}
white_urls = ["/", "/login", "/logout"]

@app.middleware("http")
async def check_session(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static") or path in white_urls:
        return await call_next(request)

    session_id = request.cookies.get("session_id")
    if session_id not in sessions:
        return RedirectResponse(url="/")

    session_data = sessions[session_id]
    if datetime.now() - session_data["created"] > SESSION_TTL:
        del sessions[session_id]
        return RedirectResponse(url="/")

    session_data["created"] = datetime.now()

    role = session_data["role"]
    if path.startswith("/home/admin") and role != "admin":
        return RedirectResponse(url="/")

    return await call_next(request)

@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
def login(request: Request,
          username: str = Form(...),
          password: str = Form(...)):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        active_user = sessions[session_id]["user"]
        return RedirectResponse(url=f"/home/{active_user}", status_code=302)

    try:
        users = pd.read_csv(USERS)
    except Exception:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Ошибка сервера"})

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    if username in users['users'].values:
        user_row = users[users['users'] == username].iloc[0]
        stored_hash = str(user_row['password_hash'])
        role = str(user_row['role'])

        if stored_hash == password_hash:
            session_id = str(uuid.uuid4())
            sessions[session_id] = {
                "created": datetime.now(),
                "user": username,
                "role": role
            }
            response = RedirectResponse(url=f"/home/{username}", status_code=302)
            response.set_cookie(key="session_id", value=session_id)
            response.set_cookie(key="user_name", value=username)
            response.set_cookie(key="role", value=role)
            return response

        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный пароль"})

    return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин"})

@app.get("/logout", response_class=HTMLResponse)
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        del sessions[session_id]
    return templates.TemplateResponse("login.html", {
        "request": request,
        "message": "Сессия завершена",
        "url": "/login"
    })

@app.get("/home/admin", response_class=HTMLResponse)
def get_admin_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/home/admin", response_class=HTMLResponse)
def get_user_page(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)
    return templates.TemplateResponse("error.html", {"request": request, "code": exc.status_code}, status_code=exc.status_code)

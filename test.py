import csv
import hashlib
import logging
import uuid
from datetime import timedelta, datetime
import pandas as pd
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

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
        logging.warning(f"Попытка доступа без сессии: {path}")
        return RedirectResponse(url="/")

    session_data = sessions[session_id]
    if datetime.now() - session_data["created"] > SESSION_TTL:
        del sessions[session_id]
        logging.info(f"Сессия истекла: {session_data['user']}")
        return RedirectResponse(url="/")

    session_data["created"] = datetime.now()

    role = session_data["role"]
    if path.startswith("/home/admin") and role != "admin":
        logging.warning(f"Доступ запрещён: {session_data['user']} → {path}")
        return templates.TemplateResponse("403.html", {"request": request}, status_code=403)

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

    users = pd.read_csv(USERS)
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
            logging.info(f"Успешный вход: {username} ({role})")
            return response

        logging.warning(f"Неверный пароль: {username}")
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный пароль"})

    logging.warning(f"Неверный логин: {username}")
    return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин"})

@app.get("/logout", response_class=HTMLResponse)
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        logging.info(f"Выход: {sessions[session_id]['user']}")
        del sessions[session_id]
    return templates.TemplateResponse("login.html", {
        "request": request,
        "message": "Сессия завершена",
        "url": "/login"
    })

@app.get("/home/admin", response_class=HTMLResponse)
def get_admin_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/home/{username}", response_class=HTMLResponse)
def get_user_page(request: Request, username: str):
    return templates.TemplateResponse("home.html", {"request": request, "username": username})

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)
    elif exc.status_code == 403:
        return templates.TemplateResponse("403.html", {"request": request}, status_code=403)
    return templates.TemplateResponse("error.html", {"request": request, "code": exc.status_code}, status_code=exc.status_code)

# HTTPS запуск
# uvicorn main:app --host 0.0.0.0 --port 443 --ssl-keyfile=key.pem --ssl-certfile=cert.pem

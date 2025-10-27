#Убрать ошибку повторного logout
#Убрать ошибку повторного login
#Все неправильные адреса - 404
#Хэширование паролей(hashlib)
#Логирование в файл
#Автообновление сессии(примерно 3 минуты бездействия)

import csv
from datetime import timedelta, datetime
import uuid
import pandas as pd
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


# Подключение всех статических файлов, шаблонов,
# инициализация веб-приложения, описание глобальных переменных
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
# app.mount("/sources", StaticFiles(directory="sources"), name="sources")
templates = Jinja2Templates(directory="templates")
USERS = "users.csv"
SESSION_TTL = timedelta(10)
sessions = {}
white_urls = ["/", "/login", "/logout"]

# Контрорль авторизации и сессии
@app.middleware("http")
async def check_session(request: Request, call_next):
    if request.url.path.startswith("/static") or request.url.path in white_urls:
        return await call_next(request)

    session_id = request.cookies.get("session_id")
    if session_id not in sessions:
        return RedirectResponse(url="/")
    
    created_session = sessions[session_id]
    if datetime.now() - created_session > SESSION_TTL:
        del sessions[session_id]
        return RedirectResponse(url="/")

    return await call_next(request)   

# Маршрутизации приложения
@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})  #{"request": request} Если нужно обращаться к вебу и обратно(нужен всегда)


@app.post("/login")
def login(request: Request,
          username: str = Form(...),
          password: str = Form(...)):
    users = pd.read_csv(USERS)
    if username  in users['users'].values[0]:
        if str(users[users['users'] == username].values[0][1]) == password:
            session_id = str(uuid.uuid4())
            sessions[session_id] = datetime.now()
            response = RedirectResponse(url=f"/home/{username}", status_code=302)
            response.set_cookie(key="session_id", value=session_id)
            return response
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный пароль"})
    return templates.TemplateResponse("login.html", {"request": request, "error": "Неверный логин"})
    
@app.get("/logout", response_class=HTMLResponse)
def logout(request: Request):
    session_id = request.cookies.get("session_id")
    del sessions[session_id] 
    return templates.TemplateResponse("login.html", {"request": request, "message": "Сессия завершина", "url": "/login"})

@app.get("/home/admin", response_class=HTMLResponse)
def get_start_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})
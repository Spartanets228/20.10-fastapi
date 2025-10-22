import csv
from datetime import datetime, timedelta
import uuid
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import pandas as pd


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
#app.mount("/sourses", StaticFiles(directory="sourses"), name="sourses")
templates = Jinja2Templates(directory="templates")
USERS = "users.csv"
SESSION_TTL = timedelta(10)
sessions = {}
white_urls = ["/", "login", "logout"]

#Контроль авторизации
@app.middleware("http")
async def check_session(request:Request, call_next):
    if request.url.path.startswith("/static") or request.url.path in white_urls:
        return await call_next(request)
    
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in sessions:
        return RedirectResponse(url="/")
    
    created_session = sessions[session_id]
    if datetime.now() - created_session > SESSION_TTL:
        del sessions[session_id]
        return RedirectResponse(url="/")
    
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def get_login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request":request}) #request обязательно

@app.post("/login")
def login(request: Request, 
          username:str = Form(...), 
          password: str = Form(...)):
    users = pd.read_csv(USERS)
    if username in users['user']:
        if users[users["user"] == username].values[0][1] == password:
            session_id = str(uuid.uuid4()) 
            sessions[session_id] = datetime.now()
            response = RedirectResponse(url=f"/home/{username}", status_code=302)
            response.set_cookie(key="session_id", value=session_id, httponly=True)
            return response
    return templates.TemplateResponse("login.html", {"request":request, "error": "Неверный логин или пароль"})



@app.get("/home/admin", response_class=HTMLResponse)
def get_start_page(request: Request):
    return templates.TemplateResponse("main.html", {"request":request})
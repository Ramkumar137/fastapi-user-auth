from fastapi import FastAPI, Request, Form, Depends
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.models import User
from app.schemas import UserLogin, UserCreate
from app.database import engine, SessionLocal, Base
import bcrypt

app = FastAPI()
templates = Jinja2Templates(directory="templates")
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/signup")
def signup(request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)):
    user_data = UserCreate(username=username, password=password)

    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        return HTMLResponse("❌ Username already exists", status_code=400)
    hashed_pw = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt()).decode()

    user = User(username=user_data.username, password=hashed_pw)
    db.add(user)
    db.commit()
    return RedirectResponse(url="/signin", status_code=303)

@app.get("/signin", response_class=HTMLResponse)
def signin_page(request: Request):
    return templates.TemplateResponse("signin.html", {"request": request})

@app.post("/signin")
def signin(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    login_data = UserLogin(username=username, password=password)
    user = db.query(User).filter(User.username == login_data.username).first()
    if user and bcrypt.checkpw(login_data.password.encode('utf-8'), user.password.encode('utf-8')):
        return templates.TemplateResponse("welcome.html", {"request": request, "username": login_data.username})
    return HTMLResponse("Invalid credentials", status_code=401)










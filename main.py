import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import requests

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

import bcrypt
from jose import JWTError, jwt

# ---------- Sozlamalar ----------
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./local.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "telc-b1-maxfiy-kalit-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30  # 30 kun

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)


# ---------- Parol funksiyalari ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# ---------- Ma'lumotlar bazasi modellari ----------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    progress = relationship("Progress", back_populates="user")


class Progress(Base):
    __tablename__ = "progress"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    section = Column(String, index=True)
    completed_count = Column(Integer, default=0)
    user = relationship("User", back_populates="progress")


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------- Yordamchi funksiyalar ----------
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Avtorizatsiya xato yoki muddati tugagan",
    )
    if not token:
        raise credentials_error
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise credentials_error
    except JWTError:
        raise credentials_error
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise credentials_error
    return user


# ---------- FastAPI ilovasi ----------
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Pydantic sxemalari ----------
class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class ProgressUpdateRequest(BaseModel):
    section: str


class SpeechCheckRequest(BaseModel):
    text: str


# ---------- Avtorizatsiya endpointlari ----------
@app.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Bu email bilan foydalanuvchi allaqachon bor")
    user = User(
        name=req.name,
        email=req.email,
        hashed_password=hash_password(req.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer", "name": user.name}


@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Email yoki parol noto'g'ri")
    token = create_access_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer", "name": user.name}


@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {"name": current_user.name, "email": current_user.email}


# ---------- Progress endpointlari ----------
@app.get("/progress")
def get_progress(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.query(Progress).filter(Progress.user_id == current_user.id).all()
    return {row.section: row.completed_count for row in rows}


@app.post("/progress/increment")
def increment_progress(
    req: ProgressUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    row = (
        db.query(Progress)
        .filter(Progress.user_id == current_user.id, Progress.section == req.section)
        .first()
    )
    if row is None:
        row = Progress(user_id=current_user.id, section=req.section, completed_count=1)
        db.add(row)
    else:
        row.completed_count += 1
    db.commit()
    return {"section": req.section, "completed_count": row.completed_count}


# ---------- Eski: grammatika tekshirish ----------
@app.post("/check-speech")
def check_speech(req: SpeechCheckRequest):
    response = requests.post(
        "https://api.languagetool.org/v2/check",
        data={"text": req.text, "language": "de-DE"},
    )
    result = response.json()
    errors = []
    for match in result.get("matches", []):
        errors.append({
            "wrong_part": req.text[match["offset"]: match["offset"] + match["length"]],
            "message": match["message"],
            "suggestions": [r["value"] for r in match.get("replacements", [])][:3]
        })
    return {"original_text": req.text, "errors": errors, "error_count": len(errors)}
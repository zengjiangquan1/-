from tkinter import CHAR
from typing import List

import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, VARCHAR
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from pydantic import BaseModel
import secrets
from starlette.middleware.cors import CORSMiddleware
import bcrypt
from jose import jwt
import datetime

# 生成一个长度为32的随机字节串，并转换为Base64编码的字符串作为密钥
YOUR_SECRET_KEY = secrets.token_urlsafe(32)
YOUR_ALGORITHM = "HS256"
MAX_ADMINS = 100
MAX_ACCOUNTS = 100
MAX_NAME_LENGTH = 100
MAX_PASSWORD_LENGTH = 100

# MySQL 数据库连接配置
MYSQL_USER = "root"
MYSQL_PASSWORD = "$Zjq20060522"
MYSQL_HOST = "localhost"
MYSQL_PORT = "3306"
MYSQL_DATABASE = "Account"
# 创建 MySQL 数据库连接 URL
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}"

app = FastAPI(debug=True)
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# 定义数据库模型
class Administrator(Base):
    __tablename__ = "administrators"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(MAX_NAME_LENGTH), index=True)
    username = Column(String(MAX_NAME_LENGTH), unique=True, index=True)
    password = Column(String(MAX_PASSWORD_LENGTH))
    accounts = relationship("Account", back_populates="administrator")


class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    appname = Column(String(MAX_NAME_LENGTH), index=True)
    username = Column(String(MAX_NAME_LENGTH))
    password = Column(String(MAX_PASSWORD_LENGTH))
    administrator_id = Column(Integer, ForeignKey("administrators.id"))
    administrator = relationship("Administrator", back_populates="accounts")


# 创建数据库表格
Base.metadata.create_all(bind=engine)

# Pydantic 模型
class AccountCreate(BaseModel):
    appname: str
    username: str
    password: str

class newAccount(BaseModel):
    appname: str
    new_username: str
    new_password: str

class AdministratorCreate(BaseModel):
    name: str
    username: str
    password: str

class User(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
# 生成令牌
def generate_token(username: str) -> str:
    payload = dict(sub=username, exp=datetime.datetime.now() + datetime.timedelta(minutes=30))
    token = jwt.encode(payload, YOUR_SECRET_KEY, algorithm=YOUR_ALGORITHM)
    return token

# 验证令牌
def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, YOUR_SECRET_KEY, algorithms=[YOUR_ALGORITHM])
        return payload["sub"]
    except jwt.JWTError:
        return None

# 创建用户时对密码进行加密
def hash_password(password: str) -> str:
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

# 验证用户密码
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# 创建用户登录接口
from typing import Optional

@app.post("/login", response_model=Token)
def login_for_access_token(user:User, db: Session = Depends(get_db)):
    db_admin = db.query(Administrator).filter(Administrator.username == user.username).first()
    if not db_admin or not verify_password(user.password, db_admin.password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    return Token(access_token=generate_token(user.username), token_type="bearer")

@app.post("/save_account")
def save_account(account: AccountCreate, token: str = Depends(OAuth2PasswordBearer(tokenUrl="login")), db: Session = Depends(get_db)):
    # 根据令牌获取当前用户
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="无效令牌")
    db_admin = db.query(Administrator).filter(Administrator.username == username).first()
    if not db_admin:
        raise HTTPException(status_code=404, detail="未找到对应的管理员")

    # 检查管理员账号是否已满
    if len(db_admin.accounts) >= MAX_ACCOUNTS:
        raise HTTPException(status_code=403, detail="管理员账号已满")

    # 创建新的账号
    db_account = Account(**account.dict(), administrator_id=db_admin.id)
    db.add(db_account)
    db.commit()
    db.refresh(db_account)

    return {"message": "账号密码保存成功"}

@app.get("/show_accounts")
def show_accounts(token: str = Depends(OAuth2PasswordBearer(tokenUrl="login")), db: Session = Depends(get_db)):
    # 根据令牌获取当前用户
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="无效令牌")
    db_admin = db.query(Administrator).filter(Administrator.username == username).first()
    if not db_admin:
        raise HTTPException(status_code=404, detail="未找到对应的管理员")

    # 获取管理员管理的所有账号信息
    accounts = db.query(Account).filter(Account.administrator_id == db_admin.id).all()
    if not accounts:
        raise HTTPException(status_code=404, detail="该管理员暂无管理的账号")

    return {"accounts": [{"appname": account.appname, "username": account.username, "password": account.password} for
                         account in accounts]}

@app.post("/register_admin")
def create_new_administrator(administrator: AdministratorCreate, db: Session = Depends(get_db)):
    # 检查管理员账号是否已存在
    db_existing_admin = db.query(Administrator).filter(Administrator.username == administrator.username).first()
    if db_existing_admin:
        raise HTTPException(status_code=400, detail="该管理员账号已存在，请重新输入")

    # 创建新管理员
    hashed_password = hash_password(administrator.password)
    db_administrator = Administrator(name=administrator.name, username=administrator.username,
                                     password=hashed_password)
    db.add(db_administrator)
    db.commit()
    db.refresh(db_administrator)

    # 创建管理员的同时创建账户
    for account_data in administrator.accounts:
        db_account = Account(**account_data.dict(), administrator_id=db_administrator.id)
        db.add(db_account)
    db.commit()

    return {"message": "管理员账号注册成功"}

@app.put("/modify_account")
def modify_account(new_account: newAccount , token: str = Depends(OAuth2PasswordBearer(tokenUrl="login")),
                   db: Session = Depends(get_db)):
    # 根据令牌获取当前用户
    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="无效令牌")
    db_admin = db.query(Administrator).filter(Administrator.username == username).first()
    if not db_admin:
        raise HTTPException(status_code=404, detail="未找到对应的管理员")

    # 查找指定 app 名称的账号
    db_account = db.query(Account).filter(Account.appname == new_account.appname, Account.administrator_id == db_admin.id).first()
    if not db_account:
        raise HTTPException(status_code=404, detail="未找到指定应用的账号信息")

    # 更新账号信息
    db_account.username = new_account.new_username
    db_account.password = new_account.new_password
    db.commit()
    db.refresh(db_account)
    return {"message": "账号信息更新成功"}

if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)

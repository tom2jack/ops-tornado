# coding:utf-8

import hashlib
from datetime import datetime
from model import BaseModel, db, DBSession, relationship
from sqlalchemy import Column, Integer, String, Float, ForeignKey, Boolean, DateTime, Text


class Record(BaseModel):
    __tablename__ = 'vpc_record'

    id = Column(Integer, primary_key=True, autoincrement=True)
    submit_time = Column(DateTime, default=datetime.now())
    states = Column(String(50))
    step = Column(Integer)
    req = Column(String(50))
    msg = Column(Text)


class User(BaseModel):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    submit_time = Column(DateTime, default=datetime.now())
    email = Column(String(50), default='')
    username = Column(String(50), unique=True)
    password = Column(String(200))


class SSHKey(BaseModel):
    __tablename__ = 'ssh_key'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(200))
    create_time = Column(DateTime, default=datetime.now())
    private_key = Column(Text)
    public_key = Column(Text)
    key_password = Column(String(200), default=None, nullable=True)
    cache_dir = Column(String(200), default=None, nullable=True)


def init_db():
    BaseModel.metadata.create_all(bind=db)


if __name__ == "__main__":
    init_db()
    session = DBSession()
    username = 'admin'
    password = 'admin'
    user = User(username=username, password=hashlib.sha256(password).hexdigest())
    session.add(user)
    session.commit()
    session.close()

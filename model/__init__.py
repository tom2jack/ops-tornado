# coding:utf-8

import settings
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base

if settings.USE_DB == 'mysql':
    db = create_engine(settings.DATABASE_URI, pool_size=100, max_overflow=200, pool_recycle=3600)
elif settings.USE_DB == 'sqlite':
    db = create_engine(settings.DATABASE_URI)
else:
    db = None

BaseModel = declarative_base()
DBSession = sessionmaker(bind=db)

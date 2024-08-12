import os
from dotenv import load_dotenv
import redis




load_dotenv()


class Config:
    SECRET_KEY = os.environ['SECRET_KEY']
    SERVER_NAME = 'localhost'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://scanner:scanner@db/scanner'
    redis_client = redis.Redis(host='scheduler', port=6379, db=0)
    SESSION_TYPE = 'redis'
    SESSION_REDIS = redis_client
    SESSION_COOKIE_SECURE = True
    GOOGLE_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ['MAIL_USERNAME']
    MAIL_PASSWORD = os.environ['MAIL_PASSWORD']
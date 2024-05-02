import os
from dotenv import load_dotenv
import redis




load_dotenv()


class Config:
    SECRET_KEY = os.environ['SECRET_KEY']
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://scanner:scanner@db/scanner'
    redis_client = redis.Redis(host='scheduler', port=6379, db=0)
    SESSION_TYPE = 'redis'
    SESSION_REDIS = redis_client
    SESSION_COOKIE_SECURE = True
    GOOGLE_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
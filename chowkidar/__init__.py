from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_session import Session
from flask_admin import Admin
from flask_oauthlib.client import OAuth
from chowkidar.config import Config
from configparser import ConfigParser
from flask_migrate import Migrate
from flask_mail import Mail
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
from rq import Queue




login_manager = LoginManager()
login_manager.login_view = 'users.home'
login_manager.login_message_category = 'info'
oauth = OAuth()
session = Session()
mail = Mail()


parser = ConfigParser()
parser.read('config.ini')

def get_admin():
    return parser.get('APP', 'ADMINS')

limiter = Limiter(
get_remote_address,
storage_uri="redis://scheduler:6379",
storage_options={}
)


def create_app(config_class=Config):
    app = Flask(__name__)
    with app.app_context():
        app.config.from_object(Config)
        from chowkidar.models import db
        db.init_app(app)
        db.create_all()
        login_manager.init_app(app)
        oauth.init_app(app)
        session.init_app(app)
        mail.init_app(app)

        limiter.init_app(app)
        
        from chowkidar.utils.routes import utils
        from chowkidar.audits.routes import audits
        app.register_blueprint(utils)
        app.register_blueprint(audits)
        return app
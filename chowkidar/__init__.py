from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_session import Session
from flask_oauthlib.client import OAuth
from chowkidar.config import Config
from configparser import ConfigParser




login_manager = LoginManager()
login_manager.login_view = 'users.home'
login_manager.login_message_category = 'info'
oauth = OAuth()
session = Session()


parser = ConfigParser()
parser.read('config.ini')

def get_admin():
    return parser.get('APP', 'ADMINS')




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

        from chowkidar.utils.routes import utils
        from chowkidar.audits.routes import audits
        app.register_blueprint(utils)
        app.register_blueprint(audits)
        return app
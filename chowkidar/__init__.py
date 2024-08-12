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
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user
from flask_limiter.util import get_remote_address
import redis
from rq import Queue



parser = ConfigParser()
parser.read('config.ini')


login_manager = LoginManager()
login_manager.login_view = 'utils.home'
login_manager.login_message_category = 'info'
oauth = OAuth()
session = Session()
mail = Mail()
admin = Admin()
migrations = Migrate()


redis_connection = redis.Redis(host='scheduler', port=6379, db=0)
task_queue = Queue('task_queue', connection=redis_connection)


def get_admin():
    return parser.get('APP', 'ADMINS')

def get_workers():
    return parser.get('WORKER', 'CONTAINERS')

limiter = Limiter(
    get_remote_address,
    storage_uri="redis://scheduler:6379",
    storage_options={}
    )




class AdminPanelView(ModelView):
    def is_accessible(self):
        column_display_pk = True
        if current_user.is_authenticated and current_user.admin:
            return True
        else:
            return False




class AdminPanelAuditView(AdminPanelView):
    column_display_pk = True
    column_list = ['id', 'name', 'url', 'task_id', 'container_id', 'status', 'date', 'nmap', 'dirsearch', 'headers', 'testssl', 'nuclei', 'sublister', 'wpscan', 'Auditor']
    form_columns = ['name', 'url', 'task_id', 'container_id', 'status', 'date', 'nmap', 'dirsearch', 'headers', 'testssl', 'nuclei', 'sublister', 'wpscan', 'Auditor']




class AdminPanelTemplatesView(AdminPanelView):
    form_columns = ['name', 'description', 'impact', 'severity', 'steps', 'fix', 'cvss', 'cwe', 'type']




def create_app(config_class=Config):
    app = Flask(__name__)
    with app.app_context():
        app.config.from_object(Config)
        from chowkidar.models import db
        db.init_app(app)
        migrations.init_app(app, db)
        db.create_all()
        login_manager.init_app(app)
        oauth.init_app(app)
        session.init_app(app)
        mail.init_app(app)
        limiter.init_app(app)
        
    admin = Admin(app, name='admin')

    from chowkidar.models import User, Audit, ScanResults, VulnerabilityDiscovered, VulnerabilityTemplates, Messages
    
    admin.add_view(AdminPanelView(User, db.session))
    admin.add_view(AdminPanelAuditView(Audit, db.session))
    admin.add_view(AdminPanelView(ScanResults, db.session))
    admin.add_view(AdminPanelView(VulnerabilityDiscovered, db.session))
    admin.add_view(AdminPanelTemplatesView(VulnerabilityTemplates, db.session))
    admin.add_view(AdminPanelView(Messages, db.session))
            
    
    from chowkidar.utils.routes import utils
    from chowkidar.audits.routes import audits
    from chowkidar.admin.routes import admin_view
    from chowkidar.errors.handlers import errors
    app.register_blueprint(utils)
    app.register_blueprint(audits)
    app.register_blueprint(admin_view)
    app.register_blueprint(errors)
    
    return app
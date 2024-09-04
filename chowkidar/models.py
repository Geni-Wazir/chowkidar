from datetime import datetime, timezone
from chowkidar import login_manager
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    profile = db.Column(db.String(50), nullable=False, default='profile.png')
    admin = db.Column(db.Boolean, nullable=False, default=False)
    scan_available = db.Column(db.Integer, nullable=False, default=5)
    wpscan_api = db.Column(db.String(100))
    audit = db.relationship('Audit', back_populates='Auditor', lazy=True,  cascade="all, delete")

    def __repr__(self):
        return "User({}, {}, {})".format(self.name, self.email, self.scan_available)




class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100), nullable=False)
    asset_type = db.Column(db.String(100), nullable=False, default='web')
    date = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    scan_date = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    container_id = db.Column(db.String(100))
    task_id = db.Column(db.String(100))
    status = db.Column(db.String(100), nullable=False, default='unscanned')
    scan_verified = db.Column(db.Boolean, nullable=False, default=False)
    progress = db.Column(db.Integer, default=0)
    progress_msg = db.Column(db.String(100), default='scanning')
    # web scan config
    url = db.Column(db.String(100), nullable=False, default='')
    tools = db.Column(db.Text(), nullable=False, default='')
    # cloud (AWS) scan config
    access_id = db.Column(db.String(100), nullable=False, default='')
    secret_key = db.Column(db.String(100), nullable=False, default='')
    regions = db.Column(db.String(1000), nullable=False, default='')
    services = db.Column(db.Text(), nullable=False, default='')

    Auditor = db.relationship('User', back_populates='audit', lazy=True)
    audit_vuln = db.relationship('VulnerabilityDiscovered', backref='Audit', lazy=True, cascade="all, delete")
    result = db.relationship('ScanResults', backref='Audit', lazy=True, cascade="all, delete")

    def __repr__(self):
        return "Audit({}, {}, {})".format(self.name, self.Auditor.name, self.Auditor.email)




class CloudRegions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, default='')
    asset_type = db.Column(db.String(100), nullable=False, default='aws')




class CloudServices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, default='')
    asset_type = db.Column(db.String(100), nullable=False, default='aws')




class ScanResults(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'))
    nmap = db.Column(db.Text(4294000000), nullable=False, default='NA')
    vulnerabilities = db.Column(db.Text(4294000000), nullable=False, default='NA')
    slowloris = db.Column(db.Text(4294000000), nullable=False, default='NA')
    diffiehellman = db.Column(db.Text(4294000000), nullable=False, default='NA')
    heartbleed = db.Column(db.Text(4294000000), nullable=False, default='NA')
    poodle = db.Column(db.Text(4294000000), nullable=False, default='NA')
    testssl = db.Column(db.Text(4294000000), nullable=False, default='NA')
    sublister = db.Column(db.Text(4294000000), nullable=False, default='NA')
    nuclei = db.Column(db.Text(4294000000), nullable=False, default='NA')
    wpscan = db.Column(db.Text(4294000000), nullable=False, default='NA')
    # cloud (AWS) output [ERRORS]
    cloud = db.Column(db.Text(4294000000), nullable=False, default='{}')




class VulnerabilityDiscovered(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audit.id'))
    template_id = db.Column(db.Integer, db.ForeignKey('vulnerability_templates.id'))
    name = db.Column(db.String(100), nullable=False)
    data = db.Column(db.Text(4294000000))

    def __repr__(self):
        return "Vulnerability({})".format(self.name)




class VulnerabilityTemplates(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    impact = db.Column(db.Text,)
    severity = db.Column(db.String(100), nullable=False)
    steps = db.Column(db.Text)
    fix = db.Column(db.Text, nullable=False)
    cvss = db.Column(db.Float, nullable=False, default=0.0)
    cvss_string = db.Column(db.String(100))
    cwe = db.Column(db.String(400))
    type = db.Column(db.String(100))
    vulnerability = db.relationship('VulnerabilityDiscovered', backref='Template', lazy=True, cascade="all, delete")
    def __repr__(self):
        return "Template({})".format(self.name)


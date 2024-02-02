import os

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True

    ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}

    UPLOADS_FOLDER = 'uploads'


class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
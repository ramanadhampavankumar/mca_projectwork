# implement in future


import os

class Config:
    # Secret key for sessions
    SECRET_KEY = os.environ.get('SECRET_KEY', 'mysecretkey')

    # Database URI
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users.db')

    # Disable track modifications to save resources
    SQLALCHEMY_TRACK_MODIFICATIONS = False
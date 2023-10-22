from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from app import app, db
from models.user import User

app = Flask(__name)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgre:iqbal@localhost/lemper_checker'
db = SQLAlchemy(app)

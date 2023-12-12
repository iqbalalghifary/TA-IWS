import sys
import os

sys.path.append('D:\\lemper-checker')

# Set the environment variable
os.environ['DATABASE_URL'] = 'postgresql://postgres:1234@localhost/lemper'

from app import app as application
application.secret_key = 'anythingwished'
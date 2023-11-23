import sys
import os

sys.path.append('D:\\lemper-checker')

from app import app as application
application.secret_key = 'anythingwished'
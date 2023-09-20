import os
from decouple import config

# MONGO_URI = os.environ.get('MONGO_URI')
MONGO_URI ="mongodb://localhost:27017"
# SALT = os.environ.get('SALT')
SALT= "abcdefg12345"
# AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY')
# AWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY')


AWS_ACCESS_KEY = config("AWS_ACCESS_KEY")
AWS_SECRET_KEY = config("AWS_SECRET_KEY")
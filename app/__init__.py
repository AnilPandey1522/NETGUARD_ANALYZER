from flask import Flask
from pymongo import MongoClient
# This line below was causing your error because it couldn't find 'Config'
from config import Config 

mongo = MongoClient(Config.MONGO_URI)
db = mongo.netguard_db

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    from app.routes import main
    app.register_blueprint(main)
    
    return app
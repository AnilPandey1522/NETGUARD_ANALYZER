import os

class Config:
    # We use a secret key for security (required by Flask)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'professional-secret-key-123'
    
    # This connects to the MongoDB you showed in your screenshot
    MONGO_URI = "mongodb://localhost:27017/netguard_db" 
    
    # Folder where uploaded PCAPs will go
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
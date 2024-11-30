class Config:
    SECRET_KEY = 'your-secret-key'
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'}
    DATABASE = {
        'dbname': 'ServiceDesk',
        'user': 'postgres',
        'password': '1958',
        'host': 'localhost',
        'port': 5432
    }
    BCRYPT_LOG_ROUNDS = 12


from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from config import Config


class User(UserMixin):
    def __init__(self, id, username, password_hash, role):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role

    @staticmethod
    def get_by_username(username):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password_hash, role FROM users WHERE username = %s;', (username,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(*user_data)
        return None

    @staticmethod
    def create_user(username, password, role='user'):
        password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s);',
                       (username, password_hash, role))
        conn.commit()
        conn.close()

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

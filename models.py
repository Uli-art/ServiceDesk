from flask_login import UserMixin
import psycopg2
from config import Config


class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role_id):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role_id = role_id

    @staticmethod
    def get_user_by_id(id):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, password_hash, role_id FROM users WHERE id = %s;', (id,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(*user_data)
        return None

    @staticmethod
    def get_by_username(username):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, password_hash, role_id FROM users WHERE username = %s;', (username,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(*user_data)
        return None

    @staticmethod
    def get_by_email(email):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, email, password_hash, role_id FROM users WHERE email = %s;', (email,))
        user_data = cursor.fetchone()
        conn.close()
        if user_data:
            return User(*user_data)
        return None

    def get_hashed_password(self):
        return self.password_hash

    @staticmethod
    def validate_user_registration(username, email):
        if User.get_by_username(username):
            return False
        if User.get_by_email(email):
            return False
        return True

    @staticmethod
    def validate_user_login(bcrypt, email, password):
        user = User.get_by_email(email=email)
        if user and bcrypt.check_password_hash(user.get_hashed_password(), password):
            return user
        return None

    @staticmethod
    def create_user(username, email, password, role=1):
        password_hash = password
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, email, password_hash, role_id) VALUES (%s, %s, %s, %s);',
                       (username, email, password_hash, role))
        conn.commit()
        conn.close()


class Comment:
    def __init__(self, id, ticket_id, author_id, content):
        self.id = id
        self.ticket_id = ticket_id
        self.author_id = author_id
        self.content = content

    @staticmethod
    def create_comment(ticket_id, author_id, content):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO comments (ticket_id, author_id, content) VALUES (%s, %s, %s);',
                       (ticket_id, author_id, content))
        conn.commit()
        conn.close()


class Ticket:

    @staticmethod
    def create_ticket(title, description, priority_id, category_id, creator_id, status_id=1):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO tickets (title, description, priority_id, category_id, creator_id, status_id) '
                       'VALUES (%s, %s, %s, %s, %s, %s);',
                       (title, description, priority_id, category_id, creator_id, status_id))
        conn.commit()
        conn.close()

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

    @staticmethod
    def update_user(username, email, role_id, user_id):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute("""UPDATE users 
                                    SET username = %s, 
                                        email = %s, 
                                        role_id = %s 
                                    WHERE id = %s;  """,
                       (username, email, role_id, user_id,))
        conn.commit()
        conn.close()

    @staticmethod
    def delete_user(user_id):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute("""DELETE FROM users 
                            WHERE id = %s; """,
                       (user_id,))
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

    @staticmethod
    def update_ticket(title, description, priority_id, category_id, creator_id, status_id, ticket_id):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute("""UPDATE tickets 
                            SET title = %s, 
                                description = %s, 
                                priority_id = %s, 
                                category_id = %s, 
                                creator_id = %s, 
                                status_id = %s
                            WHERE id = %s;  """,
                       (title, description, priority_id, category_id, creator_id, status_id, ticket_id, ))
        conn.commit()
        conn.close()

    @staticmethod
    def update_ticket_status(status_id, ticket_id):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute("""UPDATE tickets 
                            SET status_id = %s
                            WHERE id = %s;  """,
                       (status_id, ticket_id, ))
        conn.commit()
        conn.close()


class ActivityLogs:

    @staticmethod
    def add_log(user_id, action, ticket_id=None):
        conn = psycopg2.connect(**Config.DATABASE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO activity_logs (user_id, ticket_id, action) '
                       'VALUES (%s, %s, %s);',
                       (user_id, ticket_id, action,))
        conn.commit()
        conn.close()
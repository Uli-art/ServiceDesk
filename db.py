import psycopg2
from psycopg2.extras import DictCursor
from config import Config


def get_db_connection():
    conn = psycopg2.connect(
        dbname=Config.DATABASE['dbname'],
        user=Config.DATABASE['user'],
        password=Config.DATABASE['password'],
        host=Config.DATABASE['host'],
        port=Config.DATABASE['port'],
    )
    return conn


def query_db(query, args=(), one=False):
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=DictCursor)
    cur.execute(query, args)
    rv = cur.fetchall()
    cur.close()
    conn.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query, args=()):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    cur.close()
    conn.close()

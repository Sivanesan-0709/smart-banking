import os
import sys
import collections.abc
import sqlite3

try:
    import psycopg2
    import psycopg2.extras
    from psycopg2.pool import ThreadedConnectionPool
except ImportError:
    psycopg2 = None
    ThreadedConnectionPool = None

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = str(BASE_DIR / 'BankNH.db')

_pool = None

class CaseInsensitiveRow(collections.abc.Mapping):
    def __init__(self, description, row_tuple):
        self._values = row_tuple
        self._keys = [desc[0] for desc in description] if description else []
        self._index_map = {name.lower(): idx for idx, name in enumerate(self._keys)}
        
    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        elif isinstance(key, str):
            lower_key = key.lower()
            if lower_key in self._index_map:
                return self._values[self._index_map[lower_key]]
            raise KeyError(key)
        raise TypeError(f"Index must be int or str, not {type(key)}")
        
    def __len__(self):
        return len(self._values)
        
    def __iter__(self):
        return iter(self._keys)
        
    def keys(self):
        return self._keys
        
    def values(self):
        return self._values
        
    def items(self):
        return zip(self._keys, self._values)
        
    def __repr__(self):
        return repr(dict(self.items()))

class CaseInsensitiveCursorWrapper:
    def __init__(self, real_cursor, is_postgres=False):
        self._cursor = real_cursor
        self._is_postgres = is_postgres
        
    def __getattr__(self, name):
        return getattr(self._cursor, name)
        
    def execute(self, query, parameters=None):
        if not isinstance(query, str):
            if parameters is not None:
                return self._cursor.execute(query, parameters)
            else:
                return self._cursor.execute(query)
                
        # Adapt placeholders where absolutely necessary
        if self._is_postgres:
            if "?" in query:
                query = query.replace("?", "%s")
        else:
            import re
            query = re.sub(r"(?<!['\"])%s(?!['\"])", "?", query)
            
        # Ignore PRAGMA calls in PostgreSQL
        if self._is_postgres and query.strip().upper().startswith("PRAGMA"):
            return None
            
        if parameters is not None:
            return self._cursor.execute(query, parameters)
        else:
            return self._cursor.execute(query)
            
    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        return CaseInsensitiveRow(self._cursor.description, row)
        
    def fetchall(self):
        rows = self._cursor.fetchall()
        if rows is None:
            return []
        return [CaseInsensitiveRow(self._cursor.description, r) for r in rows]
        
    def __iter__(self):
        return self
        
    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cursor.close()

class CaseInsensitiveConnectionWrapper:
    def __init__(self, real_conn, is_postgres=False):
        self._conn = real_conn
        self._is_postgres = is_postgres
        
    def __getattr__(self, name):
        return getattr(self._conn, name)
        
    def cursor(self, *args, **kwargs):
        cursor = self._conn.cursor(*args, **kwargs)
        return CaseInsensitiveCursorWrapper(cursor, self._is_postgres)
        
    def close(self):
        if self._is_postgres:
            global _pool
            if _pool:
                try:
                    _pool.putconn(self._conn)
                except Exception as e:
                    print(f"[ERROR] Error returning PostgreSQL connection to pool: {e}", flush=True)
        else:
            self._conn.close()
            
    def __enter__(self):
        self._conn.__enter__()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        res = self._conn.__exit__(exc_type, exc_val, exc_tb)
        self.close()
        return res

def init_pool():
    global _pool
    if _pool is not None:
        return
    db_url = os.environ.get('DATABASE_URL')
    print("[INFO] Initializing PostgreSQL connection pool...", flush=True)
    try:
        if db_url:
            _pool = ThreadedConnectionPool(minconn=1, maxconn=20, dsn=db_url)
        else:
            host = os.environ.get('DB_HOST', 'localhost')
            port = os.environ.get('DB_PORT', '5432')
            dbname = os.environ.get('DB_NAME')
            user = os.environ.get('DB_USER')
            password = os.environ.get('DB_PASSWORD')
            _pool = ThreadedConnectionPool(minconn=1, maxconn=20, host=host, port=port, dbname=dbname, user=user, password=password)
        print("[INFO] PostgreSQL connection pool initialized successfully.", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed to initialize PostgreSQL connection pool: {e}", flush=True)
        raise e

def get_db_connection():
    db_url = os.environ.get('DATABASE_URL')
    is_postgres = (db_url is not None or any(os.environ.get(var) for var in ['DB_HOST', 'DB_NAME', 'DB_USER'])) and psycopg2 is not None
    
    if is_postgres:
        global _pool
        if _pool is None:
            init_pool()
        try:
            real_conn = _pool.getconn()
            # Verify the connection is active
            with real_conn.cursor() as cur:
                cur.execute("SELECT 1")
            print("[DEBUG] PostgreSQL connection successfully fetched from pool.", flush=True)
            return CaseInsensitiveConnectionWrapper(real_conn, is_postgres=True)
        except Exception as e:
            print(f"[ERROR] Failed to retrieve PostgreSQL connection from pool: {e}", flush=True)
            raise e
    else:
        try:
            real_conn = sqlite3.connect(DB_PATH, timeout=30)
            # Enable foreign keys for SQLite
            real_conn.execute("PRAGMA foreign_keys = ON")
            # Return wrapped SQLite connection with CaseInsensitiveRow support
            return CaseInsensitiveConnectionWrapper(real_conn, is_postgres=False)
        except Exception as e:
            print(f"[ERROR] Failed to open SQLite connection: {e}", flush=True)
            raise e

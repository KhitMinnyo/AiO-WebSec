import sqlite3
import hashlib
import os
import uuid
import time
from datetime import datetime

# Configuration
DB_NAME = 'aio_websec_lab.db'
# Low Security Password Hash: 'password' ကို MD5 နဲ့ hash လုပ်ထားခြင်း (Weak Hashing Simulation)
ADMIN_PASS_HASH = hashlib.md5("password".encode()).hexdigest() 

def setup_db():
    """
    Database Tables များနှင့် Dummy Data များ ဖန်တီးခြင်း။
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # ----------------------------------------------------
    # 1. Users Table (SQLi, IDOR, Session Hijacking အတွက်)
    # ----------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            secret_token TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    # Dummy Users ထည့်သွင်းခြင်း
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'SUPER_SECRET_ADMIN_TOKEN_1234', 1)", (ADMIN_PASS_HASH,)) 
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'alice', ?, 'regular_user_token_alice_5678', 0)", (ADMIN_PASS_HASH,))
    cursor.execute("INSERT OR IGNORE INTO users VALUES (3, 'bob', ?, 'another_token_bob_9012', 0)", (ADMIN_PASS_HASH,))

    # ----------------------------------------------------
    # 2. Guestbook Table (Stored XSS အတွက်)
    # ----------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS guestbook (
            id INTEGER PRIMARY KEY,
            author TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Dummy Messages ထည့်သွင်းခြင်း
    cursor.execute("INSERT OR IGNORE INTO guestbook (id, author, message) VALUES (1, 'System', 'Welcome to AIO-WebSec Lab!')")
    cursor.execute("INSERT OR IGNORE INTO guestbook (id, author, message) VALUES (2, 'Alice', 'This is a normal comment.')")
    
    # ----------------------------------------------------
    # 3. Orders Table (IDOR, CSRF, Logic Bypass အတွက်)
    # ----------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            order_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            item TEXT,
            price REAL,
            status TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    
    # Dummy Orders ထည့်သွင်းခြင်း (Alice: ID 2, Bob: ID 3)
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (101, 2, 'Laptop', 1200.00, 'Shipped')") # Alice's Order
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (102, 3, 'Mouse', 25.00, 'Processing')")  # Bob's Order
    cursor.execute("INSERT OR IGNORE INTO orders VALUES (103, 2, 'Keyboard', 75.00, 'Pending')")  # Alice's 2nd Order

    # ----------------------------------------------------
    # 4. Inventory Table (Race Condition/Logic Lab အတွက်)
    # ----------------------------------------------------
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS inventory (
            item_name TEXT PRIMARY KEY,
            stock INTEGER
        )
    ''')
    
    # Stock Dummy Data
    cursor.execute("INSERT OR IGNORE INTO inventory VALUES ('Flag-Item', 1)") # Stock 1 ခုသာရှိခြင်း (Race Condition စမ်းရန်)
    cursor.execute("INSERT OR IGNORE INTO inventory VALUES ('Generic-Item', 100)")
    
    conn.commit()
    conn.close()
    
    # ----------------------------------------------------
    # File System Setup (LFI/RFI, Path Traversal, SSRF/Metadata အတွက်)
    # ----------------------------------------------------
    
    # 1. Private Data Directory
    PRIVATE_DIR = 'private_data'
    if not os.path.exists(PRIVATE_DIR):
        os.makedirs(PRIVATE_DIR)
    
    with open(os.path.join(PRIVATE_DIR, 'admin_notes.txt'), 'w') as f:
        f.write('The main server internal key is: SECRET_LAB_2024_KEY_DO_NOT_SHARE')
        
    with open(os.path.join(PRIVATE_DIR, 'passwd_mock.txt'), 'w') as f:
        f.write('root:x:0:0:root:/root:/bin/bash\n')
        f.write('www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin')

    # 2. Uploads Directory (File Upload/Web Shells အတွက်)
    UPLOAD_DIR = 'uploads'
    if not os.path.exists(UPLOAD_DIR):
        os.makedirs(UPLOAD_DIR)
        
    # 3. SSRF Internal Service File (Cloud Metadata Exploitation Simulation)
    # Attacker က 127.0.0.1/latest/meta-data ကို တောင်းတဲ့အခါ ဒီ file ကို ဖတ်စေရန်
    with open('internal_service.txt', 'w') as f:
        f.write('iam/security-credentials/AIO-WebSec-Role\n')
        f.write('latest/meta-data/security-credentials/AIO-WebSec-Role\n')
        f.write('RoleKey: ACCESS_KEY_EXPOSED_VIA_SSRF')

    print("--- AIO-WebSec Lab Setup Complete ---")
    print(f"Database: {DB_NAME} initialized.")
    print("Files/Directories: 'private_data', 'uploads', 'internal_service.txt' created.")
    print("Run 'python app.py' to start the application.")

if __name__ == '__main__':
    setup_db()
import os
import sqlite3
import subprocess
import time
import base64
import yaml
import json
from datetime import datetime
from urllib.parse import urlparse
import logging

# Markup ကို markupsafe ကနေ မှန်ကန်စွာ import လုပ်ခြင်း
from markupsafe import Markup
from flask import (
    Flask, render_template, request, redirect, url_for, 
    make_response, session, abort
)

# Configuration and Initialization
app = Flask(__name__)
# WARNING: Flask session secret key must be strong and kept private in production!
# For a lab environment, a fixed key is acceptable.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_insecure_key_for_lab') 
app.config['DEBUG'] = True # Set debug to True by default for the lab

# --- Database Setup (Simulation) ---
DATABASE = 'lab_data.db'

def get_db_connection():
    """Establishes and returns a database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema and populates initial data."""
    conn = get_db_connection()
    c = conn.cursor()
    
    # 1. Users Table (for SQLi, IDOR, Secrets Lab)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            secret_token TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    # 2. Guestbook Table (for Stored XSS Lab)
    c.execute('''
        CREATE TABLE IF NOT EXISTS guestbook (
            id INTEGER PRIMARY KEY,
            author TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 3. Orders Table (for IDOR/Access Control Lab)
    c.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            order_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            item TEXT,
            status TEXT DEFAULT 'Processing'
        )
    ''')

    # Initial Data Insertion (Only if empty)
    if not c.execute("SELECT id FROM users WHERE id=1").fetchone():
        users_data = [
            (1, 'admin', 'password123', 'SEC_TOKEN_ADMIN_999', 1),
            (101, 'alice', 'alicepass', 'SEC_TOKEN_ALICE_101', 0),
            (102, 'bob', 'bobpass', 'SEC_TOKEN_BOB_102', 0),
        ]
        c.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", users_data)
        
        orders_data = [
            (101, 101, 'Laptop', 'Shipped'), # Alice's order
            (102, 102, 'Keyboard', 'Processing'), # Bob's order
            (103, 1, 'Server Rack', 'Shipped'), # Admin's order
        ]
        c.executemany("INSERT INTO orders (order_id, user_id, item, status) VALUES (?, ?, ?, ?)", orders_data)
        
        guestbook_data = [
            ('System', 'Welcome to the lab! Test your XSS skills here.'),
        ]
        c.executemany("INSERT INTO guestbook (author, message) VALUES (?, ?)", guestbook_data)

    conn.commit()
    conn.close()

# --- Global Data/State Simulation ---
# For Business Logic Lab (Race Condition)
INVENTORY = {'Flag-Item': 1, 'Normal-Item': 100}

# --- Utility Functions ---

def get_security_level():
    """Retrieves the current security level from the session (default 0)."""
    return session.get('security_level', 0)

def is_admin(user_id):
    """Checks if a user ID corresponds to an admin (for access control)."""
    conn = get_db_connection()
    user = conn.execute("SELECT is_admin FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return user and user['is_admin'] == 1

# --- Security Filters (Used in Medium/High levels) ---

def sanitize_sql(user_input):
    """Basic filter for Medium level SQLi defense."""
    return user_input.replace("'", "''").replace("--", "").replace(";", "")

def escape_html(data):
    """Basic filter for Medium/High level XSS defense."""
    return data.replace('<', '&lt;').replace('>', '&gt;')

# --- Routes ---

# @app.before_first_request ကို ဖယ်ရှားလိုက်ပါ

@app.route('/')
def index():
    """Home page route."""
    return render_template('index.html')

@app.route('/set_security_level', methods=['POST'])
def set_security_level():
    """Handles setting the global security level."""
    try:
        level = int(request.form.get('level', 0))
        if 0 <= level <= 2:
            session['security_level'] = level
            # Redirect back to the page the user came from
            return redirect(request.referrer or url_for('index'))
    except ValueError:
        pass
    return redirect(request.referrer or url_for('index'))

# --- Lab 1: Injection Lab (SQLi, XSS, CmdI) ---

@app.route('/injection_lab', methods=['GET', 'POST'])
def injection_lab():
    level = get_security_level()
    output = None
    users = []
    conn = get_db_connection()
    
    # Handle Form Submissions (POST)
    if request.method == 'POST':
        action = request.form.get('action')
        
        # 1. Command Injection (CmdI)
        if action == 'ping':
            host = request.form.get('host', '127.0.0.1')
            
            if level == 2:
                # High: Strict validation
                import re
                if not re.match(r'^[a-zA-Z0-9\.-]+$', host):
                    output = "Error: Invalid host format. Command Injection Blocked."
                else:
                    output = subprocess.getoutput(f'ping -c 4 {host}')

            elif level == 1:
                # Medium: Basic filtering (easily bypassable)
                if ';' in host or '&' in host:
                    output = "Error: Filtered characters detected."
                else:
                    # Still vulnerable to many characters like `|` or `&&`
                    output = subprocess.getoutput(f'ping -c 4 {host}')
                    
            else:
                # Low: Highly vulnerable - direct execution
                output = subprocess.getoutput(f'ping -c 4 {host}')

        # 2. Stored XSS
        elif action == 'post_comment':
            author = request.form.get('author', 'Anonymous')
            message = request.form.get('message', '')
            
            if level == 2:
                # High: Full HTML escaping before storing
                message = escape_html(message)
                
            elif level == 1:
                # Medium: Basic removal of <script> (easily bypassable)
                message = message.replace('<script>', '').replace('</script>', '')
                
            # Store the data (vulnerable or secure depending on level)
            conn.execute("INSERT INTO guestbook (author, message) VALUES (?, ?)", (author, message))
            conn.commit()
            
            # Redirect to GET to avoid form resubmission
            return redirect(url_for('injection_lab')) 

    # Handle URL Parameters (GET)
    action = request.args.get('action')
    
    # 3. SQL Injection (SQLi)
    if action == 'search_user':
        username = request.args.get('username', '')
        
        if level == 2:
            # High: Parameterized query (Secure)
            sql = "SELECT id, username, secret_token FROM users WHERE username LIKE ?"
            users = conn.execute(sql, (f'%{username}%',)).fetchall()
            
        elif level == 1:
            # Medium: Basic sanitization (Bypassable)
            username_filtered = sanitize_sql(username)
            sql = f"SELECT id, username, secret_token FROM users WHERE username LIKE '%{username_filtered}%'"
            users = conn.execute(sql).fetchall()
            
        else:
            # Low: Highly vulnerable - string concatenation
            sql = f"SELECT id, username, secret_token FROM users WHERE username LIKE '%{username}%'"
            try:
                users = conn.execute(sql).fetchall()
            except sqlite3.Error as e:
                output = f"SQL Error Detected: {e}"

    # Fetch guestbook entries for XSS display
    guestbook_entries = conn.execute("SELECT * FROM guestbook ORDER BY timestamp DESC LIMIT 10").fetchall()
    
    conn.close()
    
    return render_template('injection_lab.html', level=level, users=users, output=output, guestbook_entries=guestbook_entries)

# --- Lab 2: Access Control Lab (IDOR, CSRF, Session) ---

@app.route('/access_lab', methods=['GET', 'POST'])
def access_lab():
    level = get_security_level()
    message = None
    order = None
    user_id = session.get('user_id', 101) # Default user 101
    conn = get_db_connection()

    # Temporary login for the lab
    if 'user_id' not in session:
        session['user_id'] = 101 # Alice logged in by default

    # 1. IDOR/BOLA (GET Parameter)
    order_id = request.args.get('order_id', '101') # Default order is Alice's (101)

    if order_id.isdigit():
        order_id = int(order_id)
        
        # IDOR Logic Check
        if level == 2:
            # High: Check if the retrieved order belongs to the current user
            order_data = conn.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?", (order_id, user_id)).fetchone()
            if not order_data:
                message = f"Order DENIED: You do not have permission to view Order ID {order_id}."
        elif level == 1:
            # Medium: Simple check that order exists, but still allows IDOR
            order_data = conn.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
            if order_data and order_data['user_id'] != user_id:
                 message = f"Warning: Viewing another user's order (ID: {order_data['user_id']}). IDOR vulnerability remains."
        else:
            # Low: No check at all (Highly vulnerable to IDOR)
            order_data = conn.execute("SELECT * FROM orders WHERE order_id=?", (order_id,)).fetchone()
            
        order = dict(order_data) if order_data else None

    # 2. CSRF / State Transition Abuse (POST)
    if request.method == 'POST':
        action = request.form.get('action')
        order_id_post = request.args.get('order_id') # Order ID from URL in POST request

        if action == 'cancel' and order_id_post and order_id_post.isdigit():
            order_id_post = int(order_id_post)
            
            # CSRF Token Check
            csrf_token_valid = True
            if level > 0:
                expected_token = session.get('csrf_token')
                submitted_token = request.form.get('csrf_token')
                if not expected_token or expected_token != submitted_token:
                    csrf_token_valid = False
                    message = "CSRF Token Mismatch or Missing. Access DENIED."
            
            if csrf_token_valid:
                # State Transition Abuse Check
                current_status = conn.execute("SELECT status, user_id FROM orders WHERE order_id=?", (order_id_post,)).fetchone()
                
                if current_status:
                    current_user_id = current_status['user_id']
                    
                    # 3. Access Control (IDOR) & State Transition Check
                    if current_user_id != user_id and level > 0:
                         message = "Cancellation DENIED: You cannot modify another user's order (IDOR protection active)."
                    elif current_status['status'] == 'Canceled' and level == 2:
                        message = "Cancellation DENIED: Order is already Canceled (State Transition Abuse blocked)."
                    else:
                        # Low/Medium: Vulnerable to State Transition Abuse (re-cancelling)
                        # Low: Vulnerable to IDOR on action
                        conn.execute("UPDATE orders SET status='Canceled' WHERE order_id=?", (order_id_post,))
                        conn.commit()
                        message = f"Order ID {order_id_post} successfully Canceled (even if already canceled in low level)."
                else:
                    message = f"Error: Order ID {order_id_post} not found."
                    
    # Generate CSRF Token for the next request (Medium/High)
    if level > 0:
        session['csrf_token'] = os.urandom(16).hex()

    conn.close()
    return render_template('access_lab.html', level=level, message=message, order=order, session_id_display=session.sid if hasattr(session, 'sid') else 'SESSION_ID_SIMULATION_123')


# --- Lab 3: File System Lab (LFI/RFI, Upload, Traversal) ---

# Simulated files for LFI/Traversal
SIMULATED_FILES = {
    'public_info.txt': 'This is public information about the company.\nVersion: 1.0',
    'private_data/admin_notes.txt': 'SECRET: Never launch with DEBUG mode enabled. DB_PASS=super_secret_db_pass',
    'app.py': 'from flask import ... (This is the application core code)',
}

@app.route('/file_system_lab', methods=['GET', 'POST'])
def file_system_lab():
    level = get_security_level()
    file_content = None
    file_error = None
    upload_message = None
    uploaded_filename = None
    
    # Create the 'uploads' directory if it doesn't exist
    UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    if request.method == 'GET':
        action = request.args.get('action')
        
        # 1. Path Traversal / LFI/RFI
        if action == 'read_file':
            filename = request.args.get('filename', '')
            
            # Simulated File Content (or actual file reading in the full app)
            # This simulation allows LFI/Traversal to be tested on the hardcoded file list
            def get_simulated_file_content(path):
                # Normalize path to prevent easy traversal, but keep vulnerability low level
                path = path.replace('../', '').replace('./', '')
                if path in SIMULATED_FILES:
                    return SIMULATED_FILES[path]
                return None

            if level == 2:
                # High: Only allows specific filenames and blocks external schemes
                if filename not in ['public_info.txt', 'app.py'] or urlparse(filename).scheme:
                    file_error = "Access DENIED: File access is strictly controlled. External schemes are blocked."
                else:
                    file_content = get_simulated_file_content(filename)

            elif level == 1:
                # Medium: Blocks '../' but can be bypassed with '....//' or RFI
                if '..' in filename:
                    file_error = "Access DENIED: Directory traversal ('..') is blocked. Try bypassing it."
                elif urlparse(filename).scheme in ['http', 'https', 'ftp']:
                     file_error = "Remote Inclusion Blocked."
                else:
                    file_content = get_simulated_file_content(filename)
                    if not file_content:
                         file_error = f"File {filename} not found in the simulated directory."
            else:
                # Low: Highly vulnerable LFI/RFI (Simulation is limited to SIMULATED_FILES)
                file_content = get_simulated_file_content(filename)
                if not file_content:
                    file_error = f"File {filename} not found. (Vulnerability to LFI/RFI is simulated to work on specific paths)."


    if request.method == 'POST':
        action = request.form.get('action')
        
        # 2. Unsafe File Upload
        if action == 'upload':
            if 'file' not in request.files:
                upload_message = "No file part in the request."
            else:
                file = request.files['file']
                if file.filename == '':
                    upload_message = "No selected file."
                
                if file:
                    filename = file.filename
                    
                    if level == 2:
                        # High: Strict whitelist for extensions and content check (MIME)
                        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                        ext = filename.rsplit('.', 1)[-1].lower()
                        if ext not in allowed_extensions:
                            upload_message = "Upload Error: Invalid file extension. Only images allowed."
                        else:
                             # Simulating saving a file securely
                            secure_filename = os.urandom(8).hex() + '_' + filename
                            file.save(os.path.join(UPLOAD_FOLDER, secure_filename))
                            uploaded_filename = secure_filename
                            upload_message = f"File '{filename}' uploaded successfully and securely renamed."

                    elif level == 1:
                        # Medium: Blacklist dangerous extensions (Easily bypassable)
                        blacklisted_extensions = {'php', 'phtml', 'asp', 'aspx'}
                        ext = filename.rsplit('.', 1)[-1].lower()
                        if ext in blacklisted_extensions:
                            upload_message = "Upload Error: Blacklisted file extension."
                        else:
                            file.save(os.path.join(UPLOAD_FOLDER, filename))
                            uploaded_filename = filename
                            upload_message = f"File '{filename}' uploaded successfully."
                            
                    else:
                        # Low: No validation - allows any file
                        file.save(os.path.join(UPLOAD_FOLDER, filename))
                        uploaded_filename = filename
                        upload_message = f"File '{filename}' uploaded successfully. (Web shell opportunity!)"
                        
    return render_template('file_system_lab.html', level=level, file_content=file_content, file_error=file_error, upload_message=upload_message, uploaded_filename=uploaded_filename)

# --- Lab 4: Business Logic Lab (Tampering, Race Condition) ---

@app.route('/logic_lab', methods=['GET', 'POST'])
def logic_lab():
    level = get_security_level()
    message = None
    
    # Global access to inventory state
    global INVENTORY 

    if request.method == 'POST':
        action = request.form.get('action')
        
        # 1. Pricing Manipulation / Parameter Tampering
        if action == 'purchase':
            item = request.form.get('item')
            original_price = request.form.get('original_price', '0.00')
            discount_code = request.form.get('discount_code', '')
            
            # Server-side validation check
            if level == 2:
                # High: Re-fetch price from database/config and ignore client-side price
                server_price = 100.00 if item == 'Basic_Plan' else 500.00
                if float(original_price) != server_price:
                    message = "Purchase DENIED: Client-side price mismatch. Parameter Tampering detected."
                else:
                    message = f"Purchase successful for {item} at ${server_price}. Server-side price check passed."
            
            elif level == 1:
                # Medium: Simple price check but still trusts some client input (e.g., discount)
                if float(original_price) < 10.00:
                    message = "Purchase DENIED: Price is unrealistically low."
                else:
                    message = f"Purchase successful for {item} at ${original_price} (Medium: Logic remains weak on discount calculation)."
            
            else:
                # Low: Highly vulnerable - trusts client-side hidden 'original_price'
                message = f"Purchase successful for {item} at tampered price: ${original_price}. (Logic Flaw Exploited!)"

        # 2. Logic Bypass (State Transition)
        elif action == 'activate_voucher':
            voucher_id = request.form.get('voucher_id', 'VOUCHER_123_INACTIVE')
            
            # Assume VOUCHER_123_ACTIVE is already active state
            if level == 2:
                if 'ACTIVE' in voucher_id:
                    message = "Activation DENIED: Voucher is already active. State transition blocked."
                else:
                    message = f"Voucher {voucher_id} successfully activated (State transition safe)."
            
            elif level == 1:
                if 'ACTIVE' in voucher_id and 'activate_voucher' in request.referrer:
                    message = "Activation DENIED: Basic referrer check to prevent simple replay."
                else:
                    message = f"Voucher {voucher_id} successfully activated (Medium: Vulnerable to non-referrer replay)."
                    
            else:
                # Low: No state check at all
                message = f"Voucher {voucher_id} successfully activated. (Logic flaw exploited: activated multiple times or from wrong state!)"

        # 3. Race Condition (Inventory Manipulation)
        elif action == 'buy_flag_item':
            item_name = request.form.get('item_name')
            
            if item_name in INVENTORY:
                
                # Low/Medium: Not using a transaction/lock (Vulnerable to Race)
                if level < 2:
                    
                    # Race Condition vulnerability: Check and update are separate operations
                    if INVENTORY[item_name] > 0:
                        # Simulate processing time (makes race condition easier)
                        time.sleep(0.1) 
                        INVENTORY[item_name] -= 1
                        message = f"SUCCESS: Bought {item_name}. Stock left: {INVENTORY[item_name]}."
                    else:
                        message = f"FAILURE: {item_name} is out of stock (Stock: {INVENTORY[item_name]})."
                
                else:
                    # High: Secure logic (Requires DB Transaction or Locking mechanism, simulated here)
                    # In a real app: BEGIN TRANSACTION; SELECT FOR UPDATE...
                    if INVENTORY[item_name] > 0:
                        INVENTORY[item_name] -= 1
                        message = f"SUCCESS: Bought {item_name}. Stock left: {INVENTORY[item_name]} (Race Condition Blocked)."
                    else:
                        message = f"FAILURE: {item_name} is out of stock (Stock: {INVENTORY[item_name]})."
                        
            else:
                message = "Item not found."

    return render_template('logic_lab.html', level=level, message=message, current_stock=INVENTORY['Flag-Item'])


# --- Lab 5: SSRF Lab (Server-Side Request Forgery) ---

@app.route('/ssrf_lab', methods=['GET'])
def ssrf_lab():
    level = get_security_level()
    message = None
    fetched_content = None

    action = request.args.get('action')
    if action == 'fetch_url':
        url = request.args.get('url', '')
        
        # --- Internal Fetcher Simulation ---
        # NOTE: A full SSRF lab requires a dedicated internal network or an actual HTTP client (requests).
        # We simulate the most common targets (Localhost, Metadata) for simplicity.
        
        # Simulate local and metadata access for testing
        is_internal_target = any(
            target in url for target in ['127.0.0.1', 'localhost', '169.254.169.254', 'file://']
        )
        
        if level == 2:
            # High: Strict whitelist and blocks all internal IPs/schemes
            if is_internal_target or urlparse(url).scheme not in ['http', 'https']:
                message = "Fetch Blocked: Internal network access or prohibited scheme detected."
            else:
                message = "Fetch successful. (SSRF Blocked)."
                fetched_content = f"Simulated content from external URL: {url}"
                
        elif level == 1:
            # Medium: Blacklist some internal IPs (Easily bypassable)
            if '127.0.0.1' in url or '169.254.169.254' in url:
                message = "Fetch Blocked: Direct access to 127.0.0.1/169.254.169.254 is prohibited (Bypass needed)."
            else:
                # Still vulnerable to variants like 0.0.0.0 or other internal ranges
                message = f"Fetch successful. URL: {url} (Medium: Blacklist bypassed or external target)."
                fetched_content = f"Simulated content from URL: {url}"
                if 'internal_service.txt' in url:
                    fetched_content = "This is a sensitive file from the internal network."
        else:
            # Low: No validation (Vulnerable)
            message = f"Fetch successful. URL: {url} (SSRF Vulnerable!)"
            if '127.0.0.1' in url or 'localhost' in url:
                 fetched_content = "Internal Service Running. Port 5000 is open. (Simulated)"
            elif 'file://' in url:
                 fetched_content = "File content: root:x:0:0:root:/root:/bin/bash (Simulated /etc/passwd)"
            else:
                fetched_content = f"Simulated content from external URL: {url}"

    return render_template('ssrf_lab.html', level=level, message=message, fetched_content=fetched_content)

# --- Lab 6: Advanced Injection Lab (SSTI, XXE, Deserialization) ---

# Global function outside of app.route scope if using Jinja2 Env directly (for low level SSTI)
from jinja2 import Environment

@app.route('/advanced_lab', methods=['GET', 'POST'])
def advanced_lab():
    level = get_security_level()
    output = None
    
    # 1. SSTI (GET)
    if request.method == 'GET' and request.args.get('action') == 'greet':
        name = request.args.get('name', 'Guest')
        
        if level == 2:
            # High: Rendering only a sanitized string, no template engine evaluation
            output = f"Hello, {name}. SSTI protection is active."
        elif level == 1:
            # Medium: Basic filtering for common SSTI keywords (easily bypassable)
            if '{' in name and '}' in name:
                name = name.replace('{', '').replace('}', '')
            # render_template_string is not defined, use render_template with a string input
            output = render_template('advanced_lab.html', output=f"Hello, {name}!", level=level)
        else:
            # Low: Highly vulnerable SSTI (Jinja2 default behavior)
            env = Environment()
            template = env.from_string(f"Hello, {name}!")
            output = template.render()
            
    # 2. XXE (POST)
    elif request.method == 'POST' and request.form.get('xml_data'):
        xml_data = request.form.get('xml_data')
        
        try:
            # We use ElementTree for the simulation
            import xml.etree.ElementTree as ET
            
            if level == 2:
                # High: Using a secure parser configuration (e.g., defusedxml)
                output = "XXE Blocked: Secure XML parser is used. External Entities disabled."
            else:
                # Low/Medium: Vulnerable XML parsing
                parser = ET.XMLParser()
                # Disable Entity expansion in ET is complex, we simulate the vulnerable state
                root = ET.fromstring(xml_data, parser=parser) 
                
                # Example: Extract data that could contain XXE result
                extracted_name = root.find('name').text if root.find('name') is not None else "No Name"
                
                if level == 1:
                    # Medium: Simple keyword check
                    if '<!ENTITY' in xml_data:
                        output = "XXE Warning: <!ENTITY detected. LFI/XXE potential."
                    else:
                        output = f"XML Processed (Medium): Name: {extracted_name}"
                else:
                    # Low: Highly vulnerable
                    output = f"XML Processed (Low): Name: {extracted_name}"
                    
        except ET.ParseError as e:
            output = f"XML Parsing Error: {e}"

    # 3. Deserialization (POST)
    elif request.method == 'POST' and request.form.get('yaml_data'):
        yaml_data = request.form.get('yaml_data')
        
        try:
            if level == 2:
                # High: Using safe_load or secure library
                data = yaml.safe_load(yaml_data)
                output = f"YAML Processed Safely (High): {json.dumps(data, indent=2)}"
            elif level == 1:
                # Medium: Basic keyword filter
                if '!python' in yaml_data:
                    output = "Deserialization Warning: '!python' keyword detected."
                else:
                    data = yaml.load(yaml_data, Loader=yaml.SafeLoader)
                    output = f"YAML Processed (Medium/SafeLoader): {json.dumps(data, indent=2)}"
            else:
                # Low: Highly vulnerable (Allows arbitrary code execution with a proper payload)
                # NOTE: For security reasons, we can't use yaml.unsafe_load here, 
                # so we simulate the result for the low level.
                output = "YAML Processed (Low): Deserialization vulnerability confirmed! Use a malicious payload."
                
        except yaml.YAMLError as e:
            output = f"YAML Parsing Error: {e}"

    return render_template('advanced_lab.html', level=level, output=output)


# --- Lab 7: Secrets and Cryptography Lab ---

@app.route('/secrets_lab', methods=['GET', 'POST'])
def secrets_lab():
    level = get_security_level()
    message = None
    profile_data = None
    encoded_id = base64.b64encode(b'101').decode('utf-8') # Default Alice

    # Generate a dummy encoded ID for the default user to start the lab
    user_id_to_encode = session.get('user_id', 101) 
    encoded_id = base64.b64encode(str(user_id_to_encode).encode('utf-8')).decode('utf-8')
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        # 1. Improper Cryptography / Secrets Tampering
        if action == 'view_profile':
            encoded_user_id = request.form.get('encoded_user_id', '')
            
            try:
                decoded_id_bytes = base64.b64decode(encoded_user_id)
                decoded_id = int(decoded_id_bytes.decode('utf-8'))
                
                conn = get_db_connection()
                
                # Check for IDOR on decoded ID (although the primary flaw is weak crypto)
                if level == 2 and decoded_id != session.get('user_id', 101):
                     message = "Access DENIED: Cannot view another user's profile (IDOR protection)."
                else:
                    user = conn.execute("SELECT id, username, secret_token, is_admin FROM users WHERE id=?", (decoded_id,)).fetchone()
                    if user:
                        profile_data = dict(user)
                        message = f"Profile data loaded for User ID: {decoded_id}"
                        if level == 0 and decoded_id == 1:
                            message = "SUCCESS: Admin profile viewed via Weak Cryptography/Encoding!"
                    else:
                        message = f"Error: User ID {decoded_id} not found."
                conn.close()
                
            except Exception as e:
                message = f"Error: Failed to decode/process user ID. Invalid encoded data. ({e})"

    # 2. Security Misconfiguration (Trigger Error)
    elif request.method == 'GET' and request.args.get('action') == 'trigger_error':
        if level == 0:
             # Low: Explicitly raise an error to expose stack trace (Debug Mode Simulation)
             # NOTE: The actual Flask DEBUG mode setting in app.run is what truly exposes the debugger.
             # This code simulates an internal error.
             raise Exception("A controlled internal error occurred! Check the stack trace/debug console for secrets.")
        else:
            message = "Error is logged internally, but public message is generic. (Misconfiguration blocked)."

    return render_template('secrets_lab.html', level=level, message=message, encoded_id=encoded_id, profile_data=profile_data)

# --- Lab 8: DoS / Anti-Automation Lab ---

@app.route('/dos_lab', methods=['GET'])
def dos_lab():
    level = get_security_level()
    message = None
    
    action = request.args.get('action')
    if action == 'search':
        search_query = request.args.get('search', '')
        
        # Simple Rate Limit Simulation (Only for High Level)
        if level == 2:
            # High: Basic rate limiting based on a counter/timestamp in the session or cache
            last_request_time = session.get('last_dos_request', 0)
            if time.time() - last_request_time < 0.5: # 0.5 second limit
                message = "Search Blocked: Rate limit exceeded (500ms). Try again later."
                session['last_dos_request'] = time.time() # Update time even if blocked to punish fast requests
            else:
                session['last_dos_request'] = time.time()
                message = f"Search processed successfully for '{search_query}' (Rate-limiting active)."
                
        elif level == 1:
            # Medium: Basic Time Delay (not true rate limiting, still vulnerable to concurrency)
            time.sleep(0.5)
            message = f"Search processed successfully for '{search_query}' (Time delay added to deter fast automation)."

        else:
            # Low: No rate limiting or delay (Highly vulnerable to DoS/Automation)
            # Simulate a slow resource query to highlight the DoS potential
            time.sleep(1) 
            message = f"Search processed successfully for '{search_query}'. (Low: No rate limit or concurrency control!)"

    return render_template('dos_lab.html', level=level, message=message)

# --- Error Handling (Optional: For a cleaner look when not in debug mode) ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page Not Found"), 404

# --- Run Application ---

if __name__ == '__main__':
    # Set DEBUG=True for the low level misconfiguration lab (Lab 7)
    is_debug_mode = app.config.get('DEBUG', False)
    
    # 💥 Database Initialization ကို App Context အတွင်း တစ်ကြိမ်သာ လုပ်ပါ
    with app.app_context():
        print("Initializing Database...")
        init_db()
    
    print("Starting AIO-WebSec Lab...")
    app.run(debug=is_debug_mode, host='0.0.0.0', port=8080)
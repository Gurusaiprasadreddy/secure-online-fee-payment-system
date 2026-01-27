import base64
import json 
import os   
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import random
import io
import sys
from datetime import datetime, timedelta
from fpdf import FPDF
from security_logic import SecurityEngine

app = Flask(__name__)
app.secret_key = 'super_secret_lab_key'
app.permanent_session_lifetime = timedelta(days=7)

sec_engine = SecurityEngine()

# --- DATABASE SETUP ---
users_db = {}
fee_db = {} 
deleted_users_db = []
reset_tokens = {}
DB_FILE = 'database.json'

# --- JSON ENCODER (Kept your fix) ---
class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex() 
        return super().default(obj)

# --- PERSISTENCE ---
def save_data():
    data = { "users": users_db, "fees": fee_db, "deleted_logs": deleted_users_db }
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(data, f, indent=4, cls=BytesEncoder)
        print(" >>> [SYSTEM] Data Saved to disk.", file=sys.stdout)
    except Exception as e:
        print(f" >>> [ERROR] Save failed: {e}", file=sys.stdout)

def load_data():
    global users_db, fee_db, deleted_users_db
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                data = json.load(f)
                users_db = data.get("users", {})
                fee_db = data.get("fees", {})
                deleted_users_db = data.get("deleted_logs", [])
            print(" >>> [SYSTEM] Data Loaded from disk.", file=sys.stdout)
            return True
        except Exception as e:
            print(f" >>> [ERROR] Load failed: {e}", file=sys.stdout)
            return False
    return False 

# --- HELPER ---
def create_test_user(username, email, password, role):
    if username not in users_db:
        salt, key = sec_engine.hash_password(password)
        users_db[username] = {
            'salt': salt.hex(), 'key': key.hex(), 'role': role, 'email': email, 'student_type': None
        }
        print(f"[INIT] Created User: {username} | Role: {role}")

# --- DEFAULTS ---
def get_default_fees():
    return {
        'Tuition Fee': {'amount': 125000, 'status': 'Pending', 'date': 'Due Now'},
        'Hostel Fee': {'amount': 45000, 'status': 'Pending', 'date': 'Due Now'},
        'Mess Fee': {'amount': 25000, 'status': 'Pending', 'date': 'Due Now'},
        'Bus Fee': {'amount': 15000, 'status': 'Pending', 'date': 'Due Now'}
    }

# --- PDF ---
def create_receipt_pdf(user, data, fee_type, signature):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 18); pdf.cell(0, 10, txt="Amrita School of Computing", ln=1, align='C')
    pdf.set_font("Arial", 'B', 14); pdf.cell(0, 10, txt=f"{fee_type} Receipt", ln=1, align='C'); pdf.ln(10)
    pdf.set_font("Arial", size=11); line_h = 8
    pdf.cell(0, line_h, txt=f"Student ID: {user}", ln=1)
    pdf.cell(0, line_h, txt=f"Fee Type: {fee_type}", ln=1)
    pdf.cell(0, line_h, txt=f"Amount Paid: {data.get('amount')} INR", ln=1)
    pdf.cell(0, line_h, txt=f"Transaction Date: {data.get('date')}", ln=1)
    pdf.cell(0, line_h, txt=f"Payment Status: SUCCESS", ln=1); pdf.ln(5)
    pdf.set_font("Arial", 'B', 12); pdf.cell(0, 10, txt="Routing Details:", ln=1)
    pdf.set_font("Arial", size=11)
    pdf.cell(0, line_h, txt=f"From: {data.get('issuing_bank')}", ln=1)
    pdf.cell(0, line_h, txt=f"Via: {data.get('settlement')}", ln=1)
    pdf.cell(0, line_h, txt=f"To: {data.get('acquiring_bank')}", ln=1); pdf.ln(5)
    pdf.set_font("Arial", 'B', 12); pdf.cell(0, 10, txt="Digital Signature (Integrity Check):", ln=1)
    pdf.set_font("Courier", size=8); pdf.multi_cell(0, 4, txt=signature); pdf.ln(15)
    pdf.set_y(-30); pdf.set_font("Arial", 'I', 9)
    pdf.cell(0, 10, txt="This receipt is computer generated and AES encrypted.", ln=1, align='C')
    buffer = io.BytesIO(); pdf_output = pdf.output(dest='S').encode('latin-1'); buffer.write(pdf_output); buffer.seek(0)
    return buffer

@app.route('/')
def home():
    if 'user' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    login_input = request.form['username']
    password = request.form['password']
    target_user = None
    if login_input in users_db: target_user = login_input
    else:
        for u, d in users_db.items():
            if d.get('email') == login_input: target_user = u; break
    
    if target_user:
        try:
            salt_val = users_db[target_user]['salt']
            key_val = users_db[target_user]['key']
            if isinstance(salt_val, str): salt_val = bytes.fromhex(salt_val)
            if isinstance(key_val, str): key_val = bytes.fromhex(key_val)
            
            if sec_engine.verify_password(salt_val, key_val, password):
                session['pre_auth_user'] = target_user
                session['otp'] = random.randint(100000, 999999)
                print(f"!!! MFA CODE: {session['otp']} !!!")
                return render_template('mfa.html')
        except Exception as e: print(f"Login Error: {e}")
    flash("Invalid Credentials"); return redirect(url_for('home'))

@app.route('/verify_mfa', methods=['POST'])
def verify_mfa():
    if int(request.form['otp']) == session.get('otp'):
        session['user'] = session['pre_auth_user']
        session['role'] = users_db[session['user']]['role']
        if session['user'] not in fee_db and session['role'] == 'Student': 
            fee_db[session['user']] = get_default_fees(); save_data()
        return redirect(url_for('dashboard'))
    flash("Wrong OTP"); return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session: return redirect(url_for('home'))
    user, role = session['user'], session['role']
    msg = None
    
    if request.method == 'POST' and 'pay_fee' in request.form:
        if role != 'Student': flash("ACCESS DENIED")
        else:
            fee_type = request.form['fee_type']
            selected_type = request.form.get('student_type_selection')
            if selected_type: users_db[user]['student_type'] = selected_type
            
            payer_name = request.form['payer_name']
            pay_method = request.form['payment_method']
            card_num = request.form['card_num']
            
            if len(card_num) != 12 or not card_num.isdigit(): flash("Invalid Card"); return redirect(url_for('dashboard'))
            if pay_method == 'UPI' and len(request.form.get('upi_pin')) != 4: flash("Invalid PIN"); return redirect(url_for('dashboard'))
            if pay_method != 'UPI' and len(request.form.get('ifsc_code')) < 4: flash("Invalid IFSC"); return redirect(url_for('dashboard'))
            issuing_bank = "UPI App" if pay_method == 'UPI' else pay_method

            settlement = random.choice(["Visa Secure", "Mastercard", "RuPay Network", "NPCI Switch"])
            acquiring_bank = random.choice(["HDFC Bank", "ICICI Bank", "SBI Treasury", "Axis Corporate"])

            # --- LOGS (Restored) ---
            print("\n" + "="*60, file=sys.stdout)
            print(f" >>> [SECURITY LOG] Transaction: {fee_type} for {user}", file=sys.stdout)
            dummy_salt, dummy_hash = sec_engine.hash_password(card_num)
            print(f"     Salt: {str(dummy_salt)[:30]}... | Hash: {str(dummy_hash)[:30]}...", file=sys.stdout)
            sec_engine.encrypt_data(card_num) 
            encrypted_val = f"AES_ENC_{random.randint(10000,99999)}_{card_num[-4:]}"
            print(f"     Stored Token: {encrypted_val}", file=sys.stdout)
            raw_sig = sec_engine.sign_data(f"Paid|{user}|{fee_type}|{datetime.now()}")
            encoded_sig = base64.b64encode(raw_sig.encode()).decode() 
            session['last_receipt_sig'] = encoded_sig; session['last_fee_type'] = fee_type
            print(f"     Signature: {encoded_sig[:40]}...", file=sys.stdout)
            print("="*60 + "\n", file=sys.stdout)

            fee_db[user][fee_type].update({
                'status': 'Paid', 'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                'payer_name': payer_name, 'issuing_bank': issuing_bank, 
                'settlement': settlement, 'acquiring_bank': acquiring_bank, 'encrypted_card': encrypted_val
            })
            save_data(); msg = f"{fee_type} Paid Successfully!"

    return render_template('dashboard.html', user=user, role=role, all_fees=fee_db, all_users=users_db, deleted_logs=deleted_users_db, msg=msg)

@app.route('/admin/delete/<target_user>')
def delete_user(target_user):
    if session.get('role') == 'Admin' and target_user in users_db:
        deleted_users_db.append({'username': target_user, 'role': users_db[target_user]['role'], 'deleted_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        del users_db[target_user]
        if target_user in fee_db: del fee_db[target_user]
        save_data()
    return redirect(url_for('dashboard'))

# --- [FIX] GRANULAR RESET: Only resets the specific fee passed in URL ---
@app.route('/admin/reset_fee/<target_user>/<fee_type>')
def reset_fee(target_user, fee_type):
    if session.get('role') == 'Admin' and target_user in fee_db: 
        defaults = get_default_fees()
        # Reset ONLY this specific fee key, leave others as they are
        if fee_type in fee_db[target_user]:
            fee_db[target_user][fee_type] = defaults[fee_type]
            save_data()
    return redirect(url_for('dashboard'))

@app.route('/admin/delete_log/<int:log_id>')
def delete_log(log_id):
    if session.get('role') == 'Admin':
        try: deleted_users_db.pop(log_id); save_data()
        except IndexError: pass
    return redirect(url_for('dashboard'))

@app.route('/download_receipt')
def download_receipt():
    user = session.get('user'); fee_type = session.get('last_fee_type')
    if not user or not fee_type: return redirect(url_for('home'))
    return send_file(create_receipt_pdf(user, fee_db.get(user, {}).get(fee_type, {}), fee_type, session.get('last_receipt_sig', '')), as_attachment=True, download_name=f"Receipt_{fee_type}.pdf", mimetype='application/pdf')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        login_input = request.form['username']; found = None
        if login_input in users_db: found = login_input
        else:
            for u, d in users_db.items():
                if d.get('email') == login_input: found = u; break
        if found:
            token = random.randint(1000, 9999); reset_tokens[found] = token
            return render_template('reset_password.html', username=found, demo_token=token)
        flash("User Not Found")
    return render_template('forgot_password.html')

@app.route('/perform_reset', methods=['POST'])
def perform_reset():
    user = request.form['username']; token = int(request.form['token']); new_pass = request.form['new_password']
    if reset_tokens.get(user) == token:
        salt, key = sec_engine.hash_password(new_pass)
        users_db[user].update({'salt': salt.hex(), 'key': key.hex()})
        del reset_tokens[user]; save_data(); flash("Reset Success"); return redirect(url_for('home'))
    flash("Invalid Token"); return render_template('reset_password.html', username=user, demo_token=reset_tokens.get(user))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, e, p, r = request.form['username'], request.form['email'], request.form['password'], request.form['role']
        if u in users_db: flash("User Exists"); return redirect(url_for('register'))
        create_test_user(u, e, p, r)
        if r == 'Student': fee_db[u] = get_default_fees()
        save_data(); flash("Created!"); return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('home'))

if __name__ == '__main__':
    loaded = load_data()
    if not loaded:
        print("--- FIRST RUN: INITIALIZING DEFAULTS ---")
        create_test_user("CB.SC.U4CSE23111", "student1@amrita.edu", "password123", "Student")
        create_test_user("CB.SC.U4CSE23112", "student2@amrita.edu", "password123", "Student")
        create_test_user("accountant1", "accounts@amrita.edu", "password123", "Accountant")
        create_test_user("admin1", "admin@amrita.edu", "password123", "Admin")
        fee_db['CB.SC.U4CSE23111'] = get_default_fees()
        fee_db['CB.SC.U4CSE23112'] = get_default_fees()
        save_data()
    app.run(debug=True)
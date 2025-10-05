import os
from dotenv import load_dotenv
import google.generativeai as genai
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import string
from datetime import datetime, timedelta

from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import secrets
from PIL import Image
import io
import json
from pyngrok import ngrok
import redis
from flask_session import Session

from prompt import Prompt

load_dotenv(override=True)
google_api_key = os.getenv('GEMINI_API_KEY')

EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')

genai.configure(api_key=google_api_key)
model = genai.GenerativeModel('gemini-2.5-flash')
chat_sessions = {}

system_message1 = Prompt.prompt1
system_message2 = Prompt.prompt2
system_message3 = Prompt.prompt3

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'skdex_session:'
app.config['SESSION_REDIS'] = redis.from_url('redis://127.0.0.1:6379')

db = SQLAlchemy(app)
sess = Session(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

login_manager.session_protection = "strong"
login_manager.login_message_category = "info"       

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False) 

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False, nullable=False)
    priority = db.Column(db.String(10), default='medium', nullable=False)  # low, medium, high
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('tasks', lazy=True, cascade='all, delete-orphan'))

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

def generate_otp():
    """Generate a 6-digit OTP"""
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp_code, username):
    """Send OTP email to user"""
    try:
        if not EMAIL_USER or not EMAIL_PASS:
            print("Email credentials not configured")
            return False
            
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = email
        msg['Subject'] = "SkillDEX Verification Code"

        template_path = os.path.join(os.path.dirname(__file__), 'templates', 'email.html')
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                html_template = f.read()
        except FileNotFoundError:
            print(f"Error: Email template not found at {template_path}")
            return False
        except Exception as e:
            print(f"Error reading email template file: {e}")
            return False
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: white; margin: 0; font-size: 28px;">SkillDEX</h1>
                <p style="color: rgba(255,255,255,0.9); margin: 5px 0 0 0;">Your AI Career Companion</p>
            </div>
            
            <div style="background: #ffffff; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <h2 style="color: #374151; margin-top: 0;">Hi {username}!</h2>
                <p style="color: #6b7280; line-height: 1.6;">Please use the verification code below to complete your action:</p>
                
                <div style="background: #f8fafc; border: 2px dashed #e5e7eb; padding: 20px; text-align: center; margin: 25px 0; border-radius: 8px;">
                    <h1 style="color: #4f46e5; font-size: 36px; letter-spacing: 8px; margin: 0; font-family: 'Courier New', monospace;">{otp_code}</h1>
                </div>
                
                <p style="color: #6b7280; font-size: 14px; line-height: 1.6;">
                    • This code will expire in <strong>10 minutes</strong><br>
                    • Don't share this code with anyone<br>
                    • If you didn't request this, please ignore this email
                </p>
                
                <hr style="border: none; height: 1px; background: #e5e7eb; margin: 25px 0;">
                <p style="color: #9ca3af; font-size: 12px; text-align: center;">
                    This is an automated message from SkillDEX. Please do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

@app.route("/chat_api", methods=["POST"])
@login_required
def chat_api():
    try:
        message = request.form.get("message", "").strip()
        session_id = request.form.get("session_id", "default")
        enable_streaming = request.form.get("stream", "false").lower() == "true"
        image_file = request.files.get("image")

        mode = request.form.get("mode", "").lower()

        print(f"DEBUG: Received mode = '{mode}'")
        print(f"DEBUG: Available form data = {dict(request.form)}")

        # Determine system message based on mode
        if mode == "urgent":
            system_message = system_message1
            print("DEBUG: Using system_message1 (urgent)")
        elif mode == "resume":
            system_message = system_message2    
            print("DEBUG: Using system_message2 (resume)")
        elif mode == "interview":
            system_message = system_message3
            print("DEBUG: Using system_message3 (interview)")
        else:
            system_message = system_message1 
            print(f"DEBUG: Using default system_message1, mode was '{mode}'")

        if not message and not image_file:
            return jsonify({"error": "Please provide a message or upload an image."}), 400

        # Create new session or get existing one
        if session_id not in chat_sessions:
            # Start with system prompt, then user's message
            chat_sessions[session_id] = model.start_chat(
                history=[
                    {"role": "user", "parts": [system_message]},
                    {"role": "user", "parts": [message]}
                ]
            )
        else:
            # For ongoing sessions, append user's message to history
            chat = chat_sessions[session_id]
            chat.send_message(message)
            chat_sessions[session_id] = chat

        chat = chat_sessions[session_id]

        image_part = None
        if image_file:
            print(f"Processing image: {image_file.filename}, type={image_file.mimetype}")

            if not image_file.mimetype.startswith("image/"):
                return jsonify({"error": "Unsupported file type. Please upload an image."}), 400

            if image_file.content_length and image_file.content_length > 16 * 1024 * 1024:
                return jsonify({"error": "File too large. Maximum size is 16MB."}), 413

            try:
                image_bytes = image_file.read()
                image_part = Image.open(io.BytesIO(image_bytes))
                image_part.load()
            except Exception as e:
                return jsonify({"error": f"Invalid image file: {e}"}), 400

        if not message:
            message = "Please analyze this resume image in detail"

        inputs = [message]
        if image_part is not None:
            inputs.append(image_part)

        def generate_response():
            try:
                if enable_streaming:
                    response = chat.send_message(inputs, stream=True)
                    accumulated_text = ""
                    for chunk in response:
                        if chunk.text:
                            chunk_text = chunk.text
                            accumulated_text += chunk_text
                            yield f"data: {json.dumps({'chunk': chunk_text, 'accumulated': accumulated_text})}\n\n"
                    if not accumulated_text:
                        yield f"data: {json.dumps({'chunk': 'Sorry, I could not generate a response.', 'accumulated': 'Sorry, I could not generate a response.'})}\n\n"
                else:
                    response = chat.send_message(inputs)
                    full_text = response.text if response.text else "Sorry, I could not generate a response."
                    yield f"data: {json.dumps({'chunk': full_text, 'accumulated': full_text})}\n\n"
            except Exception as e:
                print(f"Gemini API error: {e}")
                error_msg = f"I apologize, but I'm having trouble processing your request: {str(e)}"
                yield f"data: {json.dumps({'chunk': error_msg, 'accumulated': error_msg})}\n\n"
            finally:
                yield "data: [DONE]\n\n"

        if enable_streaming:
            return Response(
                generate_response(),
                mimetype="text/plain",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "Access-Control-Allow-Origin": "*",
                },
            )
        else:
            full_response = ""
            for chunk in generate_response():
                if chunk.startswith("data: ") and not chunk.strip().endswith("[DONE]"):
                    try:
                        data = json.loads(chunk[6:])
                        full_response = data.get("accumulated", "")
                    except:
                        continue
            return jsonify({"response": full_response, "session_id": session_id})

    except Exception as e:
        print(f"Chat API error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/chat_api/reset", methods=["POST"])
@login_required
def reset_chat():
    try:
        return jsonify({"message": "Chat session reset successfully"})
    except Exception as e:
        return jsonify({"error": "Failed to reset session"}), 500

##################################################################################################################################################
@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')
        
        if len(username) < 3:
            flash("Username must be at least 3 characters long.", "danger")
            return render_template('reg-log.html', form_type="register")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template('reg-log.html', form_type="register")
            
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('reg-log.html', form_type="register")
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please use a different email or login.", "danger")
            return render_template('reg-log.html', form_type="register")
            
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash("Username already taken. Please choose a different username.", "danger")
            return render_template('reg-log.html', form_type="register")
        
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        session['pending_registration'] = {
            'username': username,
            'email': email,
            'password': hashed_pw
        }

        otp_code = generate_otp()
        expires_at = datetime.utcnow() + timedelta(minutes=10)
        OTP.query.filter_by(email=email).delete() 
        otp_record = OTP(email=email, otp_code=otp_code, expires_at=expires_at)
        db.session.add(otp_record)
        db.session.commit()

        if send_otp_email(email, otp_code, username):
            session['otp_email'] = email
            session['verification_context'] = 'register'
            flash("A verification code has been sent to your email to complete your registration.", "info")
            return redirect(url_for('verify_otp'))
        else:
            flash("Failed to send verification email. Please try again.", "danger")
            session.pop('pending_registration', None) 
            return render_template('reg-log.html', form_type="register")

    return render_template('reg-log.html', form_type="register")

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_verified:
                flash("Your account is not verified. Please check your email for the OTP.", "warning")
                # You might want to redirect to an OTP verification page here
                return render_template('reg-log.html', form_type="login")
            else:
                login_user(user, remember=True)
                next_page = request.args.get('next') or url_for('dashboard')
                
                print(f"Login successful for {user.email}, redirecting to {next_page}")
                print(f"User authenticated: {current_user.is_authenticated}")
                
                return redirect(next_page)
        else:
            flash("Invalid email or password. Please try again.", "danger")
            return render_template('reg-log.html', form_type="login")
    
    return render_template('reg-log.html', form_type="login")

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.is_json

    if 'otp_email' not in session or 'verification_context' not in session:
        flash("Your verification session has expired. Please try again.", "warning")
        if is_ajax:
            return jsonify({'error': 'Session expired', 'redirect_url': url_for('login')}), 400
        return redirect(url_for('login'))

    context = session.get('verification_context')
    email = session.get('otp_email')

    if request.method == "POST":
        entered_otp = (request.json.get('otp') if request.is_json else request.form.get('otp', '')).strip()
        
        otp_record = OTP.query.filter_by(
            email=email,
            otp_code=entered_otp,
            used=False
        ).first()

        if otp_record and otp_record.expires_at > datetime.utcnow():
            otp_record.used = True
            db.session.commit()

            if context == 'register':
                reg_data = session.get('pending_registration')
                if not reg_data:
                    if is_ajax:
                        return jsonify({'error': 'Registration session expired.', 'redirect_url': url_for('register')}), 400
                    flash("Registration session expired. Please register again.", "danger")
                    return redirect(url_for('register'))
                
                new_user = User(
                            username=reg_data['username'], 
                            email=reg_data['email'], 
                            password=reg_data['password'],
                            is_verified=True 
                            )

                db.session.add(new_user)
                db.session.commit()

                session.pop('pending_registration', None)
                session.pop('otp_email', None)
                session.pop('verification_context', None)
                
                if is_ajax:
                     return jsonify({
                        'success': True, 
                        'message': 'Your account has been created successfully.',
                        'title': 'Registration Complete!',
                        'redirect_url': url_for('login')
                    })
                flash("Email verified and account created! You can now log in.", "success")
                return redirect(url_for('login'))

            elif context == 'login':
                user_id = session.get('pending_user_id')
                if not user_id:
                    if is_ajax:
                        return jsonify({'error': 'Login session expired.', 'redirect_url': url_for('login')}), 400
                    flash("Login session expired. Please log in again.", "danger")
                    return redirect(url_for('login'))
                
                user = User.query.get(user_id)
                login_user(user)

                session.pop('pending_user_id', None)
                session.pop('otp_email', None)
                session.pop('verification_context', None)
                
                next_page = request.args.get('next') or url_for('dashboard')
                if is_ajax:
                    return jsonify({
                        'success': True, 
                        'message': f'Welcome back, {user.username}!',
                        'title': 'Login Successful!',
                        'redirect_url': next_page
                    })
                flash(f"Welcome back, {user.username}!", "success")
                return redirect(next_page)
        else:
            if is_ajax:
                return jsonify({'error': 'Invalid or expired verification code.'}), 400
            flash("Invalid or expired verification code. Please try again.", "danger")
            return redirect(url_for('verify_otp'))
    
    return render_template('otp-verification.html', context=context)


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    if 'otp_email' not in session:
        return jsonify({"error": "No pending verification session found."}), 400

    email = session['otp_email']
    username = "User"
    context = session.get('verification_context')

    if context == 'register' and 'pending_registration' in session:
        username = session['pending_registration'].get('username', 'User')
    elif context == 'login':
        user = User.query.filter_by(email=email).first()
        if user:
            username = user.username
    
    otp_code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    OTP.query.filter_by(email=email, used=False).delete()
    
    otp_record = OTP(email=email, otp_code=otp_code, expires_at=expires_at)
    db.session.add(otp_record)
    db.session.commit()
    
    if send_otp_email(email, otp_code, username):
        return jsonify({"message": "A new verification code has been sent."})
    else:
        return jsonify({"error": "Failed to send the new verification code."}), 500

@app.route("/dashboard")
@login_required
def dashboard():
    user_data = {
        'conversations_count': 127,
        'tasks_completed': 34,
        'resume_score': 8.5,
        'recent_activity': []
    }
    return render_template("dashboard.html", user=current_user, stats=user_data)

@app.route("/auth")
def auth():
    return render_template('reg-log.html', form_type="login")

@app.route("/chatbot")
@login_required
def chat():
    return render_template("chatbot.html")

@app.route("/to-do")
@login_required
def to_do():
    return render_template("to-do.html")

@app.route("/api/tasks", methods=["GET"])
@login_required
def get_tasks():
    """Get all tasks for the current user"""
    try:
        tasks = Task.query.filter_by(user_id=current_user.id).order_by(Task.created_at.desc()).all()
        tasks_data = []
        
        for task in tasks:
            tasks_data.append({
                'id': task.id,
                'text': task.text,
                'completed': task.completed,
                'priority': task.priority,
                'createdAt': task.created_at.strftime('%Y-%m-%d %H:%M'),
                'updatedAt': task.updated_at.strftime('%Y-%m-%d %H:%M')
            })
        
        return jsonify({'tasks': tasks_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/tasks", methods=["POST"])
@login_required
def add_task():
    """Add a new task"""
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({'error': 'Task text is required'}), 400
        
        task_text = data['text'].strip()
        if len(task_text) == 0:
            return jsonify({'error': 'Task text cannot be empty'}), 400
        
        if len(task_text) > 200:
            return jsonify({'error': 'Task text is too long (max 200 characters)'}), 400
        
        priority = data.get('priority', 'medium')
        if priority not in ['low', 'medium', 'high']:
            priority = 'medium'
        
        new_task = Task(
            user_id=current_user.id,
            text=task_text,
            priority=priority
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        return jsonify({
            'id': new_task.id,
            'text': new_task.text,
            'completed': new_task.completed,
            'priority': new_task.priority,
            'createdAt': new_task.created_at.strftime('%Y-%m-%d %H:%M'),
            'updatedAt': new_task.updated_at.strftime('%Y-%m-%d %H:%M')
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route("/api/tasks/<int:task_id>", methods=["PUT"])
@login_required
def update_task(task_id):
    """Update a task (toggle completion, edit text, etc.)"""
    try:
        task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
        
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        data = request.get_json()
        
        if 'completed' in data:
            task.completed = bool(data['completed'])
        
        if 'text' in data:
            new_text = data['text'].strip()
            if len(new_text) == 0:
                return jsonify({'error': 'Task text cannot be empty'}), 400
            if len(new_text) > 200:
                return jsonify({'error': 'Task text is too long (max 200 characters)'}), 400
            task.text = new_text
        
        if 'priority' in data and data['priority'] in ['low', 'medium', 'high']:
            task.priority = data['priority']
        
        task.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'id': task.id,
            'text': task.text,
            'completed': task.completed,
            'priority': task.priority,
            'createdAt': task.created_at.strftime('%Y-%m-%d %H:%M'),
            'updatedAt': task.updated_at.strftime('%Y-%m-%d %H:%M')
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route("/api/tasks/<int:task_id>", methods=["DELETE"])
@login_required
def delete_task(task_id):
    """Delete a task"""
    try:
        task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
        
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        db.session.delete(task)
        db.session.commit()
        
        return jsonify({'message': 'Task deleted successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route("/api/tasks/stats", methods=["GET"])
@login_required
def get_task_stats():
    """Get task statistics for the current user"""
    try:
        total_tasks = Task.query.filter_by(user_id=current_user.id).count()
        completed_tasks = Task.query.filter_by(user_id=current_user.id, completed=True).count()
        active_tasks = total_tasks - completed_tasks
        
        today = datetime.utcnow().date()
        today_tasks = Task.query.filter_by(user_id=current_user.id).filter(
            db.func.date(Task.created_at) == today
        ).count()
        
        return jsonify({
            'total': total_tasks,
            'active': active_tasks,
            'completed': completed_tasks,
            'today': today_tasks
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/tasks/bulk", methods=["POST"])
@login_required
def bulk_task_operations():
    """Perform bulk operations on tasks"""
    try:
        data = request.get_json()
        operation = data.get('operation')
        task_ids = data.get('task_ids', [])
        
        if not operation or not task_ids:
            return jsonify({'error': 'Operation and task_ids are required'}), 400
        
        tasks = Task.query.filter(
            Task.id.in_(task_ids),
            Task.user_id == current_user.id
        ).all()
        
        if operation == 'mark_completed':
            for task in tasks:
                task.completed = True
                task.updated_at = datetime.utcnow()
        elif operation == 'mark_active':
            for task in tasks:
                task.completed = False
                task.updated_at = datetime.utcnow()
        elif operation == 'delete': 
            for task in tasks:
                db.session.delete(task)
        else:
            return jsonify({'error': 'Invalid operation'}), 400
        
        db.session.commit()
        return jsonify({'message': f'Bulk {operation} completed successfully'})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route("/api/tasks/from-chat", methods=["POST"])
@login_required
def add_task_from_chat():
    try:
        data = request.get_json()
        
        if not data or 'text' not in data:
            return jsonify({'error': 'Task text is required'}), 400
        
        task_text = data['text'].strip()
        if len(task_text) == 0:
            return jsonify({'error': 'Task text cannot be empty'}), 400
        
        if len(task_text) > 200:
            return jsonify({'error': 'Task text is too long (max 200 characters)'}), 400
        
        priority = data.get('priority', 'high')
        if priority not in ['low', 'medium', 'high']:
            priority = 'high'
        
        reason = data.get('reason', '')
        if reason:
            task_text = f"{task_text} ({reason[:50]})"
        
        new_task = Task(
            user_id=current_user.id,
            text=task_text,
            priority=priority
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'task': {
                'id': new_task.id,
                'text': new_task.text,
                'completed': new_task.completed,
                'priority': new_task.priority,
                'createdAt': new_task.created_at.strftime('%Y-%m-%d %H:%M')
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash(f"Goodbye, {username}! You have been logged out.", "info")
    return redirect(url_for('home'))

#################################################################################################################
@app.route("/health")
def health_check():
    return jsonify({"status": "healthy", "gemini_configured": bool(google_api_key)})
    
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large. Maximum size is 16MB."}), 413

@app.route("/debug/session")
def debug_session():
    return jsonify({
        'session': dict(session),
        'user_authenticated': current_user.is_authenticated if current_user.is_authenticated else False,
        'user_id': current_user.id if current_user.is_authenticated else None
    })

@app.route("/debug/users")
def debug_users():
    users = User.query.all()
    users_data = [{'id': u.id, 'email': u.email, 'is_verified': u.is_verified} for u in users]
    return jsonify(users_data)
#################################################################################################################

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    for tunnel in ngrok.get_tunnels():
        ngrok.disconnect(tunnel.public_url)

    public_url = ngrok.connect(addr=7860, proto="http")
    print("Ngrok Public URL:", public_url)

    app.run(port=7860)

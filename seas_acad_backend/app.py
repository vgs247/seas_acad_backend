# app.py
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import pymysql
import os
import json

import ftplib
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from uuid import uuid4
from flask import current_app



# --- Configuration ---
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
JWT_SECRET = os.getenv("JWT_SECRET", "please-change-this-in-prod")
JWT_EXP_HOURS = int(os.getenv("JWT_EXP_HOURS", "72"))

if not all([DB_HOST, DB_NAME, DB_USER, DB_PASSWORD]):
    # App will still start but endpoints reading DB will raise a helpful error.
    print("WARNING: Database environment variables not fully set.")

app = Flask(__name__)
UPLOAD_FOLDER = "uploads/profile_pics"
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)


def upload_file_to_bluehost(local_path, remote_filename):
    import ftplib
    import os

    # FTP credentials from environment
    ftp_host = os.getenv("FTP_HOST")
    ftp_user = os.getenv("FTP_USER")
    ftp_pass = os.getenv("FTP_PASS")
    remote_dir = os.getenv("UPLOAD_REMOTE_DIR", "course_images")  # relative to FTP home

    ftp = ftplib.FTP(ftp_host, timeout=30)
    ftp.login(ftp_user, ftp_pass)

    # Ensure the remote directory exists
    for part in remote_dir.split("/"):
        if not part:
            continue
        try:
            ftp.cwd(part)
        except ftplib.error_perm:
            ftp.mkd(part)
            ftp.cwd(part)

    # Only the filename for STOR
    filename = os.path.basename(remote_filename)

    # Upload the file
    with open(local_path, "rb") as f:
        ftp.storbinary(f"STOR {filename}", f)

    ftp.quit()

    # Web-accessible URL
    base_url = os.getenv("BASE_FILE_URL", "https://seasecurity.tech/uploads/course_images")
    return f"{base_url.rstrip('/')}/{filename}"

# --- DB connection helper ---
def get_db_connection():
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        connect_timeout=5
    )
    return conn

# --- Auth helpers ---
def create_token(user_id, username, is_admin=False):
    payload = {
        "sub": str(user_id),  #convert to string
        "username": username,
        "is_admin": is_admin,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXP_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")



def decode_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"message": "Missing or invalid Authorization header"}), 401
        
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = decode_token(token)
            
            # Convert ID to integer to match your admin check
            g.user_id = int(payload["sub"]) if "sub" in payload else None
            g.username = payload.get("username")
            
            # Optional — support admin flag in token
            g.is_admin = payload.get("is_admin", False)
            
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except Exception as e:
            return jsonify({"message": "Invalid token", "error": str(e)}), 401
        
        return f(*args, **kwargs)
    return decorated


# --- Utility: run a query convenience ---
def run_query(query, params=None, fetchone=False, fetchall=False, commit=False):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(query, params or ())
            if commit:
                conn.commit()
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
    finally:
        conn.close()

# --- Routes ---

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    required = ["first_name","last_name","username","country","phone_number","email","password","confirm_password"]
    for r in required:
        if r not in data or not str(data[r]).strip():
            return jsonify({"message": f"{r} is required"}), 400
    if data["password"] != data["confirm_password"]:
        return jsonify({"message":"Passwords do not match"}), 400

    password_hash = generate_password_hash(data["password"])
    try:
        query = """
            INSERT INTO users (first_name, last_name, username, country, phone_number, email, password_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        run_query(query, (
            data.get("first_name"),
            data.get("last_name"),
            data.get("username"),
            data.get("country"),
            data.get("phone_number"),
            data.get("email"),
            password_hash
        ), commit=True)
        return jsonify({"message":"registered"}), 201
    except pymysql.err.IntegrityError as e:
        return jsonify({"message":"username or email already exists", "error": str(e)}), 400
    except Exception as e:
        return jsonify({"message":"error creating user", "error": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "username and password required"}), 400

    # Fetch user info (with is_admin)
    user = run_query(
        "SELECT id, username, password_hash, is_admin FROM users WHERE username=%s",
        (username,),
        fetchone=True
    )

    # Invalid username or password
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"message": "invalid credentials"}), 401

    # Default is_admin=False if missing
    is_admin = bool(user.get("is_admin", False))

    # Create JWT token
    token = create_token(str(user["id"]), user["username"], is_admin=is_admin)

    return jsonify({
        "token": token,
        "user_id": user["id"],
        "username": user["username"],
        "is_admin": is_admin
    })


# --- Courses CRUD (Admin endpoints protected by JWT for simplicity) ---
@app.route("/api/courses", methods=["GET"])
def list_courses():
    rows = run_query("SELECT id as course_id, title as course_title, description, duration, total_modules, amount, category, course_image FROM courses ORDER BY created_at DESC", fetchall=True)
    # add number of lessons / num_lessons
    for r in rows:
        num_lessons = run_query("SELECT COUNT(*) AS cnt FROM modules WHERE course_id=%s", (r["course_id"],), fetchone=True)
        r["num_lessons"] = num_lessons["cnt"] if num_lessons else 0
    return jsonify(rows)

@app.route("/api/courses/<int:course_id>", methods=["GET"])
def get_course(course_id):
    c = run_query("SELECT id as course_id, title as course_title, description, duration, total_modules, amount, category, course_image FROM courses WHERE id=%s", (course_id,), fetchone=True)
    if not c:
        return jsonify({"message":"not found"}), 404
    modules = run_query("SELECT module_number, module_title, content, video_url, pdf_url, module_progress FROM modules WHERE course_id=%s ORDER BY module_number ASC", (course_id,), fetchall=True)
    c["modules"] = modules
    return jsonify(c)


ALLOWED_UPLOAD_EXT = {"png","jpg","jpeg","gif","pdf"}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_UPLOAD_EXT

def upload_file_to_bluehost(local_path, remote_filename):
    ftp_host = os.getenv("FTP_HOST")
    ftp_user = os.getenv("FTP_USER")
    ftp_pass = os.getenv("FTP_PASS")
    remote_dir = os.getenv("UPLOAD_REMOTE_DIR", "public_html/uploads/course_images")

    ftp = ftplib.FTP(ftp_host, timeout=30)
    ftp.login(ftp_user, ftp_pass)
    # change to uploads directory (ensure this exists on Bluehost)
    ftp.cwd(remote_dir)
    with open(local_path, "rb") as f:
        ftp.storbinary(f"STOR {remote_filename}", f)
    ftp.quit()

    base_url = os.getenv("BASE_FILE_URL")  # e.g. https://seasecurity.tech/uploads/profile_pics/
    return f"{base_url.rstrip('/')}/{remote_filename}"

@app.route("/api/courses", methods=["POST"])
@login_required
def add_course():
    """Admin-only: create a course and upload its image"""
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    try:
        # Use form-data for both text fields and file
        title = request.form.get("title")
        description = request.form.get("description")
        duration = request.form.get("duration")
        total_modules = request.form.get("total_modules")
        amount = request.form.get("amount")
        category = request.form.get("category")
        file = request.files.get("file")

        # Validate required fields
        if not all([title, description, duration, total_modules, amount, category]):
            return jsonify({"message": "All fields are required"}), 400

        # --- SINGLE CONNECTION TO AVOID DUPLICATES ---
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Insert course
                cur.execute("""
                    INSERT INTO courses (title, description, duration, total_modules, amount, category)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (title, description, duration, total_modules, amount, category))
                course_id = cur.lastrowid  #correct course ID from same connection

            conn.commit()
        finally:
            conn.close()

        # --- Handle Image Upload ---
        course_image = None
        if file and file.filename:
            allowed_extensions = {"jpg", "jpeg", "png"}
            ext = file.filename.rsplit(".", 1)[-1].lower()
            if ext not in allowed_extensions:
                return jsonify({"message": "File type not allowed"}), 400

            filename = secure_filename(f"course_{course_id}_{uuid4().hex}.{ext}")
            local_tmp = os.path.join("/tmp", filename)
            file.save(local_tmp)

            # Upload to Bluehost FTP
            course_image = upload_file_to_bluehost(local_tmp, filename)

            # Update course image URL in DB
            run_query(
                "UPDATE courses SET course_image=%s WHERE id=%s",
                (course_image, course_id),
                commit=True
            )

            # Clean up temp file
            if os.path.exists(local_tmp):
                os.remove(local_tmp)

        return jsonify({
            "message": "Course created successfully",
            "course_id": course_id,
            "course_image": course_image
        }), 201

    except Exception as e:
        current_app.logger.exception("Error creating course")
        return jsonify({"message": "Error creating course", "error": str(e)}), 500

@app.route("/api/courses/<int:course_id>", methods=["PUT","PATCH"])
@login_required
def update_course(course_id):
    if not getattr(g, "is_admin", False):
       return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}
    # build dynamic update
    fields = []
    vals = []
    allowed = ["title","description","duration","total_modules","amount","category","course_image"]
    for key in allowed:
        if key in data:
            fields.append(f"{key}=%s")
            vals.append(data[key])
    if not fields:
        return jsonify({"message":"no fields to update"}), 400
    vals.append(course_id)
    run_query(f"UPDATE courses SET {', '.join(fields)} WHERE id=%s", tuple(vals), commit=True)
    return jsonify({"message":"updated"})

@app.route("/api/courses/<int:course_id>", methods=["DELETE"])
@login_required
def delete_course(course_id):
    if not getattr(g, "is_admin", False):
       return jsonify({"message": "admin only"}), 403

    run_query("DELETE FROM courses WHERE id=%s", (course_id,), commit=True)
    return jsonify({"message":"deleted"})

# --- Featured courses ---
@app.route("/api/featured", methods=["GET"])
def featured_courses():
    rows = run_query("""
        SELECT c.id AS course_id, c.course_image, c.title AS course_title, c.description, c.duration, c.total_modules AS num_lessons, c.amount, c.category
        FROM featured_courses f
        JOIN courses c ON f.course_id = c.id
        ORDER BY f.created_at DESC
    """, fetchall=True)
    return jsonify(rows)

@app.route("/api/featured", methods=["POST"])
@login_required
def set_featured():
    if not getattr(g, "is_admin", False):
       return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}
    course_id = data.get("course_id")
    if not course_id:
        return jsonify({"message":"course_id required"}), 400
    run_query("INSERT INTO featured_courses (course_id) VALUES (%s)", (course_id,), commit=True)
    return jsonify({"message":"featured set"}), 201

# --- Modules endpoints ---
@app.route("/api/modules/<int:course_id>", methods=["GET"])
def get_modules(course_id):
    rows = run_query("SELECT id as module_id, module_number, module_title, content, video_url, pdf_url, module_progress FROM modules WHERE course_id=%s ORDER BY module_number ASC", (course_id,), fetchall=True)
    return jsonify(rows)

@app.route("/api/modules/<int:course_id>", methods=["GET"])
@login_required
def get_course_modules(course_id):
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    rows = run_query("""
        SELECT 
            id AS module_id,
            module_number,
            module_title,
            content,
            video_url,
            pdf_url,
            module_progress
        FROM modules 
        WHERE course_id = %s 
        ORDER BY module_number ASC
    """, (course_id,), fetchall=True)

    modules = []
    for row in rows:
        # Parse JSON safely (avoid crashing on invalid/missing JSON)
        try:
            subtitles = json.loads(row.get("content", "[]")) if row.get("content") else []
        except Exception:
            subtitles = []

        modules.append({
            "module_id": row["module_id"],
            "module_number": row["module_number"],
            "module_title": row["module_title"],
            "video_url": row.get("video_url"),
            "pdf_url": row.get("pdf_url"),
            "module_progress": row.get("module_progress"),
            "subtitles": subtitles  # structured data
        })

    return jsonify(modules), 200


@app.route("/api/module_progress/<int:module_id>", methods=["PATCH"])
@login_required
def patch_module_progress(module_id):
    data = request.get_json() or {}
    progress = data.get("module_progress")
    if progress is None:
        return jsonify({"message":"module_progress required"}), 400
    run_query("UPDATE modules SET module_progress=%s WHERE id=%s", (progress, module_id), commit=True)
    return jsonify({"message":"updated"})

# --- Enrollment / user courses ---
@app.route("/api/enroll", methods=["POST"])
@login_required
def enroll():
    data = request.get_json() or {}
    course_id = data.get("course_id")
    if not course_id:
        return jsonify({"message":"course_id required"}), 400
    # create enrollment if not exists
    existing = run_query("SELECT id FROM user_courses WHERE user_id=%s AND course_id=%s", (g.user_id, course_id), fetchone=True)
    if existing:
        return jsonify({"message":"already enrolled"}), 200
    run_query("INSERT INTO user_courses (user_id, course_id, progress) VALUES (%s,%s,%s)", (g.user_id, course_id, 0), commit=True)
    return jsonify({"message":"enrolled"}), 201

@app.route("/api/my_courses", methods=["GET"])
@login_required
def my_courses():
    rows = run_query("""
        SELECT c.id AS course_id, c.course_image, c.description, c.category, uc.progress, c.title AS course_title
        FROM user_courses uc
        JOIN courses c ON uc.course_id = c.id
        WHERE uc.user_id = %s
    """, (g.user_id,), fetchall=True)
    return jsonify(rows)

@app.route("/api/courses_started", methods=["GET"])
@login_required
def courses_started():
    rows = run_query("""
        SELECT c.id AS course_id, c.title AS course_title, c.amount, c.duration, uc.progress
        FROM user_courses uc
        JOIN courses c ON uc.course_id = c.id
        WHERE uc.user_id = %s
    """, (g.user_id,), fetchall=True)
    return jsonify(rows)

@app.route("/api/course_progress/<int:course_id>", methods=["PATCH"])
@login_required
def update_course_progress(course_id):
    data = request.get_json() or {}
    progress = data.get("progress")
    if progress is None:
        return jsonify({"message":"progress required"}), 400
    run_query("UPDATE user_courses SET progress=%s WHERE user_id=%s AND course_id=%s", (progress, g.user_id, course_id), commit=True)
    return jsonify({"message":"updated"})


@app.route("/api/admins", methods=["POST"])
@login_required
def add_admin():
    # Only admins can create other admins
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "username and password required"}), 400

    # Check if username already exists
    existing = run_query("SELECT id FROM users WHERE username=%s", (username,), fetchone=True)
    if existing:
        return jsonify({"message": "username already exists"}), 400

    # Hash the password
    password_hash = generate_password_hash(password)

    # Create new admin account
    run_query(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (%s, %s, %s)",
        (username, password_hash, True),
        commit=True
    )

    return jsonify({"message": "Admin account created successfully"}), 201




# -------------------------------
# GET USER PROFILE
# -------------------------------
@app.route("/api/profile", methods=["GET"])
@login_required
def get_profile():
    """Fetch current user's profile information"""
    user = run_query(
        "SELECT first_name, last_name, email, profile_pic FROM users WHERE id=%s",
        (g.user_id,),
        fetchone=True
    )
    if not user:
        return jsonify({"message": "User not found"}), 404

    full_name = f"{user['first_name']} {user['last_name']}".strip()
    profile_pic_url = (
        f"{request.host_url.rstrip('/')}/{user['profile_pic']}"
        if user["profile_pic"] else None
    )

    return jsonify({
        "full_name": full_name,
        "email": user["email"],
        "profile_pic": profile_pic_url
    }), 200


# -------------------------------
# CHANGE PASSWORD
# -------------------------------
@app.route("/api/profile/change-password", methods=["POST"])
@login_required
def change_password():
    """Change user's password"""
    data = request.get_json() or {}
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    if not old_password or not new_password or not confirm_password:
        return jsonify({"message": "All password fields are required"}), 400

    if new_password != confirm_password:
        return jsonify({"message": "New passwords do not match"}), 400

    # Verify old password
    user = run_query(
        "SELECT password_hash FROM users WHERE id=%s",
        (g.user_id,),
        fetchone=True
    )
    if not user or not check_password_hash(user["password_hash"], old_password):
        return jsonify({"message": "Old password is incorrect"}), 401

    # Update with new password
    new_hash = generate_password_hash(new_password)
    run_query(
        "UPDATE users SET password_hash=%s WHERE id=%s",
        (new_hash, g.user_id),
        commit=True
    )
    return jsonify({"message": "Password changed successfully"}), 200


# -------------------------------
# UPDATE PROFILE INFO (NAME, EMAIL, PROFILE PIC)
# -------------------------------
@app.route("/api/profile/update", methods=["PUT"])
@login_required
def update_profile():
    """Update user's full name, email, and profile picture"""
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    file = request.files.get("profile_pic")

    if not full_name or not email:
        return jsonify({"message": "Full name and email are required"}), 400

    try:
        # Split full name into first and last
        name_parts = full_name.strip().split(" ", 1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ""

        profile_pic_path = None

        # Handle image upload
        if file and allowed_file(file.filename):
            filename = secure_filename(f"user_{g.user_id}_" + file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            profile_pic_path = f"{UPLOAD_FOLDER}/{filename}"
            
        
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)


            # Update database with new image path
            run_query(
                "UPDATE users SET first_name=%s, last_name=%s, email=%s, profile_pic=%s WHERE id=%s",
                (first_name, last_name, email, profile_pic_path, g.user_id),
                commit=True
            )
        else:
            # Update only name and email
            run_query(
                "UPDATE users SET first_name=%s, last_name=%s, email=%s WHERE id=%s",
                (first_name, last_name, email, g.user_id),
                commit=True
            )

        return jsonify({
            "message": "Profile updated successfully",
            "full_name": f"{first_name} {last_name}".strip(),
            "email": email,
            "profile_pic": profile_pic_path
        }), 200

    except Exception as e:
        return jsonify({
            "message": "Error updating profile",
            "error": str(e)
        }), 500
        
        
        

# --- Optional: helper to create admin user if none exists ---
@app.route("/api/setup_admin", methods=["POST"])
def setup_admin():
    data = request.get_json() or {}
    if run_query("SELECT id FROM users WHERE id=1", fetchone=True):
        return jsonify({"message":"admin exists"}), 400
    pw = data.get("password")
    if not pw:
        return jsonify({"message":"password required"}), 400
    run_query("""
        INSERT INTO users (id, first_name, last_name, username, country, phone_number, email, password_hash)
        VALUES (1, 'Admin', 'Admin', 'admin', 'local', '000', 'admin@example.com', %s)
    """, (generate_password_hash(pw),), commit=True)
    return jsonify({"message":"admin created, id=1"})

# --- Health & test ---
@app.route("/api/health")
def health():
    return jsonify({"status":"ok", "time": datetime.utcnow().isoformat()})

# --- Run ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))



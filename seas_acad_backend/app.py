# app.py
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import pymysql
import os
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from datetime import datetime, timedelta

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
CORS(app)  # allow cross-origin requests for your Flutter app

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
            INSERT INTO users (first_name, middle_name, last_name, username, country, phone_number, email, password_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        run_query(query, (
            data.get("first_name"),
            data.get("middle_name"),
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
        return jsonify({"message":"username and password required"}), 400

    user = run_query("SELECT id, username, password_hash, is_admin FROM users WHERE username=%s", (username,), fetchone=True)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"message":"invalid credentials"}), 401
    is_admin = (user["id"] == 1)
    token = create_token(user["id"], user["username"], is_admin=user["is_admin"])

    return jsonify({"token": token, "user_id": user["id"], "username": user["username"]})

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

@app.route("/api/courses", methods=["POST"])
@login_required
def add_course():
    # simple admin gate: only user with id==1 is admin in this example; you should implement a real role system
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}
    required = ["title","description","duration","total_modules","amount","category"]
    for r in required:
        if r not in data:
            return jsonify({"message": f"{r} required"}), 400
    q = """
      INSERT INTO courses (title, description, duration, total_modules, amount, category, course_image)
      VALUES (%s,%s,%s,%s,%s,%s,%s)
    """
    run_query(q, (
        data["title"], data["description"], data["duration"],
        data["total_modules"], data["amount"], data["category"],
        data.get("course_image")
    ), commit=True)
    return jsonify({"message":"created"}), 201

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

@app.route("/api/modules", methods=["POST"])
@login_required
def add_module():
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}
    required = ["course_id","module_number","module_title"]
    for r in required:
        if r not in data:
            return jsonify({"message": f"{r} required"}), 400
    run_query("""
        INSERT INTO modules (course_id, module_number, module_title, content, video_url, pdf_url)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (data["course_id"], data["module_number"], data["module_title"], data.get("content"), data.get("video_url"), data.get("pdf_url")), commit=True)
    return jsonify({"message":"module created"}), 201

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

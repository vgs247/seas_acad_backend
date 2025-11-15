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
import pyotp
import qrcode
import io
import base64


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
        connect_timeout=15
    )

    # Tune per-session memory buffers (safe for shared hosting)
    try:
        with conn.cursor() as cur:
            # Use moderate safe values (Bluehost limits)
            cur.execute("SET SESSION sort_buffer_size = 262144;")  # 256 KB
            cur.execute("SET SESSION read_buffer_size = 262144;")  # 256 KB
    except Exception as e:
        print(f"Warning: could not set session buffer sizes: {e}")

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


def migrate_json_subtitles_to_db():
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("SELECT id, contents FROM modules")
        modules = cursor.fetchall()

        for m in modules:
            try:
                subtitles = json.loads(m["contents"]) if m["contents"] else []
                for sub in subtitles:
                    title = sub.get("title", "Untitled")
                    contents = json.dumps(sub)
                    cursor.execute(
                        "INSERT INTO subtitles (module_id, title, contents) VALUES (%s, %s, %s)",
                        (m["id"], title, contents)
                    )
                connection.commit()
            except Exception as e:
                print("Error migrating module", m["id"], e)

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
    twofa_token = data.get("twofa_token")  # Optional 2FA code

    if not username or not password:
        return jsonify({"message": "username and password required"}), 400

    # Fetch user info (with is_admin and 2FA fields)
    user = run_query(
        "SELECT id, username, password_hash, is_admin, twofa_enabled, twofa_secret FROM users WHERE username=%s",
        (username,),
        fetchone=True
    )

    # Invalid username or password
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"message": "invalid credentials"}), 401

    # Check if 2FA is enabled
    if user.get("twofa_enabled"):
        if not twofa_token:
            # Return special response indicating 2FA is required
            return jsonify({
                "requires_2fa": True,
                "message": "2FA code required",
                "user_id": user["id"]
            }), 202  # 202 Accepted - pending 2FA
        
        # Verify 2FA token
        totp = pyotp.TOTP(user["twofa_secret"])
        if not totp.verify(twofa_token, valid_window=1):
            return jsonify({"message": "Invalid 2FA code"}), 401

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




# /api/courses GET endpoint in app.py

@app.route("/api/courses", methods=["GET"])
def list_courses():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Fetch courses including is_free
        cursor.execute("""
            SELECT 
                id AS course_id, 
                title AS course_title, 
                description, 
                duration, 
                total_modules, 
                amount, 
                is_free,
                category, 
                course_image,
                is_published,
                continuous_assessment_enabled,
                ca_percentage,
                exam_percentage
            FROM courses 
            ORDER BY created_at DESC
        """)
        courses = cursor.fetchall()

        # Fetch module counts
        cursor.execute("""
            SELECT course_id, COUNT(*) AS cnt 
            FROM modules 
            GROUP BY course_id
        """)
        counts = {row["course_id"]: row["cnt"] for row in cursor.fetchall()}

        # Process each course
        for c in courses:
            c["num_lessons"] = counts.get(c["course_id"], 0)
            c["is_published"] = bool(c.get("is_published", 0))
            c["continuous_assessment_enabled"] = bool(c.get("continuous_assessment_enabled", 0))
            c["is_free"] = bool(c.get("is_free", 0))  # ← NEW
            c["ca_percentage"] = int(c.get("ca_percentage") or 60)
            c["exam_percentage"] = int(c.get("exam_percentage") or 40)

        cursor.close()
        conn.close()

        return jsonify(courses), 200

    except Exception as e:
        print(f"Error in /api/courses: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500
    
    
    
@app.route("/api/published_courses/<int:course_id>", methods=["GET"])
def get_published_course(course_id):
    """Return a single published course with details."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Fetch the course (only if published)
        cursor.execute("""
            SELECT 
                id AS course_id,
                title AS course_title,
                description,
                duration,
                total_modules,
                amount,
                category,
                course_image,
                is_published,
                created_at,
                updated_at
            FROM courses
            WHERE id = %s AND is_published = TRUE
        """, (course_id,))
        course = cursor.fetchone()

        if not course:
            cursor.close()
            conn.close()
            return jsonify({"message": "Course not found or not published"}), 404

        # Convert is_published to boolean
        course["is_published"] = bool(course.get("is_published"))

        # Fetch number of modules (optional)
        cursor.execute("""
            SELECT COUNT(*) AS module_count
            FROM modules
            WHERE course_id = %s
        """, (course_id,))
        module_count = cursor.fetchone()["module_count"]
        course["num_lessons"] = module_count

        cursor.close()
        conn.close()

        return jsonify(course), 200

    except Exception as e:
        print(f"Error in /api/published_courses/<course_id>: {e}")
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500


    
@app.route("/api/published_courses", methods=["GET"])
def list_published_courses():
    """Return only published courses (public route)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Fetch published courses
        cursor.execute("""
            SELECT * FROM courses 
            WHERE is_published = TRUE 
            ORDER BY created_at DESC
        """)
        courses = cursor.fetchall()

        # Fetch module counts for all courses
        cursor.execute("""
            SELECT course_id, COUNT(*) AS cnt 
            FROM modules 
            GROUP BY course_id
        """)
        counts = {row["course_id"]: row["cnt"] for row in cursor.fetchall()}

        # Process each course
        for course in courses:
            course["is_published"] = bool(course.get("is_published"))
            course["is_free"] = bool(course.get("is_free"))
            course["continuous_assessment_enabled"] = bool(course.get("continuous_assessment_enabled", 0))
            course["num_lessons"] = counts.get(course["id"], 0)  # Add module count

        cursor.close()
        conn.close()

        return jsonify(courses), 200
    except Exception as e:
        current_app.logger.exception("Error listing published courses")
        return jsonify({"message": "Internal Server Error", "error": str(e)}), 500
    
    
@app.route("/api/courses/<int:course_id>/publish", methods=["PATCH"])
@login_required
def publish_course(course_id):
    """Admin-only: publish or unpublish a course."""
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}
    publish = data.get("publish")

    if publish is None:
        return jsonify({"message": "Missing 'publish' (true/false)"}), 400

    try:
        # Ensure course exists
        course = run_query("SELECT id, title FROM courses WHERE id=%s", (course_id,), fetchone=True)
        if not course:
            return jsonify({"message": "Course not found"}), 404

        # Update publish status
        run_query(
            "UPDATE courses SET is_published=%s WHERE id=%s",
            (bool(publish), course_id),
            commit=True
        )

        # Retrieve the updated record (optional)
        updated = run_query("SELECT * FROM courses WHERE id=%s", (course_id,), fetchone=True)
        if updated:
            updated["is_published"] = bool(updated.get("is_published"))

        status = "published" if publish else "unpublished"
        return jsonify({
            "message": f"Course {status} successfully",
            "course": updated
        }), 200

    except Exception as e:
        current_app.logger.exception("Error publishing course")
        return jsonify({"message": "Error publishing course", "error": str(e)}), 500




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
        is_free = request.form.get("is_free")  # ← NEW: "true" or "false"
        file = request.files.get("file")

        # Validate required fields
        if not all([title, description, duration, total_modules, category]):
            return jsonify({"message": "All required fields must be filled"}), 400

        # ✅ Handle free course logic
        if is_free == "true":
            final_amount = 0
            final_is_free = True
        else:
            try:
                final_amount = float(amount) if amount else 0
                if final_amount <= 0:
                    return jsonify({"message": "Paid courses must have amount > 0"}), 400
                final_is_free = False
            except ValueError:
                return jsonify({"message": "Invalid amount format"}), 400

        print(f"📝 Creating course: is_free={final_is_free}, amount={final_amount}")

        # --- SINGLE CONNECTION TO AVOID DUPLICATES ---
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Insert course with is_free flag
                cur.execute("""
                    INSERT INTO courses (title, description, duration, total_modules, amount, is_free, category)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (title, description, duration, total_modules, final_amount, final_is_free, category))
                course_id = cur.lastrowid

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
            "course_image": course_image,
            "is_free": final_is_free,
            "amount": final_amount
        }), 201

    except Exception as e:
        current_app.logger.exception("Error creating course")
        return jsonify({"message": "Error creating course", "error": str(e)}), 500



@app.route("/api/courses/<int:course_id>", methods=["PUT", "PATCH"])
@login_required
def update_course(course_id):
    """Admin-only: update course details (and optionally image)"""
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    try:
        title = request.form.get("title")
        description = request.form.get("description")
        duration = request.form.get("duration")
        total_modules = request.form.get("total_modules")
        amount = request.form.get("amount")
        category = request.form.get("category")
        file = request.files.get("file")

        # Build dynamic update fields
        update_fields = []
        values = []

        if title:
            update_fields.append("title=%s")
            values.append(title)
        if description:
            update_fields.append("description=%s")
            values.append(description)
        if duration:
            update_fields.append("duration=%s")
            values.append(duration)
        if total_modules:
            update_fields.append("total_modules=%s")
            values.append(total_modules)
        if amount:
            update_fields.append("amount=%s")
            values.append(amount)
        if category:
            update_fields.append("category=%s")
            values.append(category)

        if not update_fields and not file:
            return jsonify({"message": "No fields provided to update"}), 400

        # --- Handle new image upload (optional) ---
        if file and file.filename:
            allowed_extensions = {"jpg", "jpeg", "png"}
            ext = file.filename.rsplit(".", 1)[-1].lower()
            if ext not in allowed_extensions:
                return jsonify({"message": "File type not allowed"}), 400

            filename = secure_filename(f"course_{course_id}_{uuid4().hex}.{ext}")
            local_tmp = os.path.join("/tmp", filename)
            file.save(local_tmp)

            # Upload to Bluehost
            course_image = upload_file_to_bluehost(local_tmp, filename)

            # Add to update fields
            update_fields.append("course_image=%s")
            values.append(course_image)

            # Clean up local file
            if os.path.exists(local_tmp):
                os.remove(local_tmp)

        # Update in database
        if update_fields:
            query = f"UPDATE courses SET {', '.join(update_fields)} WHERE id=%s"
            values.append(course_id)
            run_query(query, tuple(values), commit=True)

        return jsonify({
            "message": "Course updated successfully",
            "course_id": course_id
        }), 200

    except Exception as e:
        current_app.logger.exception("Error updating course")
        return jsonify({"message": "Error updating course", "error": str(e)}), 500



@app.route("/api/modules/<int:module_id>", methods=["PUT", "PATCH"])
@login_required
def update_module(module_id):
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}
    title = data.get("module_title")
    content = data.get("contents") or data.get("subtitles")  # this is your JSON structure

    # Validate
    if not title and not content:
        return jsonify({"message": "Nothing to update"}), 400

    # Prepare query parts dynamically
    fields = []
    params = []

    if title:
        fields.append("module_title = %s")
        params.append(title)

    if content:
        fields.append("content = %s")
        params.append(json.dumps(content))  # store as JSON string

    if not fields:
        return jsonify({"message": "No valid fields"}), 400

    params.append(module_id)

    # Build and run query
    query = f"UPDATE modules SET {', '.join(fields)} WHERE id = %s"
    run_query(query, tuple(params), commit=True)

    return jsonify({"message": "Module updated successfully"}), 200




@app.route("/api/modules/<int:module_id>/delete", methods=["DELETE"])
@login_required
def delete_module_content(module_id):
    """Admin-only: delete a subtitle or specific content item inside a module"""
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    try:
        data = request.get_json() or {}
        subtitle_number = data.get("subtitle_number")  # e.g. "1.3"
        content_index = data.get("content_index")      # index within the 'contents' array (optional)

        # Step 1: Fetch module content
        module = run_query("SELECT content FROM modules WHERE id = %s", (module_id,), fetchone=True)
        if not module:
            return jsonify({"message": "Module not found"}), 404

        contents = json.loads(module["content"] or "[]")
        updated_contents = []

        # Step 2: Locate the target subtitle
        deleted = False
        for sub in contents:
            if sub.get("subtitle_number") == subtitle_number:
                # If only subtitle_number given → delete entire subtitle
                if content_index is None:
                    deleted = True
                    continue  # skip adding this subtitle (delete it)

                # Otherwise → delete specific content item inside subtitle
                sub_contents = sub.get("contents", [])
                if 0 <= content_index < len(sub_contents):
                    sub_contents.pop(content_index)
                    sub["contents"] = sub_contents
                    deleted = True

            updated_contents.append(sub)

        # Step 3: Validate
        if not deleted:
            return jsonify({"message": "Target not found"}), 404

        # Step 4: Update DB
        run_query(
            "UPDATE modules SET content = %s WHERE id = %s",
            (json.dumps(updated_contents), module_id),
            commit=True
        )

        return jsonify({
            "message": "Content deleted successfully",
            "subtitle_number": subtitle_number,
            "content_index": content_index
        }), 200

    except Exception as e:
        current_app.logger.exception("Error deleting content")
        return jsonify({"message": "Error deleting content", "error": str(e)}), 500



@app.route("/api/modules/<int:module_id>", methods=["DELETE"])
@login_required
def delete_module(module_id):
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    # Check if module exists first
    existing = run_query("SELECT id FROM modules WHERE id = %s", (module_id,), fetchone=True)
    if not existing:
        return jsonify({"message": "Module not found"}), 404

    # Delete the module
    run_query("DELETE FROM modules WHERE id = %s", (module_id,), commit=True)

    return jsonify({"message": f"Module {module_id} deleted successfully"}), 200




@app.route("/api/courses/<int:course_id>", methods=["DELETE"])
@login_required
def delete_course(course_id):
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    # Check if course exists
    course = run_query("SELECT id FROM courses WHERE id=%s", (course_id,), fetchone=True)
    if not course:
        return jsonify({"message": "Course not found"}), 404

    try:
        # Start transaction
        conn = get_db_connection()
        with conn.cursor() as cur:
            # 1. Delete modules related to this course
            cur.execute("DELETE FROM modules WHERE course_id=%s", (course_id,))
            
            # 2. Delete the course itself
            cur.execute("DELETE FROM courses WHERE id=%s", (course_id,))

        conn.commit()
        conn.close()

        return jsonify({"message": "Course and all related modules deleted successfully"}), 200

    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"message": "Error deleting course", "error": str(e)}), 500

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



@app.route("/api/modules", methods=["POST"])
@login_required
def add_module():
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}

    # Accept both "subtitles" and "subtitle"
    subtitles = data.get("subtitles") or data.get("subtitle")

    required = ["course_id", "module_number", "module_title"]
    for r in required:
        if r not in data:
            return jsonify({"message": f"{r} required"}), 400

    if subtitles is None:
        return jsonify({"message": "subtitles required"}), 400

    # Convert stringified JSON to actual list if needed
    if isinstance(subtitles, str):
        try:
            subtitles = json.loads(subtitles)
        except Exception:
            return jsonify({"message": "Invalid JSON format for subtitles"}), 400

    try:
        # Store all subtitles and their content in one JSON column
        run_query("""
            INSERT INTO modules (course_id, module_number, module_title, content)
            VALUES (%s, %s, %s, %s)
        """, (
            data["course_id"],
            data["module_number"],
            data["module_title"],
            json.dumps(subtitles, ensure_ascii=False)
        ), commit=True)

        return jsonify({
            "message": "Module created successfully",
            "data": {
                "course_id": data["course_id"],
                "module_number": data["module_number"],
                "module_title": data["module_title"],
                "content": subtitles
            }
        }), 201

    except Exception as e:
        current_app.logger.exception("Error creating module")
        return jsonify({"message": "Error creating module", "error": str(e)}), 500


@app.route("/api/user/modules/<int:course_id>", methods=["GET"])
@login_required
def get_user_course_modules(course_id):
    """
    Protected: Only logged-in users who are enrolled in the course can view modules.
    """
    user_id = g.user_id

    # Check if the user is enrolled in this course
    enrolled = run_query("""
        SELECT 1 FROM user_courses
        WHERE user_id = %s AND course_id = %s
        LIMIT 1
    """, (user_id, course_id), fetchone=True)

    if not enrolled:
        return jsonify({"message": "You are not enrolled in this course"}), 403

    # Fetch course modules
    rows = run_query("""
        SELECT id AS module_id,
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

    def try_json_load(value):
        """Helper: safely parse stringified JSON if possible."""
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return value
        return value

    # Fetch all completed subtitles for this user and course
    completed_subtitles = run_query("""
        SELECT subtitle_id FROM subtitle_progress
        WHERE user_id = %s AND course_id = %s
    """, (user_id, course_id), fetchall=True)
    
    completed_ids = {row["subtitle_id"] for row in completed_subtitles}

    for row in rows:
        module_id = row["module_id"]
        
        # Decode module-level JSON fields
        row["content"] = try_json_load(row.get("content", []))
        row["video_url"] = try_json_load(row.get("video_url"))
        row["pdf_url"] = try_json_load(row.get("pdf_url"))

        # Normalize deeply nested fields and assign subtitle IDs
        if isinstance(row["content"], list):
            for subtitle_index, sub in enumerate(row["content"]):
                if isinstance(sub, dict):
                    # Generate deterministic subtitle_id: "module_id-subtitle_index"
                    subtitle_id = f"{module_id}-{subtitle_index}"
                    sub["subtitle_id"] = subtitle_id
                    sub["is_completed"] = subtitle_id in completed_ids
                    
                    # Normalize contents data
                    if "contents" in sub:
                        for item in sub["contents"]:
                            if "data" in item:
                                item["data"] = try_json_load(item["data"])

    return jsonify(rows)



@app.route("/api/modules/<int:course_id>", methods=["GET"])
def get_modules(course_id):
    rows = run_query("""
        SELECT id AS module_id,
               module_number,
               module_title,
               content,
               video_url,
               pdf_url,
               module_progress
        FROM modules
        WHERE course_id=%s
        ORDER BY module_number ASC
    """, (course_id,), fetchall=True)

    def try_json_load(value):
        """Helper: safely parse stringified JSON if possible."""
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return value
        return value

    for row in rows:
        # Decode module-level JSON fields
        row["content"] = try_json_load(row.get("content", []))
        row["video_url"] = try_json_load(row.get("video_url"))
        row["pdf_url"] = try_json_load(row.get("pdf_url"))

        # Normalize deeply nested fields (like "data" in contents)
        if isinstance(row["content"], list):
            for sub in row["content"]:
                if isinstance(sub, dict) and "contents" in sub:
                    for item in sub["contents"]:
                        if "data" in item:
                            item["data"] = try_json_load(item["data"])

    return jsonify(rows)


@app.route("/api/db-test")
def db_test():
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT NOW()")
            result = cur.fetchone()
        conn.close()
        return jsonify({"status": "ok", "time": result})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500




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
        return jsonify({"message": "course_id required"}), 400

    # Check if the course exists and whether it's free
    course = run_query(
        "SELECT id, amount, is_free FROM courses WHERE id=%s", 
        (course_id,), 
        fetchone=True
    )

    if not course:
        return jsonify({"message": "Course not found"}), 404

    # ✅ Check is_free flag (more reliable than amount)
    is_free = course.get("is_free", False)
    
    # If course is NOT free, block direct enrollment
    if not is_free:
        return jsonify({
            "message": "This course requires payment before enrollment",
            "requires_payment": True
        }), 403

    # Check if already enrolled
    existing = run_query(
        "SELECT id FROM user_courses WHERE user_id=%s AND course_id=%s", 
        (g.user_id, course_id), 
        fetchone=True
    )
    
    if existing:
        return jsonify({"message": "Already enrolled"}), 200

    # Enroll the user (for free course)
    run_query(
        "INSERT INTO user_courses (user_id, course_id, progress) VALUES (%s, %s, %s)",
        (g.user_id, course_id, 0),
        commit=True
    )

    return jsonify({"message": "Enrolled successfully"}), 201



@app.route("/api/my_courses", methods=["GET"])
@login_required
def my_courses():
    rows = run_query("""
        SELECT c.id AS course_id, 
               c.course_image, 
               c.description, 
               c.category, 
               uc.progress, 
               c.title AS course_title,
               COUNT(m.id) AS total_modules
        FROM user_courses uc
        JOIN courses c ON uc.course_id = c.id
        LEFT JOIN modules m ON m.course_id = c.id
        WHERE uc.user_id = %s
        GROUP BY c.id, c.course_image, c.description, c.category, uc.progress, c.title
    """, (g.user_id,), fetchall=True)
    return jsonify(rows)



# ========================================
# PROGRESS TRACKING ENDPOINTS
# ========================================
@app.route("/api/user/progress/<int:course_id>", methods=["GET"])
@login_required
def get_user_progress(course_id):
    """Get user's progress for a specific course"""
    try:
        # Check if user is enrolled
        enrollment = run_query("""
            SELECT progress 
            FROM user_courses 
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id), fetchone=True)
        
        if not enrollment:
            return jsonify({"message": "Not enrolled in this course"}), 403
        
        # Get completed subtitles for this user and course
        completed = run_query("""
            SELECT subtitle_id, completed_at 
            FROM subtitle_progress 
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id), fetchall=True)
        
        # Calculate total subtitles from JSON content
        modules = run_query("""
            SELECT id, content FROM modules WHERE course_id=%s
        """, (course_id,), fetchall=True)
        
        total_subtitles = 0
        for module in modules:
            content = module.get("content")
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except:
                    content = []
            
            if isinstance(content, list):
                total_subtitles += len(content)
        
        # Calculate accurate progress
        completed_count = len(completed)
        progress = round((completed_count / total_subtitles) * 100, 2) if total_subtitles > 0 else 0.0
        
        # Update stored progress in user_courses
        run_query("""
            UPDATE user_courses 
            SET progress=%s 
            WHERE user_id=%s AND course_id=%s
        """, (progress, g.user_id, course_id), commit=True)
        
        return jsonify({
            "progress": progress,
            "completed_subtitles": completed or [],
            "total_subtitles": total_subtitles,
            "completed_count": completed_count
        }), 200
        
    except Exception as e:
        current_app.logger.exception("Error fetching progress")
        return jsonify({"message": "Error fetching progress", "error": str(e)}), 500


@app.route("/api/user/complete_subtitle", methods=["POST"])
@login_required
def mark_subtitle_complete():
    """Mark a subtitle as complete and update course progress"""
    data = request.get_json() or {}
    course_id = data.get("course_id")
    subtitle_id = data.get("subtitle_id")  # Now accepts "module_id-index" format
    
    if not course_id or not subtitle_id:
        return jsonify({"message": "course_id and subtitle_id required"}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        
        # Check if user is enrolled
        cursor.execute("""
            SELECT id FROM user_courses 
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id))
        
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"message": "Not enrolled in this course"}), 403
        
        # Check if already completed (idempotent)
        cursor.execute("""
            SELECT id FROM subtitle_progress 
            WHERE user_id=%s AND course_id=%s AND subtitle_id=%s
        """, (g.user_id, course_id, subtitle_id))
        
        already_completed = cursor.fetchone()
        
        if not already_completed:
            # Mark as complete
            cursor.execute("""
                INSERT INTO subtitle_progress (user_id, course_id, subtitle_id, completed_at)
                VALUES (%s, %s, %s, NOW())
            """, (g.user_id, course_id, subtitle_id))
        
        # Calculate total subtitles in course
        cursor.execute("""
            SELECT content FROM modules WHERE course_id=%s
        """, (course_id,))
        
        modules = cursor.fetchall()
        total_subtitles = 0
        
        for module in modules:
            content = module.get("content")
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except:
                    content = []
            
            if isinstance(content, list):
                total_subtitles += len(content)
        
        # Count completed subtitles
        cursor.execute("""
            SELECT COUNT(*) as completed_count 
            FROM subtitle_progress 
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id))
        
        completed_count = cursor.fetchone()["completed_count"]
        
        # Calculate progress percentage
        progress = 0
        if total_subtitles > 0:
            progress = round((completed_count / total_subtitles) * 100, 2)
        
        # Update course progress
        cursor.execute("""
            UPDATE user_courses 
            SET progress=%s 
            WHERE user_id=%s AND course_id=%s
        """, (progress, g.user_id, course_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "message": "Subtitle marked as complete",
            "progress": progress,
            "completed_subtitles": completed_count,
            "total_subtitles": total_subtitles
        }), 200
        
    except Exception as e:
        current_app.logger.exception("Error marking subtitle complete")
        return jsonify({"message": "Error marking subtitle complete", "error": str(e)}), 500
    
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
    
    # Return the stored URL directly (already uploaded to Bluehost)
    profile_pic_url = user["profile_pic"] if user["profile_pic"] else None

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
# GET USER PROFILE PICTURE
# -------------------------------
@app.route("/api/profile/picture", methods=["GET"])
@login_required
def get_profile_picture():
    """Fetch current user's profile picture URL"""
    user = run_query(
        "SELECT profile_pic FROM users WHERE id=%s",
        (g.user_id,),
        fetchone=True
    )
    
    if not user:
        return jsonify({"message": "User not found"}), 404

    profile_pic_url = user["profile_pic"] if user["profile_pic"] else None

    return jsonify({
        "profile_pic": profile_pic_url
    }), 200
    
    
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

        profile_pic_url = None

        # Handle image upload to Bluehost
        if file and file.filename:
            allowed_extensions = {"jpg", "jpeg", "png", "gif"}
            ext = file.filename.rsplit(".", 1)[-1].lower()
            
            if ext not in allowed_extensions:
                return jsonify({"message": "File type not allowed. Use jpg, jpeg, png, or gif"}), 400

            # Generate unique filename
            filename = secure_filename(f"profile_{g.user_id}_{uuid4().hex}.{ext}")
            local_tmp = os.path.join("/tmp", filename)
            
            # Save temporarily
            file.save(local_tmp)

            # Upload to Bluehost FTP
            try:
                profile_pic_url = upload_file_to_bluehost(local_tmp, filename)
            except Exception as upload_error:
                current_app.logger.exception("Failed to upload to Bluehost")
                return jsonify({
                    "message": "Error uploading profile picture",
                    "error": str(upload_error)
                }), 500
            finally:
                # Clean up temp file
                if os.path.exists(local_tmp):
                    os.remove(local_tmp)

            # Update database with new image URL
            run_query(
                "UPDATE users SET first_name=%s, last_name=%s, email=%s, profile_pic=%s WHERE id=%s",
                (first_name, last_name, email, profile_pic_url, g.user_id),
                commit=True
            )
        else:
            # Update only name and email (no image)
            run_query(
                "UPDATE users SET first_name=%s, last_name=%s, email=%s WHERE id=%s",
                (first_name, last_name, email, g.user_id),
                commit=True
            )
            
            # Fetch existing profile pic
            user = run_query(
                "SELECT profile_pic FROM users WHERE id=%s",
                (g.user_id,),
                fetchone=True
            )
            profile_pic_url = user["profile_pic"] if user else None

        return jsonify({
            "message": "Profile updated successfully",
            "full_name": f"{first_name} {last_name}".strip(),
            "email": email,
            "profile_pic": profile_pic_url
        }), 200

    except Exception as e:
        current_app.logger.exception("Error updating profile")
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



@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"message": "No file uploaded"}), 400

    if not allowed_file(file.filename):
        return jsonify({"message": "File type not allowed"}), 400

    # Generate a unique filename
    ext = file.filename.rsplit(".", 1)[1].lower()
    filename = secure_filename(f"upload_{uuid4().hex}.{ext}")
    tmp_path = os.path.join("/tmp", filename)
    file.save(tmp_path)

    try:
        # Upload to Bluehost
        file_url = upload_file_to_bluehost(tmp_path, filename)

        # Clean up temp file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

        return jsonify({"url": file_url, "message": "File uploaded successfully"}), 201

    except Exception as e:
        current_app.logger.exception("Upload failed")
        return jsonify({"message": "Error uploading file", "error": str(e)}), 500



import os
import requests
import hmac
import hashlib
from flask import request, jsonify, current_app

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY")
BASE_URL = os.getenv("BASE_URL", "https://example.com")

# 1) INITIATE PAYMENT (called by frontend)
@app.route("/api/paystack/initiate", methods=["POST"])
@login_required
def paystack_initiate():
    data = request.get_json() or {}
    course_id = data.get("course_id")
    email = data.get("email") or g.username  # optional fallback
    amount_naira = data.get("amount")  # e.g. "43.00"

    if not course_id or not amount_naira:
        return jsonify({"message":"course_id and amount required"}), 400

    # convert to kobo (or cents)
    try:
        # Allow strings like "43.00" or numbers
        amount_kobo = int(float(amount_naira) * 100)
    except Exception:
        return jsonify({"message":"invalid amount format"}), 400

    # create a unique reference
    reference = f"course_{course_id}_{g.user_id}_{int(datetime.utcnow().timestamp()*1000)}"

    payload = {
        "email": email,
        "amount": amount_kobo,
        "reference": reference,
        "metadata": {
            "user_id": g.user_id,
            "course_id": course_id
        },
        # optional: "callback_url": f"{BASE_URL}/payment_callback"
    }

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET}",
        "Content-Type": "application/json"
    }

    resp = requests.post("https://api.paystack.co/transaction/initialize", json=payload, headers=headers, timeout=30)
    res = resp.json()

    # Save initial payment record in DB
    try:
        run_query(
            "INSERT INTO payments (user_id, course_id, reference, amount, status, paystack_response) VALUES (%s,%s,%s,%s,%s,%s)",
            (g.user_id, course_id, reference, amount_kobo, res.get("status") or "initialized", json.dumps(res)),
            commit=True
        )
    except Exception as e:
        current_app.logger.exception("Failed to create payment record")

    return jsonify(res), resp.status_code

# 2) VERIFY PAYMENT (call from frontend after checkout or use webhook)
@app.route("/api/paystack/verify/<string:reference>", methods=["GET"])
@login_required
def paystack_verify(reference):
    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET}"}
    resp = requests.get(f"https://api.paystack.co/transaction/verify/{reference}", headers=headers, timeout=30)
    data = resp.json()

    if not data.get("status"):
        return jsonify({"message":"Verification failed", "data": data}), 400

    txn = data.get("data", {})
    status = txn.get("status")
    amount = txn.get("amount")  # in kobo

    # Update payments row
    try:
        run_query("UPDATE payments SET status=%s, paystack_response=%s WHERE reference=%s",
                  (status, json.dumps(data), reference), commit=True)
    except Exception:
        current_app.logger.exception("Failed to update payment row")

    if status == "success":
        # Idempotent: ensure user_courses record exists
        # check existing enrollment
        existing = run_query("SELECT id FROM user_courses WHERE user_id=%s AND course_id=%s", (g.user_id, txn.get("metadata", {}).get("course_id")), fetchone=True)
        if not existing:
            run_query("INSERT INTO user_courses (user_id, course_id, progress) VALUES (%s, %s, %s)",
                      (g.user_id, txn.get("metadata", {}).get("course_id"), 0), commit=True)

        return jsonify({"message":"Payment verified and course granted", "data": data}), 200

    return jsonify({"message":"Payment not successful", "data": data}), 400




# 3) WEBHOOK endpoint (recommended)
# Configure this in Paystack Dashboard -> Webhooks. Use the Render public URL + /api/paystack/webhook
@app.route("/api/paystack/webhook", methods=["POST"])
def paystack_webhook():
    payload = request.get_data()
    signature = request.headers.get("x-paystack-signature", "")

    # Verify signature if you have secret (recommended)
    webhook_secret = os.getenv("PAYSTACK_WEBHOOK_SECRET", "")
    if webhook_secret:
        mac = hmac.new(webhook_secret.encode(), payload, hashlib.sha512).hexdigest()
        if not hmac.compare_digest(mac, signature):
            current_app.logger.warning("Invalid Paystack webhook signature")
            return "", 400

    event = request.get_json() or {}
    event_type = event.get("event")
    data = event.get("data", {})

    # handle transaction.success
    if event_type == "charge.success" or event_type == "transaction.success":
        reference = data.get("reference")
        status = data.get("status")
        metadata = data.get("metadata", {}) or {}
        user_id = metadata.get("user_id")
        course_id = metadata.get("course_id")

        # Update payments row and enroll user idempotently
        try:
            run_query("UPDATE payments SET status=%s, paystack_response=%s WHERE reference=%s",
                      (status, json.dumps(event), reference), commit=True)
        except Exception:
            current_app.logger.exception("Failed to update payment")

        if status == "success" and user_id and course_id:
            existing = run_query("SELECT id FROM user_courses WHERE user_id=%s AND course_id=%s", (user_id, course_id), fetchone=True)
            if not existing:
                run_query("INSERT INTO user_courses (user_id, course_id, progress) VALUES (%s,%s,%s)", (user_id, course_id, 0), commit=True)

    return "", 200



@app.route("/api/2fa/enable", methods=["POST"])
@login_required
def enable_2fa():
    """Generate a new 2FA secret and return QR code"""
    try:
        # Generate a new secret for this user
        secret = pyotp.random_base32()
        
        # Get user email for the provisioning URI
        user = run_query(
            "SELECT email, username FROM users WHERE id=%s",
            (g.user_id,),
            fetchone=True
        )
        
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        # Store the secret temporarily (not enabled yet)
        run_query(
            "UPDATE users SET twofa_secret=%s, twofa_enabled=FALSE WHERE id=%s",
            (secret, g.user_id),
            commit=True
        )
        
        # Generate provisioning URI for Google Authenticator
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=user["email"] or user["username"],
            issuer_name="MyAcademy"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for JSON response
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        img_base64 = base64.b64encode(buf.read()).decode('utf-8')
        
        return jsonify({
            "message": "2FA QR code generated",
            "qr_code": f"data:image/png;base64,{img_base64}",
            "secret": secret,  # Also send secret for manual entry
            "manual_entry_key": secret
        }), 200
        
    except Exception as e:
        current_app.logger.exception("Error enabling 2FA")
        return jsonify({"message": "Error enabling 2FA", "error": str(e)}), 500


# -------------------------------
# VERIFY 2FA - Confirm Setup
# -------------------------------
@app.route("/api/2fa/verify", methods=["POST"])
@login_required
def verify_2fa_setup():
    """Verify the 6-digit code and enable 2FA"""
    data = request.get_json() or {}
    token = data.get("token")
    
    if not token or len(token) != 6:
        return jsonify({"message": "Invalid 6-digit code"}), 400
    
    try:
        # Get user's secret
        user = run_query(
            "SELECT twofa_secret FROM users WHERE id=%s",
            (g.user_id,),
            fetchone=True
        )
        
        if not user or not user["twofa_secret"]:
            return jsonify({"message": "2FA not initialized"}), 400
        
        # Verify the token
        totp = pyotp.TOTP(user["twofa_secret"])
        
        if totp.verify(token, valid_window=1):  # Allow 1 time step tolerance
            # Enable 2FA for this user
            run_query(
                "UPDATE users SET twofa_enabled=TRUE WHERE id=%s",
                (g.user_id,),
                commit=True
            )
            
            return jsonify({
                "success": True,
                "message": "2FA enabled successfully"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Invalid code. Please try again."
            }), 400
            
    except Exception as e:
        current_app.logger.exception("Error verifying 2FA")
        return jsonify({"message": "Error verifying 2FA", "error": str(e)}), 500


# -------------------------------
# DISABLE 2FA
# -------------------------------
@app.route("/api/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    """Disable 2FA for the current user"""
    data = request.get_json() or {}
    password = data.get("password")  # Require password for security
    
    if not password:
        return jsonify({"message": "Password required to disable 2FA"}), 400
    
    try:
        # Verify password
        user = run_query(
            "SELECT password_hash FROM users WHERE id=%s",
            (g.user_id,),
            fetchone=True
        )
        
        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"message": "Incorrect password"}), 401
        
        # Disable 2FA and clear secret
        run_query(
            "UPDATE users SET twofa_enabled=FALSE, twofa_secret=NULL WHERE id=%s",
            (g.user_id,),
            commit=True
        )
        
        return jsonify({
            "success": True,
            "message": "2FA disabled successfully"
        }), 200
        
    except Exception as e:
        current_app.logger.exception("Error disabling 2FA")
        return jsonify({"message": "Error disabling 2FA", "error": str(e)}), 500


# -------------------------------
# CHECK 2FA STATUS
# -------------------------------
@app.route("/api/2fa/status", methods=["GET"])
@login_required
def check_2fa_status():
    """Check if 2FA is enabled for the current user"""
    try:
        user = run_query(
            "SELECT twofa_enabled FROM users WHERE id=%s",
            (g.user_id,),
            fetchone=True
        )
        
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        return jsonify({
            "twofa_enabled": bool(user.get("twofa_enabled"))
        }), 200
        
    except Exception as e:
        current_app.logger.exception("Error checking 2FA status")
        return jsonify({"message": "Error checking 2FA status", "error": str(e)}), 500




# Add these routes to your app.py file

# ========================================
# CONTINUOUS ASSESSMENT ROUTES
# ========================================

@app.route("/api/courses/<int:course_id>/continuous_assessment", methods=["PATCH"])
@login_required
def toggle_continuous_assessment(course_id):
    """Admin-only: Enable/disable continuous assessment for a course"""
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

    data = request.get_json() or {}
    enabled = data.get("enabled")
    ca_percentage = data.get("ca_percentage", 60)
    exam_percentage = data.get("exam_percentage", 40)

    if enabled is None:
        return jsonify({"message": "Missing 'enabled' (true/false)"}), 400

    print(f"🔧 Toggle CA Request for Course {course_id}:")
    print(f"  Input - Enabled: {enabled}, CA%: {ca_percentage}, Exam%: {exam_percentage}")

    try:
        # Check if course exists
        course = run_query(
            "SELECT id, title, continuous_assessment_enabled, ca_percentage, exam_percentage FROM courses WHERE id=%s", 
            (course_id,), 
            fetchone=True
        )
        if not course:
            return jsonify({"message": "Course not found"}), 404

        print(f"📋 Current DB state: CA={course['continuous_assessment_enabled']}, CA%={course['ca_percentage']}, Exam%={course['exam_percentage']}")

        # ✅ SMART LOGIC: Auto-adjust percentages based on enabled state
        if enabled:
            # ENABLING CA: Use user-provided split (must add to 100)
            if ca_percentage + exam_percentage != 100:
                return jsonify({
                    "message": f"CA and Exam percentages must add up to 100 (got {ca_percentage} + {exam_percentage} = {ca_percentage + exam_percentage})"
                }), 400
            
            final_ca_percentage = ca_percentage
            final_exam_percentage = exam_percentage
        else:
            # DISABLING CA: Force exam to 100%, CA to 0%
            final_ca_percentage = 0
            final_exam_percentage = 100

        print(f"📝 Final values to save: CA={enabled}, CA%={final_ca_percentage}, Exam%={final_exam_percentage}")

        # Update database with explicit transaction
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE courses 
            SET continuous_assessment_enabled = %s,
                ca_percentage = %s,
                exam_percentage = %s
            WHERE id = %s
        """, (1 if enabled else 0, int(final_ca_percentage), int(final_exam_percentage), course_id))
        
        conn.commit()
        rows_affected = cursor.rowcount
        cursor.close()
        conn.close()

        print(f"✅ Updated {rows_affected} row(s)")

        # Verify the update
        verify = run_query(
            "SELECT continuous_assessment_enabled, ca_percentage, exam_percentage FROM courses WHERE id=%s",
            (course_id,),
            fetchone=True
        )
        print(f"🔍 Verified DB state: CA={verify['continuous_assessment_enabled']}, CA%={verify['ca_percentage']}, Exam%={verify['exam_percentage']}")

        status = "enabled" if enabled else "disabled"
        message = f"Continuous Assessment {status} successfully"
        
        if not enabled:
            message += " (Exam now counts 100%)"

        return jsonify({
            "message": message,
            "continuous_assessment_enabled": bool(enabled),
            "ca_percentage": int(final_ca_percentage),
            "exam_percentage": int(final_exam_percentage)
        }), 200

    except Exception as e:
        current_app.logger.exception("Error toggling continuous assessment")
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"message": "Error updating settings", "error": str(e)}), 500

# Add/Update this route in app.py
# In app.py, update the submit_quiz_score endpoint:

@app.route("/api/user/quiz_score", methods=["POST"])
@login_required
def submit_quiz_score():
    """Submit a quiz score - now tracks attempts"""
    data = request.get_json() or {}
    course_id = data.get("course_id")
    quiz_id = data.get("quiz_id")
    module_id = data.get("module_id")
    subtitle_id = data.get("subtitle_id")
    score = data.get("score")
    max_score = data.get("max_score")
    max_attempts = data.get("max_attempts")  # ← NEW: from quiz definition
    is_final_exam = data.get("is_final_exam", False)

    if not all([course_id, quiz_id, module_id, subtitle_id, score is not None, max_score]):
        return jsonify({"message": "Missing required fields"}), 400

    try:
        percentage = (score / max_score) * 100 if max_score > 0 else 0
        
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Check current attempt count
        cursor.execute("""
            SELECT attempt_count, max_attempts 
            FROM quiz_scores
            WHERE user_id=%s AND course_id=%s AND quiz_id=%s
        """, (g.user_id, course_id, quiz_id))
        
        existing = cursor.fetchone()
        
        if existing:
            current_attempts = existing['attempt_count']
            stored_max = existing['max_attempts']
            
            # Check if attempts exhausted
            if stored_max is not None and current_attempts >= stored_max:
                cursor.close()
                conn.close()
                return jsonify({
                    "message": "Maximum attempts reached",
                    "attempts_used": current_attempts,
                    "max_attempts": stored_max
                }), 403
            
            # Increment attempt count
            new_attempt_count = current_attempts + 1
        else:
            new_attempt_count = 1

        # Record this attempt in quiz_attempts table
        cursor.execute("""
            INSERT INTO quiz_attempts 
            (user_id, course_id, quiz_id, module_id, subtitle_id, 
             attempt_number, score, max_score, percentage)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (g.user_id, course_id, quiz_id, module_id, subtitle_id,
              new_attempt_count, score, max_score, percentage))

        # Update or insert main quiz_scores record (keep best score)
        if existing:
            # Only update if new score is better
            cursor.execute("""
                UPDATE quiz_scores 
                SET score = GREATEST(score, %s),
                    percentage = GREATEST(percentage, %s),
                    attempt_count = %s,
                    completed_at = CURRENT_TIMESTAMP
                WHERE user_id=%s AND course_id=%s AND quiz_id=%s
            """, (score, percentage, new_attempt_count,
                  g.user_id, course_id, quiz_id))
        else:
            cursor.execute("""
                INSERT INTO quiz_scores 
                (user_id, course_id, quiz_id, module_id, subtitle_id, 
                 score, max_score, percentage, attempt_count, max_attempts)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (g.user_id, course_id, quiz_id, module_id, subtitle_id,
                  score, max_score, percentage, new_attempt_count, max_attempts))

        conn.commit()
        cursor.close()
        conn.close()

        # Calculate remaining attempts
        remaining = None
        if max_attempts is not None:
            remaining = max_attempts - new_attempt_count

        return jsonify({
            "message": "Quiz score submitted successfully",
            "score": score,
            "max_score": max_score,
            "percentage": percentage,
            "attempt_number": new_attempt_count,
            "attempts_remaining": remaining
        }), 200

    except Exception as e:
        current_app.logger.exception("Error submitting quiz score")
        return jsonify({"message": "Error submitting quiz score", "error": str(e)}), 500



@app.route("/api/user/quiz_attempts/<int:course_id>/<string:quiz_id>", methods=["GET"])
@login_required
def get_quiz_attempt_status(course_id, quiz_id):
    """Check how many attempts a user has left for a specific quiz"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Get quiz attempt info
        cursor.execute("""
            SELECT 
                attempt_count,
                max_attempts,
                score as best_score,
                max_score,
                percentage as best_percentage,
                completed_at as last_attempt
            FROM quiz_scores
            WHERE user_id=%s AND course_id=%s AND quiz_id=%s
        """, (g.user_id, course_id, quiz_id))
        
        attempt_data = cursor.fetchone()

        # Get all individual attempts history
        cursor.execute("""
            SELECT 
                attempt_number,
                score,
                max_score,
                percentage,
                completed_at
            FROM quiz_attempts
            WHERE user_id=%s AND course_id=%s AND quiz_id=%s
            ORDER BY attempt_number DESC
        """, (g.user_id, course_id, quiz_id))
        
        attempts_history = cursor.fetchall()

        cursor.close()
        conn.close()

        if not attempt_data:
            # User hasn't attempted this quiz yet
            return jsonify({
                "has_attempted": False,
                "attempts_used": 0,
                "max_attempts": None,  # Will be set when quiz is loaded
                "can_attempt": True,
                "attempts_remaining": None,  # Unlimited until we know max_attempts
                "attempts_history": []
            }), 200

        # Calculate remaining attempts
        attempts_used = attempt_data['attempt_count']
        max_attempts = attempt_data['max_attempts']
        
        can_attempt = True
        attempts_remaining = None
        
        if max_attempts is not None:
            attempts_remaining = max_attempts - attempts_used
            can_attempt = attempts_remaining > 0

        return jsonify({
            "has_attempted": True,
            "attempts_used": attempts_used,
            "max_attempts": max_attempts,
            "can_attempt": can_attempt,
            "attempts_remaining": attempts_remaining,
            "best_score": attempt_data['best_score'],
            "best_max_score": attempt_data['max_score'],
            "best_percentage": float(attempt_data['best_percentage']) if attempt_data['best_percentage'] else 0,
            "last_attempt_date": attempt_data['last_attempt'].isoformat() if attempt_data['last_attempt'] else None,
            "attempts_history": attempts_history
        }), 200

    except Exception as e:
        current_app.logger.exception("Error checking quiz attempts")
        return jsonify({"message": "Error checking quiz attempts", "error": str(e)}), 500
    

@app.route("/api/user/final_exam_score", methods=["POST"])
@login_required
def submit_final_exam_score():
    """Submit final exam score for a user"""
    data = request.get_json() or {}
    course_id = data.get("course_id")
    score = data.get("score")
    max_score = data.get("max_score")

    if not all([course_id, score is not None, max_score]):
        return jsonify({"message": "Missing required fields"}), 400

    try:
        percentage = (score / max_score) * 100 if max_score > 0 else 0

        # Insert or update final exam score
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        cursor.execute("""
            INSERT INTO final_exam_scores 
            (user_id, course_id, score, max_score, percentage)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            score=%s, max_score=%s, percentage=%s, completed_at=CURRENT_TIMESTAMP
        """, (g.user_id, course_id, score, max_score, percentage,
              score, max_score, percentage))

        conn.commit()
        cursor.close()
        conn.close()

        # Recalculate final grade
        _update_final_grade(g.user_id, course_id)

        return jsonify({
            "message": "Final exam score submitted successfully",
            "score": score,
            "max_score": max_score,
            "percentage": percentage
        }), 200

    except Exception as e:
        current_app.logger.exception("Error submitting final exam score")
        return jsonify({"message": "Error submitting final exam score", "error": str(e)}), 500


def _update_ca_score(user_id, course_id):
    """Calculate and update CA score from all quiz scores"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Calculate average quiz score
        cursor.execute("""
            SELECT AVG(percentage) as avg_score
            FROM quiz_scores
            WHERE user_id=%s AND course_id=%s
        """, (user_id, course_id))

        result = cursor.fetchone()
        ca_score = result["avg_score"] if result and result["avg_score"] else 0

        cursor.close()
        conn.close()

        # Update or insert into course_grades
        _upsert_course_grade(user_id, course_id, ca_score=ca_score)

    except Exception as e:
        current_app.logger.exception("Error updating CA score")


def _update_final_grade(user_id, course_id):
    """Calculate final grade based on CA and exam scores"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Get course settings
        cursor.execute("""
            SELECT continuous_assessment_enabled, ca_percentage, exam_percentage
            FROM courses WHERE id=%s
        """, (course_id,))
        course = cursor.fetchone()

        if not course:
            cursor.close()
            conn.close()
            return

        ca_enabled = course["continuous_assessment_enabled"]
        ca_weight = course["ca_percentage"] / 100 if ca_enabled else 0
        exam_weight = course["exam_percentage"] / 100 if ca_enabled else 1

        # Get CA score
        cursor.execute("""
            SELECT AVG(percentage) as avg_score
            FROM quiz_scores
            WHERE user_id=%s AND course_id=%s
        """, (user_id, course_id))
        ca_result = cursor.fetchone()
        ca_score = ca_result["avg_score"] if ca_result and ca_result["avg_score"] else 0

        # Get exam score
        cursor.execute("""
            SELECT percentage FROM final_exam_scores
            WHERE user_id=%s AND course_id=%s
        """, (user_id, course_id))
        exam_result = cursor.fetchone()
        exam_score = exam_result["percentage"] if exam_result else 0

        # Calculate final score
        if ca_enabled:
            final_score = (ca_score * ca_weight) + (exam_score * exam_weight)
        else:
            final_score = exam_score

        # Determine grade
        grade = _calculate_grade(final_score)
        passed = final_score >= 50  # Pass mark is 50%

        cursor.close()
        conn.close()

        # Update course grade
        _upsert_course_grade(
            user_id, 
            course_id, 
            ca_score=ca_score if ca_enabled else 0,
            exam_score=exam_score,
            final_score=final_score,
            grade=grade,
            passed=passed
        )

    except Exception as e:
        current_app.logger.exception("Error updating final grade")


def _upsert_course_grade(user_id, course_id, ca_score=None, exam_score=None, 
                         final_score=None, grade=None, passed=None):
    """Insert or update course grade"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Build update fields dynamically
        fields = []
        values = []

        if ca_score is not None:
            fields.append("ca_score=%s")
            values.append(ca_score)
        if exam_score is not None:
            fields.append("exam_score=%s")
            values.append(exam_score)
        if final_score is not None:
            fields.append("final_score=%s")
            values.append(final_score)
        if grade is not None:
            fields.append("grade=%s")
            values.append(grade)
        if passed is not None:
            fields.append("passed=%s")
            values.append(passed)

        if not fields:
            cursor.close()
            conn.close()
            return

        # Insert or update
        cursor.execute(f"""
            INSERT INTO course_grades 
            (user_id, course_id, ca_score, exam_score, final_score, grade, passed)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE {', '.join(fields)}
        """, (user_id, course_id, ca_score or 0, exam_score or 0, final_score or 0, 
              grade or 'F', passed or False, *values))

        conn.commit()
        cursor.close()
        conn.close()

    except Exception as e:
        current_app.logger.exception("Error upserting course grade")


def _calculate_grade(score):
    """Calculate letter grade from percentage score"""
    if score >= 90:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 80:
        return "A-"
    elif score >= 75:
        return "B+"
    elif score >= 70:
        return "B"
    elif score >= 65:
        return "B-"
    elif score >= 60:
        return "C+"
    elif score >= 55:
        return "C"
    elif score >= 50:
        return "C-"
    elif score >= 45:
        return "D"
    else:
        return "F"




@app.route("/api/user/all_grades", methods=["GET"])
@login_required
def get_all_user_grades():
    """Get all grades for all enrolled courses for the current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Get all enrolled courses with their grades
        cursor.execute("""
            SELECT 
                c.id AS course_id,
                c.title AS course_title,
                c.continuous_assessment_enabled,
                c.ca_percentage,
                c.exam_percentage,
                cg.ca_score,
                cg.exam_score,
                cg.final_score,
                cg.grade,
                cg.passed,
                cg.completed_at
            FROM user_courses uc
            JOIN courses c ON uc.course_id = c.id
            LEFT JOIN course_grades cg ON cg.user_id = uc.user_id AND cg.course_id = c.id
            WHERE uc.user_id = %s
            ORDER BY c.title ASC
        """, (g.user_id,))
        
        grades = cursor.fetchall()
        
        # Convert boolean fields
        for grade in grades:
            grade['continuous_assessment_enabled'] = bool(grade.get('continuous_assessment_enabled'))
            grade['passed'] = bool(grade.get('passed')) if grade.get('passed') is not None else None
        
        cursor.close()
        conn.close()

        return jsonify(grades), 200

    except Exception as e:
        current_app.logger.exception("Error fetching all grades")
        return jsonify({"message": "Error fetching grades", "error": str(e)}), 500


@app.route("/api/user/course_grade/<int:course_id>", methods=["GET"])
@login_required
def get_course_grade(course_id):
    """Get user's grade for a specific course"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Get course settings
        cursor.execute("""
            SELECT continuous_assessment_enabled, ca_percentage, exam_percentage, title
            FROM courses WHERE id=%s
        """, (course_id,))
        course = cursor.fetchone()

        if not course:
            cursor.close()
            conn.close()
            return jsonify({"message": "Course not found"}), 404

        # Get grade data
        cursor.execute("""
            SELECT ca_score, exam_score, final_score, grade, passed, completed_at
            FROM course_grades
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id))
        grade_data = cursor.fetchone()

        # Get quiz scores
        cursor.execute("""
            SELECT quiz_id, score, max_score, percentage, completed_at
            FROM quiz_scores
            WHERE user_id=%s AND course_id=%s
            ORDER BY completed_at DESC
        """, (g.user_id, course_id))
        quiz_scores = cursor.fetchall()

        # Get exam score
        cursor.execute("""
            SELECT score, max_score, percentage, completed_at
            FROM final_exam_scores
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id))
        exam_score = cursor.fetchone()

        cursor.close()
        conn.close()

        return jsonify({
            "course_id": course_id,
            "course_title": course["title"],
            "continuous_assessment_enabled": bool(course["continuous_assessment_enabled"]),
            "ca_percentage": course["ca_percentage"],
            "exam_percentage": course["exam_percentage"],
            "grade_data": grade_data,
            "quiz_scores": quiz_scores or [],
            "exam_score": exam_score
        }), 200

    except Exception as e:
        current_app.logger.exception("Error fetching course grade")
        return jsonify({"message": "Error fetching grade", "error": str(e)}), 500
    
    

@app.route("/api/test-db", methods=["GET"])
def test_db_connection():
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT NOW() AS server_time;")
            result = cursor.fetchone()
        return jsonify({
            "status": "success",
            "message": "Database connection successful ✅",
            "server_time": str(result["server_time"])
        }), 200
    except Exception as e:
        print("Database connection test failed:", e)
        return jsonify({
            "status": "error",
            "message": "Database connection failed ❌",
            "error": str(e)
        }), 500
    finally:
        if 'conn' in locals() and conn:
            conn.close()


# --- Health & test ---
@app.route("/api/health")
def health():
    return jsonify({"status":"ok", "time": datetime.utcnow().isoformat()})

# --- Run ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))



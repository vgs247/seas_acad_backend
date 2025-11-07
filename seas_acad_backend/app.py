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




@app.route("/api/courses", methods=["GET"])
def list_courses():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Fetch courses including is_published
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
                is_published
            FROM courses 
            ORDER BY created_at DESC
        """)
        courses = cursor.fetchall()

        # Fetch counts for all courses in one query
        cursor.execute("""
            SELECT course_id, COUNT(*) AS cnt 
            FROM modules 
            GROUP BY course_id
        """)
        counts = {row["course_id"]: row["cnt"] for row in cursor.fetchall()}

        # Attach counts and convert is_published to True/False
        for c in courses:
            c["num_lessons"] = counts.get(c["course_id"], 0)
            c["is_published"] = bool(c.get("is_published"))

        cursor.close()
        conn.close()

        return jsonify(courses), 200

    except Exception as e:
        print(f"Error in /api/courses: {e}")
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

        cursor.execute("SELECT * FROM courses WHERE is_published = TRUE ORDER BY created_at DESC")
        courses = cursor.fetchall()

        # Convert is_published from 1/0 → True/False
        for course in courses:
            course["is_published"] = bool(course.get("is_published"))

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
def get_user_modules(course_id):
    user_id = g.user_id

    try:
        # --- 1️⃣ Verify enrollment ---
        enrolled = run_query("""
            SELECT 1 FROM user_courses 
            WHERE user_id=%s AND course_id=%s
        """, (user_id, course_id), fetchone=True)

        if not enrolled:
            return jsonify({"message": "You are not enrolled in this course"}), 403

        # --- 2️⃣ Fetch all modules for that course ---
        modules = run_query("""
            SELECT 
                id AS module_id,
                course_id,
                module_number,
                module_title,
                content,
                video_url,
                pdf_url
            FROM modules
            WHERE course_id=%s
            ORDER BY module_number ASC
        """, (course_id,), fetchall=True)

        if not modules:
            return jsonify({"message": "No modules found for this course"}), 404

        # --- 3️⃣ Helper for safe JSON parsing ---
        def try_json_load(value):
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except Exception:
                    return value
            return value

        # --- 4️⃣ Fetch subtitles and progress for all modules ---
        for module in modules:
            module_id = module["module_id"]

            subtitles = run_query("""
    SELECT 
        s.id AS subtitle_id,
        s.title,
        s.contents,
        CASE WHEN sp.subtitle_id IS NOT NULL THEN 1 ELSE 0 END AS is_completed
    FROM subtitles s
    LEFT JOIN subtitle_progress sp 
        ON sp.subtitle_id = s.id AND sp.user_id = %s
    WHERE s.module_id = %s
    ORDER BY s.id ASC
""", (user_id, module_id), fetchall=True)


            # Parse JSON content
            module["content"] = try_json_load(module.get("content", []))
            module["video_url"] = try_json_load(module.get("video_url"))
            module["pdf_url"] = try_json_load(module.get("pdf_url"))

            # Parse subtitles JSON and completion state
            for sub in subtitles:
                sub["contents"] = try_json_load(sub.get("contents", {}))
                sub["is_completed"] = bool(sub["is_completed"])

            # Calculate progress
            total = len(subtitles)
            done = sum(1 for s in subtitles if s["is_completed"])
            progress = round((done / total) * 100, 2) if total else 0.0

            module["subtitles"] = subtitles
            module["module_progress"] = progress

            # Optional: Normalize nested JSON data in module["content"]
            if isinstance(module["content"], list):
                for sub in module["content"]:
                    if isinstance(sub, dict) and "contents" in sub:
                        for item in sub["contents"]:
                            if "data" in item:
                                item["data"] = try_json_load(item["data"])

        return jsonify(modules)

    except Exception as e:
        print("Error fetching user modules:", e)
        return jsonify({"message": "Server error", "error": str(e)}), 500




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

    #Check if the course exists and whether it's free
    course = run_query(
        "SELECT id, price FROM courses WHERE id=%s", 
        (course_id,), 
        fetchone=True
    )

    if not course:
        return jsonify({"message": "Course not found"}), 404

    #If course is paid, block direct enrollment
    if course["price"] and float(course["price"]) > 0:
        return jsonify({
            "message": "This course requires payment before enrollment",
            "requires_payment": True
        }), 403

    #Check if already enrolled
    existing = run_query(
        "SELECT id FROM user_courses WHERE user_id=%s AND course_id=%s", 
        (g.user_id, course_id), 
        fetchone=True
    )
    if existing:
        return jsonify({"message": "Already enrolled"}), 200

    #Enroll the user (for free course)
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
        # ✅ Check enrollment
        enrollment = run_query("""
            SELECT progress 
            FROM user_courses 
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id), fetchone=True)
        
        if not enrollment:
            return jsonify({"message": "Not enrolled in this course"}), 403

        # ✅ Get completed subtitles
        completed = run_query("""
            SELECT subtitle_id, completed_at 
            FROM subtitle_progress 
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id), fetchall=True)

        # ✅ Get total subtitle count (DB-first, fallback to JSON)
        db_count = run_query("""
            SELECT COUNT(*) AS total 
            FROM subtitles s
            INNER JOIN modules m ON s.module_id = m.id
            WHERE m.course_id = %s
        """, (course_id,), fetchone=True)

        total_subtitles = db_count["total"] or 0

        # fallback: if no subtitles found in DB, use legacy JSON content count
        if total_subtitles == 0:
            modules = run_query("SELECT content FROM modules WHERE course_id=%s", (course_id,), fetchall=True)
            for module in modules:
                content = module.get("content")
                if isinstance(content, str):
                    try:
                        content = json.loads(content)
                    except:
                        content = []
                if isinstance(content, list):
                    total_subtitles += len(content)

        # ✅ Calculate accurate progress (for live recomputation)
        completed_count = len(completed)
        progress = round((completed_count / total_subtitles) * 100, 2) if total_subtitles > 0 else enrollment["progress"]

        # ✅ Update stored progress (to keep it in sync)
        run_query("""
            UPDATE user_courses 
            SET progress=%s 
            WHERE user_id=%s AND course_id=%s
        """, (progress, g.user_id, course_id), commit=True)

        return jsonify({
            "progress": progress,
            "completed_subtitles": completed or []
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
    subtitle_id = data.get("subtitle_id")

    if not course_id or not subtitle_id:
        return jsonify({"message": "course_id and subtitle_id required"}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # ✅ Verify user enrollment
        cursor.execute("""
            SELECT id FROM user_courses 
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"message": "Not enrolled in this course"}), 403

        # ✅ Ensure subtitle belongs to that course (security check)
        cursor.execute("""
            SELECT s.id 
            FROM subtitles s
            INNER JOIN modules m ON s.module_id = m.id
            WHERE s.id=%s AND m.course_id=%s
        """, (subtitle_id, course_id))
        subtitle_exists = cursor.fetchone()
        if not subtitle_exists:
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid subtitle or not part of this course"}), 404

        # ✅ Idempotent insert
        cursor.execute("""
            SELECT id FROM subtitle_progress 
            WHERE user_id=%s AND course_id=%s AND subtitle_id=%s
        """, (g.user_id, course_id, subtitle_id))
        already_completed = cursor.fetchone()

        if not already_completed:
            cursor.execute("""
                INSERT INTO subtitle_progress (user_id, course_id, subtitle_id, completed_at)
                VALUES (%s, %s, %s, NOW())
            """, (g.user_id, course_id, subtitle_id))

        # ✅ Count total subtitles (from DB)
        cursor.execute("""
            SELECT COUNT(*) AS total 
            FROM subtitles s
            INNER JOIN modules m ON s.module_id = m.id
            WHERE m.course_id = %s
        """, (course_id,))
        total_subtitles = cursor.fetchone()["total"]

        # fallback: count legacy JSON subtitles if DB empty
        if total_subtitles == 0:
            cursor.execute("SELECT content FROM modules WHERE course_id=%s", (course_id,))
            modules = cursor.fetchall()
            for module in modules:
                content = module.get("content")
                if isinstance(content, str):
                    try:
                        content = json.loads(content)
                    except:
                        content = []
                if isinstance(content, list):
                    total_subtitles += len(content)

        # ✅ Count completed subtitles
        cursor.execute("""
            SELECT COUNT(*) AS completed_count 
            FROM subtitle_progress 
            WHERE user_id=%s AND course_id=%s
        """, (g.user_id, course_id))
        completed_count = cursor.fetchone()["completed_count"]

        # ✅ Compute progress %
        progress = 0
        if total_subtitles > 0:
            progress = round((completed_count / total_subtitles) * 100, 2)

        # ✅ Update user progress in user_courses
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



@app.route("/api/upload", methods=["POST"])
@login_required
def upload_file():
    """Upload a single file (image/pdf) and return its public URL"""
    if not getattr(g, "is_admin", False):
        return jsonify({"message": "admin only"}), 403

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



# --- Health & test ---
@app.route("/api/health")
def health():
    return jsonify({"status":"ok", "time": datetime.utcnow().isoformat()})

# --- Run ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))



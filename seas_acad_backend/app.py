from flask import Flask, jsonify, request
import pymysql
import os

app = Flask(__name__)

# Get connection details from environment variables
DB_HOST = os.getenv("DB_HOST", "tardoimy.bluehostmysql.com")
DB_NAME = os.getenv("DB_NAME", "tardoimy_seas_backend")
DB_USER = os.getenv("DB_USER", "tardoimy_seas_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "Awuye@alpha247")

def get_db_connection():
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )
    return conn

@app.route("/")
def home():
    return jsonify({"message": "SEA Academy Backend is running"})

@app.route("/courses", methods=["GET"])
def get_courses():
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id, title, description, video_url, pdf_url FROM courses;")
        rows = cur.fetchall()
    conn.close()
    return jsonify(rows)

@app.route("/add_course", methods=["POST"])
def add_course():
    data = request.get_json()
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO courses (title, description, video_url, pdf_url) VALUES (%s, %s, %s, %s)",
            (data["title"], data["description"], data["video_url"], data["pdf_url"])
        )
    conn.commit()
    conn.close()
    return jsonify({"status": "success"}), 201

@app.route("/test_db")
def test_db():
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT NOW();")
            result = cur.fetchone()
        conn.close()
        return jsonify({"status": "connected", "db_time": result[0]})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

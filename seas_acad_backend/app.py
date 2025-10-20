from flask import Flask, jsonify, request
import psycopg2
import os

app = Flask(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
    return conn

@app.route("/")
def home():
    return jsonify({"message": "SEA Academy Backend is running"})

@app.route("/courses", methods=["GET"])
def get_courses():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, title, description, video_url, pdf_url FROM courses;")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify([
        {"id": r[0], "title": r[1], "description": r[2], "video_url": r[3], "pdf_url": r[4]}
        for r in rows
    ])

@app.route("/add_course", methods=["POST"])
def add_course():
    data = request.get_json()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO courses (title, description, video_url, pdf_url) VALUES (%s, %s, %s, %s)",
        (data["title"], data["description"], data["video_url"], data["pdf_url"])
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"status": "success"}), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)

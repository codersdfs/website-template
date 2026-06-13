import os, secrets, string
from datetime import datetime

def _load_secrets():
    if os.path.exists("/etc/secrets"):
        for f in os.listdir("/etc/secrets"):
            fp = os.path.join("/etc/secrets", f)
            if os.path.isfile(fp):
                with open(fp) as fh:
                    os.environ.setdefault(f, fh.read().strip())
    env_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())

_load_secrets()

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'sakura.db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class Booking(db.Model):
    __tablename__ = "bookings"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    guests = db.Column(db.String(20), nullable=False)
    experience = db.Column(db.String(100), nullable=False)
    special_requests = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Admin(db.Model):
    __tablename__ = "admins"
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(200), nullable=False)


def _ensure_admin_exists():
    with app.app_context():
        db.create_all()
        if Admin.query.count() == 0:
            password = os.environ.get("ADMIN_PASSWORD", "admin123")
            admin = Admin(password_hash=generate_password_hash(password))
            db.session.add(admin)
            db.session.commit()
            print("=" * 60)
            print("  SAKURA ADMIN PANEL — PASSWORD SET")
            print(f"  URL:      http://localhost:5000/sakura-owner/login")
            print(f"  Password:  {password}")
            print("=" * 60)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/reserve", methods=["POST"])
def reserve():
    try:
        data = request.get_json(silent=True) or request.form
        required = ["name", "email", "date", "time", "guests", "experience"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            return jsonify({"status": "error", "message": f"Missing fields: {', '.join(missing)}"}), 400

        booking = Booking(
            name=data["name"].strip(),
            email=data["email"].strip(),
            date=data["date"].strip(),
            time=data["time"].strip(),
            guests=data["guests"].strip(),
            experience=data["experience"].strip(),
            special_requests=data.get("special_requests", "").strip(),
        )
        db.session.add(booking)
        db.session.commit()
        return jsonify({"status": "success", "message": "Reservation confirmed"}), 201

    except Exception:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Server error occurred"}), 500


@app.route("/sakura-owner/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        admin = Admin.query.first()
        if admin and check_password_hash(admin.password_hash, password):
            session["owner"] = True
            session.permanent = True
            flash("Welcome back.", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Incorrect password.", "error")
            return redirect(url_for("admin_login"))
    return render_template("admin.html", login=True)


@app.route("/sakura-owner", methods=["GET"])
def admin_dashboard():
    if not session.get("owner"):
        flash("Please log in first.", "error")
        return redirect(url_for("admin_login"))
    bookings = Booking.query.order_by(Booking.created_at.desc()).all()
    return render_template("admin.html", login=False, bookings=bookings)


@app.route("/sakura-owner/delete/<int:booking_id>", methods=["POST"])
def delete_booking(booking_id):
    if not session.get("owner"):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    try:
        booking = db.session.get(Booking, booking_id)
        if not booking:
            return jsonify({"status": "error", "message": "Booking not found"}), 404
        db.session.delete(booking)
        db.session.commit()
        return jsonify({"status": "success", "message": "Booking cancelled"}), 200
    except Exception:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Server error"}), 500


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("admin_login"))


if __name__ == "__main__":
    _ensure_admin_exists()
    app.run(debug=False, host="0.0.0.0", port=5000)

import os, io, csv
from datetime import datetime, date, timedelta
import pandas as pd
from fpdf import FPDF

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from config import Config
from sqlalchemy import text

# -------------------- App / DB / Login --------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------- Helpers --------------------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    return filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

def default_student_password(full_name: str) -> str:
    return f"{(full_name.strip()[:3] or 'stu').lower()}123"

def start_of_week(d: date) -> date:
    return d - timedelta(days=d.weekday())  # Monday start

# Template utilities
@app.context_processor
def inject_utilities():
    return {
        "now": datetime.utcnow,
        "current_year": datetime.utcnow().year,
        "today_iso": date.today().isoformat()
    }

# --- lightweight schema patcher for SQLite (safe no-op if already present) ---
def _has_col(table, col):
    res = db.session.execute(text(f"PRAGMA table_info({table});")).mappings().all()
    return any(r["name"] == col for r in res)

def ensure_schema():
    applied = []
    try:
        # Assignment
        if not _has_col("assignment", "allow_text"):
            db.session.execute(text("ALTER TABLE assignment ADD COLUMN allow_text BOOLEAN DEFAULT 1;"))
            applied.append("assignment.allow_text")
        if not _has_col("assignment", "allow_pdf"):
            db.session.execute(text("ALTER TABLE assignment ADD COLUMN allow_pdf BOOLEAN DEFAULT 1;"))
            applied.append("assignment.allow_pdf")
        if not _has_col("assignment", "max_score"):
            db.session.execute(text("ALTER TABLE assignment ADD COLUMN max_score INTEGER DEFAULT 100;"))
            applied.append("assignment.max_score")
        # Submission
        if not _has_col("submission", "score"):
            db.session.execute(text("ALTER TABLE submission ADD COLUMN score REAL;"))
            applied.append("submission.score")
        if applied:
            db.session.commit()
            print("Schema patched:", ", ".join(applied))
        else:
            print("Schema OK")
    except Exception as e:
        print("Schema patch failed:", e)

# -------------------- Models --------------------
class Role:
    ADMIN = "ADMIN"
    TEACHER = "TEACHER"
    STUDENT = "STUDENT"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # ADMIN/TEACHER/STUDENT
    class_name = db.Column(db.String(50))  # for students
    dob = db.Column(db.String(10))  # YYYY-MM-DD
    security_pin = db.Column(db.String(10))  # 4-6 digits recommended
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)
    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

class TeacherAttendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, default=date.today, index=True)
    sign_in_time = db.Column(db.DateTime, nullable=True)
    sign_out_time = db.Column(db.DateTime, nullable=True)
    teacher = db.relationship('User', backref='attendance_records')

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    due_date = db.Column(db.DateTime, nullable=True)
    class_name = db.Column(db.String(50), nullable=True)  # None => All classes
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # submission controls
    allow_text = db.Column(db.Boolean, default=True)
    allow_pdf  = db.Column(db.Boolean, default=True)
    max_score  = db.Column(db.Integer, default=100)
    teacher = db.relationship('User', backref='assignments', foreign_keys=[created_by])

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    pdf_path = db.Column(db.String(300), nullable=True)
    text_answer = db.Column(db.Text, nullable=True)
    score = db.Column(db.Float, nullable=True)
    grade = db.Column(db.String(20), nullable=True)
    feedback = db.Column(db.Text, nullable=True)
    assignment = db.relationship('Assignment', backref='submissions')
    student = db.relationship('User', backref='submissions', foreign_keys=[student_id])

class ClassCatalog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class SubjectCatalog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    class_name = db.Column(db.String(50), nullable=True)
    __table_args__ = (db.UniqueConstraint('name', 'class_name', name='uq_subject_class'),)

class LessonNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(120), nullable=False)
    topic = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="PENDING")  # PENDING/APPROVED/REVISE
    admin_comment = db.Column(db.Text, nullable=True)
    teacher = db.relationship('User', backref='lesson_notes')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- CLI seed helper --------------------
@app.cli.command("initdb")
def initdb_command():
    db.create_all()
    ensure_schema()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", full_name="System Admin", role=Role.ADMIN, security_pin="9999")
        admin.set_password("admin123")
        db.session.add(admin); db.session.commit()
        print("Initialized DB + admin (admin/admin123)")
    else:
        print("DB exists; admin present.")

# -------------------- Auth & Reset --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/password-reset", methods=["GET", "POST"])
def password_reset():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "")
        pin = request.form.get("security_pin", "").strip()
        dob = request.form.get("dob", "").strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            flash("No such user.", "danger"); return redirect(request.url)
        verified = False
        if user.security_pin and pin and user.security_pin == pin: verified = True
        if user.dob and dob and user.dob == dob: verified = True
        if not verified:
            flash("Verification failed. Provide correct Security PIN or DOB (YYYY-MM-DD).", "warning")
            return redirect(request.url)
        if len(new_password) < 6:
            flash("Password too short (min 6).", "warning"); return redirect(request.url)
        user.set_password(new_password); db.session.commit()
        flash("Password reset successful. You can login now.", "success")
        return redirect(url_for("login"))
    return render_template("password_reset.html")

# -------------------- Dashboard --------------------
@app.route("/")
@login_required
def dashboard():
    if current_user.role == Role.ADMIN:
        teachers = User.query.filter_by(role=Role.TEACHER).count()
        students = User.query.filter_by(role=Role.STUDENT).count()
        assignments = Assignment.query.count()
        notes_pending = LessonNote.query.filter_by(status="PENDING").count()
        return render_template("admin_dashboard.html",
                               teachers=teachers, students=students,
                               assignments=assignments, notes_pending=notes_pending)
    elif current_user.role == Role.TEACHER:
        my_assignments = Assignment.query.filter_by(created_by=current_user.id).order_by(Assignment.created_at.desc()).limit(5).all()
        my_notes = LessonNote.query.filter_by(teacher_id=current_user.id).order_by(LessonNote.created_at.desc()).limit(5).all()
        return render_template("teacher_dashboard.html", my_assignments=my_assignments, my_notes=my_notes)
    else:
        items = Assignment.query.filter(
            (Assignment.class_name == current_user.class_name) | (Assignment.class_name == None)
        ).order_by(Assignment.created_at.desc()).all()
        my_subs = Submission.query.filter_by(student_id=current_user.id).all()
        return render_template("student_dashboard.html", assignments=items, my_subs=my_subs)

# -------------------- Admin: Catalogs --------------------
@app.route("/admin/catalogs", methods=["GET", "POST"])
@login_required
def admin_catalogs():
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    if request.method == "POST":
        mode = request.form.get("mode")
        if mode == "add_class":
            name = (request.form.get("class_name") or "").strip().upper()
            if name and not ClassCatalog.query.filter_by(name=name).first():
                db.session.add(ClassCatalog(name=name)); db.session.commit()
                flash("Class added.", "success")
            else:
                flash("Invalid / duplicate class.", "warning")
        elif mode == "add_subject":
            sname = (request.form.get("subject_name") or "").strip().title()
            cname = (request.form.get("for_class") or "").strip().upper() or None
            if sname:
                exists = SubjectCatalog.query.filter_by(name=sname, class_name=cname).first()
                if not exists:
                    db.session.add(SubjectCatalog(name=sname, class_name=cname)); db.session.commit()
                    flash("Subject added.", "success")
                else:
                    flash("Duplicate subject for class.", "warning")
            else:
                flash("Provide a subject name.", "warning")
        elif mode == "delete_class":
            cid = request.form.get("cid", type=int)
            c = ClassCatalog.query.get(cid)
            if c: db.session.delete(c); db.session.commit(); flash("Class deleted.", "info")
        elif mode == "delete_subject":
            sid = request.form.get("sid", type=int)
            s = SubjectCatalog.query.get(sid)
            if s: db.session.delete(s); db.session.commit(); flash("Subject deleted.", "info")
    classes = ClassCatalog.query.order_by(ClassCatalog.name.asc()).all()
    subjects = SubjectCatalog.query.order_by(SubjectCatalog.class_name.asc().nullsfirst(), SubjectCatalog.name.asc()).all()
    return render_template("admin_catalogs.html", classes=classes, subjects=subjects)

# -------------------- Admin: Students CRUD + CSV --------------------
@app.route("/admin/students", methods=["GET", "POST"])
@login_required
def admin_students():
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    if request.method == "POST":
        mode = request.form.get("mode")
        if mode == "add_one":
            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip()
            class_name = request.form.get("class_name", "").strip() or None
            dob = request.form.get("dob", "").strip() or None
            pin = request.form.get("security_pin", "").strip() or None
            if not full_name or not username:
                flash("Full name and username required.", "warning")
            elif User.query.filter_by(username=username).first():
                flash("Username exists.", "danger")
            else:
                u = User(username=username, full_name=full_name, role=Role.STUDENT,
                         class_name=class_name, dob=dob, security_pin=pin)
                u.set_password(default_student_password(full_name))
                db.session.add(u); db.session.commit()
                flash("Student added.", "success")
        elif mode == "import_csv":
            file = request.files.get("csv_file")
            if not file or not file.filename:
                flash("Select a CSV file.", "warning")
            else:
                try:
                    rows = 0
                    text_rows = file.stream.read().decode("utf-8").splitlines()
                    reader = csv.DictReader(text_rows)
                    for r in reader:
                        full_name = (r.get("full_name") or r.get("name") or "").strip()
                        username = (r.get("username") or "").strip()
                        class_name = (r.get("class_name") or "").strip() or None
                        dob = (r.get("dob") or "").strip() or None
                        pin = (r.get("security_pin") or "").strip() or None
                        if not full_name or not username: continue
                        if User.query.filter_by(username=username).first(): continue
                        u = User(username=username, full_name=full_name, role=Role.STUDENT,
                                 class_name=class_name, dob=dob, security_pin=pin)
                        u.set_password(default_student_password(full_name))
                        db.session.add(u); rows += 1
                    db.session.commit()
                    flash(f"Imported {rows} students.", "success")
                except Exception as e:
                    flash(f"Import failed: {e}", "danger")
    q = request.args.get("q", "").strip()
    query = User.query.filter_by(role=Role.STUDENT)
    if q:
        like = f"%{q}%"
        query = query.filter((User.full_name.ilike(like)) | (User.username.ilike(like)) | (User.class_name.ilike(like)))
    students = query.order_by(User.class_name, User.full_name).all()
    classes = ClassCatalog.query.order_by(ClassCatalog.name.asc()).all()
    return render_template("admin_students.html", students=students, q=q, classes=classes)

@app.route("/admin/students/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def admin_student_edit(user_id):
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    u = User.query.get_or_404(user_id)
    if u.role != Role.STUDENT: return ("Forbidden", 403)
    if request.method == "POST":
        u.full_name = request.form.get("full_name", "").strip()
        u.username = request.form.get("username", "").strip()
        u.class_name = request.form.get("class_name", "").strip() or None
        u.dob = request.form.get("dob", "").strip() or None
        u.security_pin = request.form.get("security_pin", "").strip() or None
        if not u.full_name or not u.username:
            flash("Full name and username required.", "warning")
        else:
            other = User.query.filter(User.username == u.username, User.id != u.id).first()
            if other:
                flash("Username already taken.", "danger")
            else:
                db.session.commit()
                flash("Student updated.", "success")
                return redirect(url_for("admin_students"))
    classes = ClassCatalog.query.order_by(ClassCatalog.name.asc()).all()
    return render_template("admin_student_edit.html", u=u, classes=classes)

@app.route("/admin/students/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_student_delete(user_id):
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    u = User.query.get_or_404(user_id)
    if u.role != Role.STUDENT: return ("Forbidden", 403)
    db.session.delete(u); db.session.commit()
    flash("Student deleted.", "info")
    return redirect(url_for("admin_students"))

# -------------------- Admin: Teachers CRUD + CSV --------------------
@app.route("/admin/teachers", methods=["GET", "POST"])
@login_required
def admin_teachers():
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    if request.method == "POST":
        mode = request.form.get("mode")
        if mode == "add_one":
            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip()
            pin = request.form.get("security_pin", "").strip() or None
            if not full_name or not username:
                flash("Full name and username required.", "warning")
            elif User.query.filter_by(username=username).first():
                flash("Username exists.", "danger")
            else:
                u = User(username=username, full_name=full_name, role=Role.TEACHER, security_pin=pin)
                u.set_password("teacher123")
                db.session.add(u); db.session.commit()
                flash("Teacher added.", "success")
        elif mode == "import_csv":
            file = request.files.get("csv_file")
            if not file or not file.filename:
                flash("Select a CSV file.", "warning")
            else:
                try:
                    rows = 0
                    text_rows = file.stream.read().decode("utf-8").splitlines()
                    reader = csv.DictReader(text_rows)
                    for r in reader:
                        full_name = (r.get("full_name") or r.get("name") or "").strip()
                        username = (r.get("username") or "").strip()
                        pin = (r.get("security_pin") or "").strip() or None
                        if not full_name or not username: continue
                        if User.query.filter_by(username=username).first(): continue
                        u = User(username=username, full_name=full_name, role=Role.TEACHER, security_pin=pin)
                        u.set_password("teacher123")
                        db.session.add(u); rows += 1
                    db.session.commit()
                    flash(f"Imported {rows} teachers.", "success")
                except Exception as e:
                    flash(f"Import failed: {e}", "danger")
    q = request.args.get("q", "").strip()
    query = User.query.filter_by(role=Role.TEACHER)
    if q:
        like = f"%{q}%"
        query = query.filter((User.full_name.ilike(like)) | (User.username.ilike(like)))
    teachers = query.order_by(User.full_name).all()
    return render_template("admin_teachers.html", teachers=teachers, q=q)

@app.route("/admin/teachers/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
def admin_teacher_edit(user_id):
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    u = User.query.get_or_404(user_id)
    if u.role != Role.TEACHER: return ("Forbidden", 403)
    if request.method == "POST":
        u.full_name = request.form.get("full_name", "").strip()
        u.username = request.form.get("username", "").strip()
        u.security_pin = request.form.get("security_pin", "").strip() or None
        if not u.full_name or not u.username:
            flash("Full name and username required.", "warning")
        else:
            other = User.query.filter(User.username == u.username, User.id != u.id).first()
            if other:
                flash("Username already taken.", "danger")
            else:
                db.session.commit()
                flash("Teacher updated.", "success")
                return redirect(url_for("admin_teachers"))
    return render_template("admin_teacher_edit.html", u=u)

@app.route("/admin/teachers/<int:user_id>/delete", methods=["POST"])
@login_required
def admin_teacher_delete(user_id):
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    u = User.query.get_or_404(user_id)
    if u.role != Role.TEACHER: return ("Forbidden", 403)
    db.session.delete(u); db.session.commit()
    flash("Teacher deleted.", "info")
    return redirect(url_for("admin_teachers"))

# -------------------- Admin: Force Reset Password --------------------
@app.route("/admin/reset-password", methods=["POST"])
@login_required
def admin_force_reset():
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    user_id = request.form.get("user_id", type=int)
    new_password = request.form.get("new_password", "").strip()
    if not user_id or len(new_password) < 6:
        flash("Invalid request.", "warning")
        return redirect(request.referrer or url_for("dashboard"))
    user = User.query.get_or_404(user_id)
    user.set_password(new_password); db.session.commit()
    flash(f"Password reset for {user.full_name}.", "success")
    return redirect(request.referrer or url_for("dashboard"))

# -------------------- Admin: Attendance + Export --------------------
@app.route("/admin/attendance", methods=["GET", "POST"])
@login_required
def admin_attendance():
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    if request.method == "POST":
        teacher_id = request.form.get("teacher_id", type=int)
        action = request.form.get("action")
        the_date_str = request.form.get("the_date")
        the_date = date.fromisoformat(the_date_str) if the_date_str else date.today()
        t = User.query.get_or_404(teacher_id)
        if t.role != Role.TEACHER:
            flash("Selected user is not a teacher.", "warning")
            return redirect(request.url)
        rec = TeacherAttendance.query.filter_by(teacher_id=t.id, date=the_date).first()
        if not rec:
            rec = TeacherAttendance(teacher_id=t.id, date=the_date)
            db.session.add(rec)
        now = datetime.utcnow()
        if action == "sign_in":
            if rec.sign_in_time:
                flash(f"{t.full_name} has already signed in today.", "info")
            else:
                rec.sign_in_time = now; db.session.commit()
                flash(f"Signed in: {t.full_name}.", "success")
        elif action == "sign_out":
            if not rec.sign_in_time:
                flash(f"{t.full_name} hasn't signed in yet.", "warning")
            elif rec.sign_out_time:
                flash(f"{t.full_name} has already signed out today.", "info")
            else:
                rec.sign_out_time = now; db.session.commit()
                flash(f"Signed out: {t.full_name}.", "success")
        return redirect(url_for("admin_attendance", day=the_date.isoformat()))
    q = request.args.get("q", "").strip()
    day_str = request.args.get("day", "").strip()
    week_start_str = request.args.get("week_start", "").strip()
    the_day = date.fromisoformat(day_str) if day_str else date.today()
    week_start = date.fromisoformat(week_start_str) if week_start_str else start_of_week(the_day)
    week_end = week_start + timedelta(days=6)
    teachers_q = User.query.filter_by(role=Role.TEACHER)
    if q:
        like = f"%{q}%"
        teachers_q = teachers_q.filter(User.full_name.ilike(like) | User.username.ilike(like))
    teachers = teachers_q.order_by(User.full_name).all()
    weekly_records = (
        db.session.query(TeacherAttendance, User)
        .join(User, TeacherAttendance.teacher_id == User.id)
        .filter(TeacherAttendance.date >= week_start, TeacherAttendance.date <= week_end)
        .order_by(TeacherAttendance.date.desc(), User.full_name.asc())
        .all()
    )
    daily_records = (
        db.session.query(TeacherAttendance, User)
        .join(User, TeacherAttendance.teacher_id == User.id)
        .filter(TeacherAttendance.date == the_day)
        .order_by(User.full_name.asc())
        .all()
    )
    return render_template("admin_attendance.html",
                           teachers=teachers, q=q,
                           the_day=the_day, week_start=week_start, week_end=week_end,
                           daily_records=daily_records, weekly_records=weekly_records)

# -------------------- Admin: Attendance History (date range + export) --------------------
@app.route("/admin/attendance/history")
@login_required
def admin_attendance_history():
    if current_user.role != Role.ADMIN:
        return ("Forbidden", 403)

    # Inputs
    q = (request.args.get("q") or "").strip()
    date_from_str = (request.args.get("date_from") or "").strip()
    date_to_str = (request.args.get("date_to") or "").strip()
    fmt = (request.args.get("format") or "").lower()  # "xlsx" or "pdf" to export

    # Defaults: last 90 days
    today = date.today()
    try:
        date_from = date.fromisoformat(date_from_str) if date_from_str else today - timedelta(days=90)
    except Exception:
        date_from = today - timedelta(days=90)
    try:
        date_to = date.fromisoformat(date_to_str) if date_to_str else today
    except Exception:
        date_to = today

    # Query
    rows = (db.session.query(TeacherAttendance, User)
            .join(User, TeacherAttendance.teacher_id == User.id)
            .filter(TeacherAttendance.date >= date_from,
                    TeacherAttendance.date <= date_to))

    if q:
        like = f"%{q}%"
        rows = rows.filter((User.full_name.ilike(like)) | (User.username.ilike(like)))

    rows = rows.order_by(TeacherAttendance.date.asc(),
                         User.full_name.asc()).all()

    # Build data list for export
    data = []
    for rec, u in rows:
        sign_in = rec.sign_in_time.isoformat(sep=" ", timespec="seconds") if rec.sign_in_time else ""
        sign_out = rec.sign_out_time.isoformat(sep=" ", timespec="seconds") if rec.sign_out_time else ""
        hours = ""
        if rec.sign_in_time and rec.sign_out_time:
            delta = rec.sign_out_time - rec.sign_in_time
            hours = f"{delta.total_seconds()/3600:.2f}"
        data.append({
            "Date": rec.date.isoformat(),
            "Teacher": u.full_name,
            "Username": u.username,
            "Sign In": sign_in,
            "Sign Out": sign_out,
            "Hours": hours
        })

    # Export
    if fmt == "xlsx":
        import io, pandas as pd
        bio = io.BytesIO()
        df = pd.DataFrame(data or [{"Date":"","Teacher":"","Username":"","Sign In":"","Sign Out":"","Hours":""}])
        with pd.ExcelWriter(bio, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Attendance")
        bio.seek(0)
        fname = f"attendance_{date_from.isoformat()}_{date_to.isoformat()}.xlsx"
        return send_file(bio, as_attachment=True, download_name=fname,
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    if fmt == "pdf":
        from fpdf import FPDF
        pdf = FPDF(orientation="L", unit="mm", format="A4")
        pdf.add_page()
        pdf.set_font("Arial", "B", 12)
        title = f"Teacher Attendance — {date_from.isoformat()} to {date_to.isoformat()}"
        pdf.cell(0, 10, title, ln=1, align="C")

        headers = ["Date", "Teacher", "Username", "Sign In", "Sign Out", "Hours"]
        col_w = [30, 70, 45, 45, 45, 20]
        pdf.set_font("Arial", "B", 10)
        for w, h in zip(col_w, headers):
            pdf.cell(w, 8, h, border=1, align="C")
        pdf.ln(8)

        pdf.set_font("Arial", "", 9)
        if not data:
            pdf.cell(sum(col_w), 8, "No records", border=1, align="C")
        else:
            for r in data:
                pdf.cell(col_w[0], 8, r["Date"], border=1)
                pdf.cell(col_w[1], 8, r["Teacher"][:35], border=1)
                pdf.cell(col_w[2], 8, r["Username"], border=1)
                pdf.cell(col_w[3], 8, r["Sign In"], border=1)
                pdf.cell(col_w[4], 8, r["Sign Out"], border=1)
                pdf.cell(col_w[5], 8, r["Hours"], border=1, align="R")
                pdf.ln(8)

        pdf_bytes = pdf.output(dest="S").encode("latin1")
        import io
        bio = io.BytesIO(pdf_bytes)
        fname = f"attendance_{date_from.isoformat()}_{date_to.isoformat()}.pdf"
        return send_file(bio, as_attachment=True, download_name=fname, mimetype="application/pdf")

    # Render page
    return render_template("admin_attendance_history.html",
                           q=q, date_from=date_from, date_to=date_to, rows=rows)

@app.route("/admin/attendance/export")
@login_required
def admin_attendance_export():
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    fmt = (request.args.get("format") or "xlsx").lower()  # xlsx or pdf
    week_start_str = request.args.get("week_start")
    day_str = request.args.get("day")
    the_day = date.fromisoformat(day_str) if day_str else date.today()
    week_start = date.fromisoformat(week_start_str) if week_start_str else start_of_week(the_day)
    week_end = week_start + timedelta(days=6)
    rows = (
        db.session.query(TeacherAttendance, User)
        .join(User, TeacherAttendance.teacher_id == User.id)
        .filter(TeacherAttendance.date >= week_start, TeacherAttendance.date <= week_end)
        .order_by(TeacherAttendance.date.asc(), User.full_name.asc())
        .all()
    )
    data = []
    for rec, u in rows:
        sign_in = rec.sign_in_time.isoformat(sep=" ", timespec="seconds") if rec.sign_in_time else ""
        sign_out = rec.sign_out_time.isoformat(sep=" ", timespec="seconds") if rec.sign_out_time else ""
        hours = ""
        if rec.sign_in_time and rec.sign_out_time:
            delta = rec.sign_out_time - rec.sign_in_time
            hours = f"{delta.total_seconds()/3600:.2f}"
        data.append({"Date": rec.date.isoformat(), "Teacher": u.full_name, "Username": u.username,
                     "Sign In": sign_in, "Sign Out": sign_out, "Hours": hours})
    if fmt == "xlsx":
        df = pd.DataFrame(data or [{"Date":"","Teacher":"","Username":"","Sign In":"","Sign Out":"","Hours":""}])
        bio = io.BytesIO()
        with pd.ExcelWriter(bio, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Attendance")
        bio.seek(0)
        fname = f"attendance_{week_start.isoformat()}_{week_end.isoformat()}.xlsx"
        return send_file(bio, as_attachment=True, download_name=fname,
                         mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.add_page(); pdf.set_font("Arial", "B", 12)
    title = f"Teacher Attendance — {week_start.isoformat()} to {week_end.isoformat()}"
    pdf.cell(0, 10, title, ln=1, align="C")
    headers = ["Date", "Teacher", "Username", "Sign In", "Sign Out", "Hours"]
    col_w = [30, 70, 45, 45, 45, 20]
    pdf.set_font("Arial", "B", 10)
    for w, h in zip(col_w, headers): pdf.cell(w, 8, h, border=1, align="C")
    pdf.ln(8); pdf.set_font("Arial", "", 9)
    if not data:
        pdf.cell(sum(col_w), 8, "No records", border=1, align="C")
    else:
        for r in data:
            pdf.cell(col_w[0], 8, r["Date"], border=1)
            pdf.cell(col_w[1], 8, r["Teacher"][:35], border=1)
            pdf.cell(col_w[2], 8, r["Username"], border=1)
            pdf.cell(col_w[3], 8, r["Sign In"], border=1)
            pdf.cell(col_w[4], 8, r["Sign Out"], border=1)
            pdf.cell(col_w[5], 8, r["Hours"], border=1, align="R")
            pdf.ln(8)
    pdf_bytes = pdf.output(dest="S").encode("latin1")
    bio = io.BytesIO(pdf_bytes)
    fname = f"attendance_{week_start.isoformat()}_{week_end.isoformat()}.pdf"
    return send_file(bio, as_attachment=True, download_name=fname, mimetype="application/pdf")

# -------------------- Teacher: Assignments --------------------
@app.route("/teacher/assignments", methods=["GET", "POST"])
@login_required
def teacher_assignments():
    if current_user.role != Role.TEACHER: return ("Forbidden", 403)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        due_date_str = request.form.get("due_date")
        class_name = request.form.get("class_name", "").strip() or None
        allow_text = (request.form.get("allow_text") == "on")
        allow_pdf  = (request.form.get("allow_pdf") == "on")
        max_score = request.form.get("max_score", type=int) or 100
        if not (allow_text or allow_pdf):
            flash("Choose at least one submission mode (Text and/or PDF).", "warning")
            return redirect(request.url)
        due_dt = None
        if due_date_str:
            try: due_dt = datetime.strptime(due_date_str, "%Y-%m-%dT%H:%M")
            except Exception: pass
        if not title or not description:
            flash("Title and description are required.", "warning")
        else:
            a = Assignment(title=title, description=description, due_date=due_dt,
                           class_name=class_name, created_by=current_user.id,
                           allow_text=allow_text, allow_pdf=allow_pdf, max_score=max_score)
            db.session.add(a); db.session.commit()
            flash("Assignment created.", "success")
            return redirect(url_for("teacher_assignments"))
    my_assignments = Assignment.query.filter_by(created_by=current_user.id).order_by(Assignment.created_at.desc()).all()
    classes = ClassCatalog.query.order_by(ClassCatalog.name.asc()).all()
    return render_template("teacher_assignments.html", assignments=my_assignments, classes=classes)

@app.route("/teacher/assignments/<int:assignment_id>/submissions")
@login_required
def teacher_assignment_submissions(assignment_id):
    if current_user.role != Role.TEACHER: return ("Forbidden", 403)
    a = Assignment.query.get_or_404(assignment_id)
    if a.created_by != current_user.id: return ("Forbidden", 403)
    subs = (Submission.query
            .filter_by(assignment_id=a.id)
            .join(User, Submission.student_id == User.id)
            .add_columns(
                Submission.id, Submission.submitted_at, Submission.text_answer, Submission.pdf_path,
                Submission.score, Submission.grade, Submission.feedback,
                User.full_name.label("student_name"), User.username.label("student_username"))
            .order_by(Submission.submitted_at.desc())
            .all())
    return render_template("teacher_assignment_submissions.html", a=a, subs=subs)

@app.route("/teacher/submissions/<int:submission_id>", methods=["GET", "POST"])
@login_required
def teacher_grade_submission(submission_id):
    if current_user.role != Role.TEACHER: return ("Forbidden", 403)
    s = Submission.query.get_or_404(submission_id)
    a = Assignment.query.get_or_404(s.assignment_id)
    if a.created_by != current_user.id: return ("Forbidden", 403)
    if request.method == "POST":
        score = request.form.get("score", type=float)
        grade = request.form.get("grade", "").strip() or None
        feedback = request.form.get("feedback", "").strip() or None
        if score is not None:
            if score < 0: flash("Score cannot be negative.", "warning"); return redirect(request.url)
            if a.max_score and score > a.max_score:
                flash(f"Score cannot exceed max score ({a.max_score}).", "warning"); return redirect(request.url)
        s.score = score; s.grade = grade; s.feedback = feedback
        db.session.commit()
        flash("Marked and saved.", "success")
        return redirect(url_for("teacher_assignment_submissions", assignment_id=a.id))
    return render_template("teacher_grade_submission.html", a=a, s=s)

# -------------------- Teacher: Lesson Notes --------------------
@app.route("/teacher/lesson-notes", methods=["GET", "POST"])
@login_required
def teacher_lesson_notes():
    if current_user.role != Role.TEACHER: return ("Forbidden", 403)
    if request.method == "POST":
        subject = request.form.get("subject", "").strip()
        topic = request.form.get("topic", "").strip()
        content = request.form.get("content", "").strip()
        if not subject or not topic or not content:
            flash("All fields required.", "warning")
        else:
            note = LessonNote(teacher_id=current_user.id, subject=subject, topic=topic, content=content)
            db.session.add(note); db.session.commit()
            flash("Lesson note submitted.", "success")
            return redirect(url_for("teacher_lesson_notes"))
    notes = LessonNote.query.filter_by(teacher_id=current_user.id).order_by(LessonNote.created_at.desc()).all()
    return render_template("teacher_lesson_notes.html", notes=notes)

# -------------------- Admin: Lesson Notes Review --------------------
@app.route("/admin/lesson-notes", methods=["GET", "POST"])
@login_required
def admin_lesson_notes():
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    if request.method == "POST":
        note_id = request.form.get("note_id", type=int)
        status = request.form.get("status", "PENDING")
        comment = request.form.get("admin_comment", "")
        note = LessonNote.query.get_or_404(note_id)
        note.status = status; note.admin_comment = comment
        db.session.commit(); flash("Lesson note updated.", "success")
        return redirect(url_for("admin_lesson_notes", **request.args))
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    query = LessonNote.query.join(User, LessonNote.teacher_id == User.id)
    if q:
        like = f"%{q}%"
        query = query.filter((LessonNote.subject.ilike(like)) | (LessonNote.topic.ilike(like)) | (User.full_name.ilike(like)))
    if status:
        query = query.filter(LessonNote.status == status)
    notes = query.order_by(LessonNote.created_at.desc()).all()
    return render_template("admin_lesson_notes.html", notes=notes)

# -------------------- Student: Assignments + Submission --------------------
@app.route("/assignments")
@login_required
def list_assignments():
    if current_user.role != Role.STUDENT: return ("Forbidden", 403)
    items = Assignment.query.filter(
        (Assignment.class_name == current_user.class_name) | (Assignment.class_name == None)
    ).order_by(Assignment.created_at.desc()).all()
    return render_template("student_assignments.html", assignments=items)

@app.route("/assignments/<int:assignment_id>/submit", methods=["GET", "POST"])
@login_required
def submit_assignment(assignment_id):
    if current_user.role != Role.STUDENT: return ("Forbidden", 403)
    a = Assignment.query.get_or_404(assignment_id)
    if a.class_name and a.class_name != current_user.class_name: return ("Forbidden", 403)
    if request.method == "POST":
        text_answer = request.form.get("text_answer", "").strip() or None
        pdf = request.files.get("pdf")
        pdf_path = None
        if text_answer and not a.allow_text:
            flash("This assignment does not allow typed answers.", "warning"); return redirect(request.url)
        if pdf and pdf.filename:
            if not a.allow_pdf:
                flash("This assignment does not allow PDF uploads.", "warning"); return redirect(request.url)
            if allowed_file(pdf.filename):
                fname = secure_filename(f"{current_user.username}_{a.id}_{int(datetime.utcnow().timestamp())}.pdf")
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                pdf.save(save_path); pdf_path = fname
            else:
                flash("Only PDF files are allowed.", "warning"); return redirect(request.url)
        if not text_answer and not pdf_path:
            flash("Provide a text answer or upload a PDF (as allowed).", "warning"); return redirect(request.url)
        s = Submission(assignment_id=a.id, student_id=current_user.id,
                       text_answer=text_answer, pdf_path=pdf_path)
        db.session.add(s); db.session.commit()
        flash("Submission received.", "success")
        return redirect(url_for("list_assignments"))
    return render_template("student_submit.html", a=a)

@app.route("/uploads/pdfs/<path:filename>")
@login_required
def serve_pdf(filename):
    if current_user.role not in (Role.TEACHER, Role.ADMIN): return ("Forbidden", 403)
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)

# -------------------- Admin: schema patch button --------------------
@app.route("/admin/patch-schema")
@login_required
def admin_patch_schema():
    if current_user.role != Role.ADMIN: return ("Forbidden", 403)
    ensure_schema()
    flash("Schema checked/patched.", "success")
    return redirect(url_for("dashboard"))

# -------------------- First admin helper --------------------
@app.route("/init-admin")
def init_admin_view():
    db.create_all(); ensure_schema()
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", full_name="System Admin", role=Role.ADMIN, security_pin="9999")
        admin.set_password("admin123")
        db.session.add(admin); db.session.commit()
        return "Admin created: admin / admin123 (PIN 9999)"
    return "Admin already exists."

# -------------------- Run --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_schema()
    # In production, run via gunicorn/wsgi.py; keep debug False
    app.run(host="0.0.0.0", port=5000, debug=False)

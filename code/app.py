import os
import re
from datetime import datetime
from io import BytesIO

import fitz
import nltk
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import Email, EqualTo, InputRequired, Length, ValidationError

# ==============================================================================
# 1. FLASK APP & DATABASE CONFIGURATION
# ==============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
Session(app)

# ==============================================================================
# 2. DATABASE MODELS
# ==============================================================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(150), nullable=False)
    jobs = db.relationship('Job', backref='owner', lazy=True, cascade="all, delete-orphan")

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidates = db.relationship('Candidate', backref='job', lazy=True, cascade="all, delete-orphan")

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150))
    phone = db.Column(db.String(50))
    experience = db.Column(db.Float)
    education = db.Column(db.String(200))
    cgpa = db.Column(db.Float)
    score = db.Column(db.Float, nullable=False) # Skill score
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==============================================================================
# 3. WTFORMS
# ==============================================================================
class SignupForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('That email is already taken.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# ==============================================================================
# 4. INFORMATION EXTRACTION SYSTEM
# ==============================================================================
def clear_session_data():
    for key in ['processed_resume_data', 'all_results', 'available_skills', 'current_job_id', 'resume_files']:
        session.pop(key, None)

def load_skill_dictionary(file_path='skills.txt'):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError: return set()

SKILL_DICTIONARY = load_skill_dictionary()
for package in ['punkt', 'stopwords']:
    try: nltk.data.find(f'tokenizers/{package}')
    except LookupError: nltk.download(package, quiet=True)

def extract_text_from_pdf(file_stream):
    try:
        return "".join(page.get_text() for page in fitz.open(stream=file_stream, filetype="pdf"))
    except Exception as e:
        print(f"Error extracting text: {e}")
        return None

def extract_name(text):
    for line in text.split('\n')[:5]:
        stripped = line.strip()
        if any(keyword in stripped.lower() for keyword in ['summary', 'profile', 'experience', 'education', 'contact', '@', 'linkedin', 'github']):
            continue
        if 2 <= len(stripped.split()) <= 4 and re.match(r'^[A-Za-z\s-]{5,}$', stripped):
            return stripped.title()
    return "Unknown Candidate"

def extract_contact_info(text):
    info = {
        'email': (re.search(r'[\w\.\-]+@[\w\.\-]+', text) or [None])[0],
        'phone': (re.search(r'(\(?\d{3}\)?[\s\.\-]?){1,2}\d{3}[\s\.\-]?\d{4}', text) or [None])[0],
        'linkedin': (re.search(r'linkedin\.com/in/[\w\-]+', text, re.IGNORECASE) or [None])[0],
        'github': (re.search(r'github\.com/[\w\-]+', text, re.IGNORECASE) or [None])[0]
    }
    return {k: v.strip() if v else None for k, v in info.items()}

def extract_experience(text):
    total_months = 0
    month_map = {name.lower(): i+1 for i, name in enumerate(['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'])}
    date_range_pattern = re.compile(r'(?P<s_mon>\w+)?\s*(?P<s_year>\d{4})\s*(?:to|-|–)\s*(?P<e_mon>\w+)?\s*(?P<e_year>\d{4}|present|current)', re.IGNORECASE)
    
    for match in date_range_pattern.finditer(text):
        try:
            start_year = int(match.group('s_year'))
            start_month_str = (match.group('s_mon') or 'jan').lower()[:3]
            start_month = month_map.get(start_month_str, 1)
            
            end_year_str = match.group('e_year').lower()
            if end_year_str in ['present', 'current']:
                end_year, end_month = datetime.now().year, datetime.now().month
            else:
                end_year = int(end_year_str)
                end_month_str = (match.group('e_mon') or 'dec').lower()[:3]
                end_month = month_map.get(end_month_str, 12)
            
            duration = (end_year - start_year) * 12 + (end_month - start_month) + 1
            if duration > 0: total_months += duration
        except (ValueError, IndexError): continue
            
    if total_months > 0: return round(total_months / 12.0, 1)

    year_matches = re.findall(r'(\d+\.?\d*)\s*\+?\s*years? of experience', text.lower())
    if year_matches: return round(max([float(y) for y in year_matches]), 1)
    return 0.0

def extract_education(text):
    education_hierarchy = [
        ('Ph.D', ['ph.d']),
        ("Master's", ['m.tech', 'm.e.', 'master of engineering', 'master of technology', 'm.s', 'm.sc', 'mca', 'mba']),
        ("Bachelor's", ['b.tech', 'b.e.', 'bachelor of engineering', 'bachelor of technology', 'b.sc', 'bca','bachelor of science']),
        ('Diploma', ['diploma']),
        ('High School', ['high school', 'secondary', '12th', '10th'])
    ]
    text_lower = text.lower()
    for level, keywords in education_hierarchy:
        for kw in keywords:
            if re.search(r'\b' + re.escape(kw) + r'\b', text_lower):
                return level
    return 'Not Found'

def extract_cgpa(text):
    match = re.search(r'(?:c\.?g\.?p\.?a\.?|gpa)\s*:?\s*(\d\.\d{1,2})\s*(?:/|out of)?\s*(?:\d{1,2})?', text, re.IGNORECASE)
    return float(match.group(1)) if match else 0.0

def extract_skills(text, skill_list):
    found = {skill for skill in skill_list if re.search(r'\b' + re.escape(skill) + r'\b', text.lower())}
    return list(found)

# ==============================================================================
# 5. FLASK ROUTES
# ==============================================================================
@app.route('/resume/<filename>')
@login_required
def resume_details(filename):
    processed_data = session.get('processed_resume_data', {})
    candidate = processed_data.get(filename)
    if not candidate:
        flash('Candidate not found.', 'danger')
        return redirect(url_for('index'))

    # Get matched skills and all skills
    all_skills = candidate.get('skills', [])
    predefined_skills = set(SKILL_DICTIONARY)
    matched_skills = [skill for skill in all_skills if skill in predefined_skills]

    return render_template('resume_details.html', candidate=candidate, matched_skills=matched_skills, all_skills=all_skills, filename=filename)

@app.route('/download_resume/<filename>')
@login_required
def download_resume(filename):
    resume_files = session.get('resume_files', {})
    file_content = resume_files.get(filename)
    if not file_content:
        flash('Resume file not found.', 'danger')
        return redirect(url_for('index'))
    return send_file(BytesIO(file_content), download_name=filename, as_attachment=True)
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/logout')
def logout():
    clear_session_data()
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))
    
@app.route('/process-resumes', methods=['POST'])
@login_required
def process_resumes():
    clear_session_data()
    resume_files = request.files.getlist('resumes')
    if not resume_files: return jsonify({"error": "Resumes are required."}), 400

    new_job = Job(title=f"Processing Job - {datetime.now().strftime('%Y-%m-%d %H:%M')}", user_id=current_user.id)
    db.session.add(new_job); db.session.commit()

    processed_data, all_discovered_skills = {}, set()
    session['resume_files'] = {}

    for file in resume_files:
        if file and file.filename:
            file_content = file.read()
            session['resume_files'][file.filename] = file_content
            resume_text = extract_text_from_pdf(BytesIO(file_content))
            
            if resume_text:
                skills = extract_skills(resume_text, SKILL_DICTIONARY)
                all_discovered_skills.update(skills)
                processed_data[file.filename] = {
                    'name': extract_name(resume_text),
                    'contact': extract_contact_info(resume_text),
                    'experience': extract_experience(resume_text),
                    'education': extract_education(resume_text),
                    'cgpa': extract_cgpa(resume_text),
                    'skills': skills,
                }
    
    session['processed_resume_data'] = processed_data
    session['available_skills'] = sorted(list(SKILL_DICTIONARY.union(all_discovered_skills)))
    session['current_job_id'] = new_job.id
    session.modified = True
    
    return jsonify({"status": "success", "message": "Resumes processed.", "available_skills": session['available_skills']})


# POST: filter resumes and store rankings in session
@app.route('/filter-resumes', methods=['POST'])
@login_required
def filter_resumes():
    data = request.get_json()
    processed_data = session.get('processed_resume_data', {})
    if not processed_data:
        return jsonify({"error": "Session expired. Please upload resumes again."}), 400

    filters = {
        'skills': set(data.get('selected_skills', [])),
        'min_exp': float(data.get('min_exp', 0)),
        'max_exp': float(data.get('max_exp', 100)),
        'min_cgpa': float(data.get('min_cgpa', 0)),
        'education': data.get('education_req', '').lower()
    }

    results = []
    for filename, info in processed_data.items():
        if not (filters['min_exp'] <= info['experience'] <= filters['max_exp']): continue
        if info['cgpa'] < filters['min_cgpa']: continue
        if filters['education'] and filters['education'] not in info['education'].lower(): continue

        score = len(set(info['skills']).intersection(filters['skills']))
        if filters['skills'] and score == 0: continue

        results.append({**info, 'filename': filename, 'score': score})

    sorted_results = sorted(results, key=lambda x: (-x['score'], -x['experience']))
    session['all_results'] = sorted_results
    session.modified = True

    page_size, page_1 = 10, sorted_results[:10]
    total_pages = (len(sorted_results) + page_size - 1) // page_size if len(sorted_results) > 0 else 1
    pagination = {"current_page": 1, "total_pages": total_pages, "total_results": len(sorted_results)}

    return jsonify({"rankings": page_1, "pagination": pagination})

# GET: return last rankings from session
@app.route('/filter-resumes', methods=['GET'])
@login_required
def get_last_rankings():
    all_results = session.get('all_results', [])
    if not all_results:
        return jsonify({"error": "No rankings found. Please filter resumes again."}), 404

    page_size = 10
    page_1 = all_results[:10]
    total_pages = (len(all_results) + page_size - 1) // page_size if len(all_results) > 0 else 1
    pagination = {"current_page": 1, "total_pages": total_pages, "total_results": len(all_results)}

    return jsonify({"rankings": page_1, "pagination": pagination})

@app.route('/shortlist', methods=['POST'])
@login_required
def shortlist_candidate():
    data = request.get_json()
    filename = data.get('filename')
    job_id = session.get('current_job_id')
    all_results = session.get('all_results', [])

    if not all([filename, job_id, all_results]):
        return jsonify({"error": "Missing data for shortlisting."}), 400

    if Candidate.query.filter_by(filename=filename, job_id=job_id).first():
        return jsonify({"status": "exists", "message": "Candidate already shortlisted."})

    info = next((item for item in all_results if item['filename'] == filename), None)
    if not info:
        return jsonify({"error": "Candidate data not found."}), 404

    candidate = Candidate(
        filename=filename, name=info['name'],
        email=info['contact']['email'], phone=info['contact']['phone'],
        experience=info['experience'], education=info['education'], cgpa=info['cgpa'],
        score=info['score'], job_id=job_id
    )
    db.session.add(candidate)
    db.session.commit()
    return jsonify({"status": "success", "message": "Candidate shortlisted."})

@app.route('/database_view')
@login_required
def database_view():
    candidates = session.get('processed_resume_data', {})
    if not candidates:
        flash("No resumes have been processed yet.", "info")
        return redirect(url_for('index'))
    return render_template('database_view.html', candidates=candidates.items())

# --- ALL ROUTES ARE NOW PRESENT ---
@app.route('/dashboard')
@login_required
def dashboard():
    jobs = Job.query.filter_by(owner=current_user).order_by(Job.id.desc()).all()
    return render_template('dashboard.html', jobs=jobs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form)
    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: return redirect(url_for('index'))
    form = SignupForm()
    if form.validate_on_submit():
        new_user = User(email=form.email.data, password_hash=generate_password_hash(form.password.data))
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.before_request
def create_tables():
    if not hasattr(app, 'tables_created'):
        with app.app_context():
            db.create_all()
        app.tables_created = True

if __name__ == '__main__':
    app.run(debug=True)
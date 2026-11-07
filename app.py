from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort, send_file, Response
import sqlite3
import csv, io, secrets, os, smtplib, hashlib, hmac, json
from email.message import EmailMessage
from datetime import timedelta
from pathlib import Path
from functools import wraps
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
# Load the private .env file from the same directory as this app.py,
# regardless of the folder from which the application is launched.
BASE_DIR = Path(__file__).resolve().parent
try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / '.env')
except ImportError:
    pass

try:
    from authlib.integrations.flask_client import OAuth
except ImportError:
    OAuth = None
try:
    import razorpay
except ImportError:
    razorpay = None

DB_PATH = BASE_DIR / 'efms.db'
SCHEMA_PATH = BASE_DIR / 'schema.sql'

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Application and integration configuration (.env)
# ---------------------------------------------------------------------------
DEBUG = os.getenv('DEBUG', 'false').strip().lower() in ('1', 'true', 'yes', 'on')
# Never hard-code credentials in app.py. All private values must come from .env
# or the process environment. Generate a fresh key locally with:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"
# Development fallback requested for this local project.
# Prefer SECRET_KEY from the private .env file; rotate this exposed fallback
# before deployment and set a fresh environment value.
SECRET_KEY = os.getenv('SECRET_KEY', '').strip()
if not SECRET_KEY:
    raise RuntimeError('SECRET_KEY is missing. Add a fresh SECRET_KEY to your .env file.')

app.config.update(
    SECRET_KEY=SECRET_KEY,
    DATABASE=str(DB_PATH),
    SESSION_COOKIE_HTTPONLY=os.getenv('SESSION_COOKIE_HTTPONLY', 'true').strip().lower() in ('1', 'true', 'yes', 'on'),
    SESSION_COOKIE_SAMESITE=os.getenv('SESSION_COOKIE_SAMESITE', 'Lax').strip(),
    SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE', 'false').strip().lower() in ('1', 'true', 'yes', 'on'),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.getenv('SESSION_LIFETIME_HOURS', '12'))),
)
app.secret_key = SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
PROFILE_UPLOAD_DIR = BASE_DIR / 'static' / 'uploads' / 'profiles'
PROFILE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_PROFILE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

APP_BASE_URL = os.getenv('APP_BASE_URL', 'http://127.0.0.1:5000').strip().rstrip('/')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '').strip()
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '').strip()
GOOGLE_REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', f"{APP_BASE_URL}/auth/google/callback").strip()
RAZORPAY_KEY_ID = os.getenv('RAZORPAY_KEY_ID', '').strip()
RAZORPAY_KEY_SECRET = os.getenv('RAZORPAY_KEY_SECRET', '').strip()
SMTP_HOST = os.getenv('SMTP_HOST', '').strip()
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER', '').strip()
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '').strip()
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USER).strip()
SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'true').strip().lower() not in ('0', 'false', 'no')
SMTP_TIMEOUT = int(os.getenv('SMTP_TIMEOUT', '20'))

def smtp_configured():
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and SMTP_FROM)

def send_email(to_email, subject, body):
    if not smtp_configured():
        return False
    msg = EmailMessage(); msg['Subject'] = subject; msg['From'] = SMTP_FROM; msg['To'] = to_email; msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
        if SMTP_USE_TLS: server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
    return True

def send_email_otp(user_id, email):
    # Deliver first; never create an OTP record if SMTP is unavailable or rejects it.
    code = f'{secrets.randbelow(1_000_000):06d}'
    sent = send_email(
        email,
        'EFMS email verification code',
        f'Your EFMS verification code is {code}. It expires in 10 minutes. '
        'If you did not request this, ignore this email.'
    )
    if not sent:
        raise RuntimeError('SMTP is not configured. Check SMTP settings in your private .env file.')
    conn = db()
    try:
        now = datetime.utcnow()
        conn.execute(
            'UPDATE email_otps SET used_at=? WHERE user_id=? AND used_at IS NULL',
            (now.isoformat(), user_id)
        )
        conn.execute(
            'INSERT INTO email_otps(user_id,code_hash,expires_at) VALUES (?,?,?)',
            (user_id, generate_password_hash(code), (now + timedelta(minutes=10)).isoformat())
        )
        conn.commit()
    finally:
        conn.close()


oauth = OAuth(app) if OAuth else None
if oauth and GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    oauth.register(name='google', client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET,
                   server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                   client_kwargs={'scope':'openid email profile'})

def db():
    conn = sqlite3.connect(app.config['DATABASE'], timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 15000')
    return conn


def init_db():
    conn = db()
    schema = SCHEMA_PATH.read_text(encoding='utf-8')
    conn.executescript(schema)
    # Safe in-place migrations for databases created by the previous prototype.
    user_cols = {r['name'] for r in conn.execute('PRAGMA table_info(users)')}
    if 'email_verified' not in user_cols: conn.execute('ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1')
    conn.execute('CREATE TABLE IF NOT EXISTS email_otps (otp_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE)')
    conn.execute('CREATE TABLE IF NOT EXISTS password_reset_otps (reset_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE)')
    conn.execute("CREATE TABLE IF NOT EXISTS user_profiles (profile_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE, profile_photo TEXT, bio TEXT, date_of_birth TEXT, address TEXT, college TEXT, department TEXT, organization_name TEXT, website TEXT, education TEXT, experience TEXT, skills TEXT, availability TEXT, emergency_contact TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE)")
    conn.execute('INSERT OR IGNORE INTO user_profiles(user_id) SELECT user_id FROM users')
    payment_cols = {r['name'] for r in conn.execute('PRAGMA table_info(payments)')}
    if 'gateway_payment_id' not in payment_cols: conn.execute('ALTER TABLE payments ADD COLUMN gateway_payment_id TEXT')
    incident_cols = {r['name'] for r in conn.execute('PRAGMA table_info(incidents)')}
    for col, declaration in [('location', 'TEXT'), ('severity', "TEXT DEFAULT 'Medium'")]:
        if col not in incident_cols: conn.execute(f'ALTER TABLE incidents ADD COLUMN {col} {declaration}')
    # Additive migrations for existing local databases.
    event_cols = {r['name'] for r in conn.execute('PRAGMA table_info(events)')}
    for col, declaration in [('location','TEXT'),('winning_prize','TEXT'),('organizer_user_id','INTEGER'),('event_budget','REAL NOT NULL DEFAULT 0'),('payment_note','TEXT'),('contact_email','TEXT'),('contact_phone','TEXT')]:
        if col not in event_cols: conn.execute(f'ALTER TABLE events ADD COLUMN {col} {declaration}')
    volunteer_cols = {r['name'] for r in conn.execute('PRAGMA table_info(volunteers)')}
    for col, declaration in [('bio','TEXT'),('education','TEXT'),('experience','TEXT'),('address','TEXT')]:
        if col not in volunteer_cols: conn.execute(f'ALTER TABLE volunteers ADD COLUMN {col} {declaration}')
    seed(conn)
    conn.execute("UPDATE events SET organizer_user_id=(SELECT user_id FROM event_coordinators WHERE event_coordinators.coordinator_id=events.coordinator_id) WHERE organizer_user_id IS NULL")
    conn.execute("INSERT OR IGNORE INTO event_approvals(event_id,submitted_by,status) SELECT event_id,NULL,CASE WHEN status='Published' THEN 'Approved' ELSE 'Pending' END FROM events")
    if conn.execute('SELECT COUNT(*) FROM parking_zones').fetchone()[0] == 0:
        conn.execute("INSERT INTO parking_zones(zone_name,location,vehicle_type,capacity,accessible_spaces,status,notes) VALUES ('Main Gate Visitor Parking','Main Gate','Any',80,4,'Open','Demo zone; adjust capacity to actual site survey')")
    conn.commit()
    conn.close()


def seed(conn):
    # Idempotent seed data.
    # Ensure required roles exist even when the database was created by an older version.
    required_roles = [
        ('Admin','Full system administration'),
        ('Organizer','Festival and event management'),
        ('Participant','Event registration and feedback'),
        ('Volunteer','Event duties and attendance'),
        ('Sponsor','Sponsorship and contribution management')
    ]
    for role_name, role_description in required_roles:
        conn.execute('INSERT OR IGNORE INTO roles(name, description) VALUES (?,?)',
                     (role_name, role_description))
    role_ids = {r['name']: r['role_id'] for r in conn.execute('SELECT * FROM roles').fetchall()}

    # Add only missing demo accounts. Existing users and their passwords are preserved.
    demo_users = [
        ('System Admin','admin@efms.local','9876543210','admin123','Admin'),
        ('Event Organizer','organizer@efms.local','9876543211','org123','Organizer'),
        ('Demo Participant','participant@efms.local','9876543212','part123','Participant'),
        ('Demo Volunteer','volunteer@efms.local','9876543213','vol123','Volunteer'),
        ('Demo Sponsor','sponsor@efms.local','9876543214','sponsor123','Sponsor')
    ]
    for name, email, phone, password, role_name in demo_users:
        conn.execute("INSERT OR IGNORE INTO users(name,email,phone,password_hash,role_id) VALUES (?,?,?,?,?)",
                     (name, email, phone, generate_password_hash(password), role_ids[role_name]))
    users = {u['email']: u for u in conn.execute('SELECT u.*, r.name role_name FROM users u JOIN roles r ON r.role_id=u.role_id').fetchall()}
    if conn.execute('SELECT COUNT(*) FROM festival_categories').fetchone()[0] == 0:
        conn.executemany('INSERT INTO festival_categories(name,description) VALUES (?,?)', [
            ('Cultural','Cultural and artistic celebrations'),('Technical','Technology and innovation'),
            ('Sports','Sports and fitness'),('Educational','Academic and educational'),('Entertainment','Music and entertainment')])
    cats = {r['name']: r['category_id'] for r in conn.execute('SELECT * FROM festival_categories').fetchall()}
    if conn.execute('SELECT COUNT(*) FROM organizers').fetchone()[0] == 0:
        conn.execute('INSERT INTO organizers(user_id,organization_name,contact_person,phone,email,address,approval_status) VALUES (?,?,?,?,?,?,?)',
                     (users['organizer@efms.local']['user_id'],'Campus Events Committee','Event Organizer','9876543211','organizer@efms.local','Brainware University Campus','Approved'))
    organizer_id = conn.execute('SELECT organizer_id FROM organizers LIMIT 1').fetchone()['organizer_id']
    if conn.execute('SELECT COUNT(*) FROM festivals').fetchone()[0] == 0:
        conn.execute('''INSERT INTO festivals(festival_name,description,theme,start_date,end_date,location,category_id,organizer_id,status,budget)
                        VALUES (?,?,?,?,?,?,?,?,?,?)''',
                     ('Campus Utsav 2026','Annual university cultural and technical festival','Innovation Meets Culture',
                      '2026-11-15','2026-11-17','Main Campus',cats['Cultural'],organizer_id,'Upcoming',250000))
        conn.execute('''INSERT INTO festivals(festival_name,description,theme,start_date,end_date,location,category_id,organizer_id,status,budget)
                        VALUES (?,?,?,?,?,?,?,?,?,?)''',
                     ('TechNova 2026','Student technology showcase and hackathon','Build the Future',
                      '2026-12-05','2026-12-06','Innovation Block',cats['Technical'],organizer_id,'Upcoming',180000))
    festivals = {r['festival_name']: r for r in conn.execute('SELECT * FROM festivals').fetchall()}
    if conn.execute('SELECT COUNT(*) FROM venues').fetchone()[0] == 0:
        conn.executemany('INSERT INTO venues(venue_name,location,capacity,venue_type,facilities,status) VALUES (?,?,?,?,?,?)', [
            ('University Auditorium','Academic Block',800,'Indoor','Stage,Sound,Projector','Available'),
            ('Open Air Stage','Central Ground',1500,'Outdoor','Stage,Lighting,Power','Available'),
            ('Computer Lab 1','Innovation Block',120,'Indoor','Computers,Projector,Internet','Available'),
            ('Seminar Hall','Academic Block',250,'Indoor','Projector,Audio,AC','Available')])
    venues = {r['venue_name']: r for r in conn.execute('SELECT * FROM venues').fetchall()}
    if conn.execute('SELECT COUNT(*) FROM event_categories').fetchone()[0] == 0:
        conn.executemany('INSERT INTO event_categories(name,description) VALUES (?,?)', [
            ('Cultural','Dance, music and arts'),('Competition','Competitive events'),('Technical','Hackathons and technical sessions'),
            ('Workshop','Hands-on learning'),('Entertainment','Shows and performances')])
    ecats = {r['name']: r for r in conn.execute('SELECT * FROM event_categories').fetchall()}
    org_user_id = users['organizer@efms.local']['user_id']
    if conn.execute('SELECT COUNT(*) FROM event_coordinators').fetchone()[0] == 0:
        conn.execute('INSERT INTO event_coordinators(user_id,name,phone,email) VALUES (?,?,?,?)', (org_user_id,'Event Coordinator','9876543211','organizer@efms.local'))
    coord_id = conn.execute('SELECT coordinator_id FROM event_coordinators LIMIT 1').fetchone()['coordinator_id']
    if conn.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0:
        conn.executemany('''INSERT INTO events(festival_id,category_id,coordinator_id,event_name,description,rules,eligibility_criteria,max_participants,min_participants,registration_deadline,status)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?)''', [
            (festivals['Campus Utsav 2026']['festival_id'],ecats['Cultural']['category_id'],coord_id,'Dance Competition','Inter-department dance competition','Team of 4-12','University students',200,10,'2026-11-10','Published'),
            (festivals['Campus Utsav 2026']['festival_id'],ecats['Entertainment']['category_id'],coord_id,'Musical Night','Live student performances','Open registration','All students',700,20,'2026-11-14','Published'),
            (festivals['TechNova 2026']['festival_id'],ecats['Technical']['category_id'],coord_id,'24-Hour Hackathon','Build an innovative prototype','Teams of 2-4','Engineering students',120,20,'2026-12-01','Published')])
    events = {r['event_name']: r for r in conn.execute('SELECT * FROM events').fetchall()}
    if conn.execute('SELECT COUNT(*) FROM event_schedules').fetchone()[0] == 0:
        conn.executemany('INSERT INTO event_schedules(event_id,venue_id,event_date,start_time,end_time,status) VALUES (?,?,?,?,?,?)', [
            (events['Dance Competition']['event_id'],venues['University Auditorium']['venue_id'],'2026-11-15','10:00','13:00','Scheduled'),
            (events['Musical Night']['event_id'],venues['Open Air Stage']['venue_id'],'2026-11-16','18:00','21:30','Scheduled'),
            (events['24-Hour Hackathon']['event_id'],venues['Computer Lab 1']['venue_id'],'2026-12-05','10:00','10:00','Scheduled')])
    if conn.execute('SELECT COUNT(*) FROM ticket_types').fetchone()[0] == 0:
        for event_name in events:
            event_id = events[event_name]['event_id']
            prices = [('General',100,500),('Student',50,300),('VIP',500,50)] if event_name != '24-Hour Hackathon' else [('General',0,120)]
            conn.executemany('INSERT INTO ticket_types(event_id,type_name,price,total_tickets,available_tickets,description) VALUES (?,?,?,?,?,?)',
                             [(event_id,*p,p[2],f'{p[0]} ticket') for p in prices])
    # Volunteer and sponsor demo records. Use safe lookups so a partially
    # populated/older database does not crash during startup.
    vol_account = users.get('volunteer@efms.local')
    sponsor_account = users.get('sponsor@efms.local')
    if vol_account and conn.execute('SELECT COUNT(*) FROM volunteers').fetchone()[0] == 0:
        conn.execute('INSERT INTO volunteers(user_id,name,phone,email,skills,availability_status,status) VALUES (?,?,?,?,?,?,?)',
                     (vol_account['user_id'],'Demo Volunteer','9876543213','volunteer@efms.local','Registration, Crowd Management','Available','Active'))
    if sponsor_account and conn.execute('SELECT COUNT(*) FROM sponsors').fetchone()[0] == 0:
        conn.execute('INSERT INTO sponsors(user_id,company_name,contact_person,phone,email,address,status) VALUES (?,?,?,?,?,?,?)',
                     (sponsor_account['user_id'],'TechCorp','Demo Sponsor','9876543214','sponsor@efms.local','Kolkata','Active'))
    if conn.execute('SELECT COUNT(*) FROM sponsorship_packages').fetchone()[0] == 0:
        conn.executemany('INSERT INTO sponsorship_packages(package_name,amount,benefits,description,status) VALUES (?,?,?,?,?)', [
            ('Silver',25000,'Logo placement, social mention','Entry sponsorship','Active'),
            ('Gold',50000,'Stage branding, social campaign, stalls','Premium sponsorship','Active'),
            ('Platinum',100000,'Title branding, premium stall, stage mention','Title sponsorship','Active')])
    if conn.execute('SELECT COUNT(*) FROM sponsorships').fetchone()[0] == 0:
        sponsor_id=conn.execute('SELECT sponsor_id FROM sponsors LIMIT 1').fetchone()['sponsor_id']
        package_id=conn.execute("SELECT package_id FROM sponsorship_packages WHERE package_name='Gold'").fetchone()['package_id']
        festival_id=conn.execute('SELECT festival_id FROM festivals ORDER BY festival_id LIMIT 1').fetchone()['festival_id']
        conn.execute('INSERT INTO sponsorships(sponsor_id,festival_id,package_id,amount,start_date,end_date,status) VALUES (?,?,?,?,?,?,?)',
                     (sponsor_id,festival_id,package_id,50000,'2026-11-01','2026-11-30','Active'))
    if conn.execute('SELECT COUNT(*) FROM resources').fetchone()[0] == 0:
        conn.executemany('INSERT INTO resources(resource_name,description,quantity_total,quantity_available,resource_type,status) VALUES (?,?,?,?,?,?)', [
            ('Wireless Microphone','Stage microphone',20,20,'Equipment','Available'),('Speaker System','PA speakers',8,8,'Equipment','Available'),
            ('Projector','HD projector',6,6,'Equipment','Available'),('Folding Chair','Event seating',1000,1000,'Furniture','Available')])


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'warning')
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if session.get('role') not in roles:
                flash('You do not have permission for this action.', 'danger')
                return redirect(url_for('dashboard'))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def query(sql, params=(), one=False):
    conn = db()
    cur = conn.execute(sql, params)
    rows = cur.fetchone() if one else cur.fetchall()
    conn.close()
    return rows


def execute(sql, params=()):
    conn = db()
    cur = conn.execute(sql, params)
    conn.commit()
    last = cur.lastrowid
    conn.close()
    return last


def audit(action, entity_type, entity_id=None, details=''):
    try:
        execute('INSERT INTO audit_logs(user_id,action,entity_type,entity_id,details,ip_address) VALUES (?,?,?,?,?,?)', (session.get('user_id'), action, entity_type, str(entity_id) if entity_id is not None else None, details, request.remote_addr))
    except sqlite3.Error:
        pass


@app.context_processor
def inject_globals():
    photo = None
    if session.get('user_id'):
        try:
            row = query('SELECT profile_photo FROM user_profiles WHERE user_id=?', (session['user_id'],), one=True)
            photo = row['profile_photo'] if row else None
        except Exception:
            photo = None
    return {'current_year': datetime.now().year, 'nav_profile_photo': photo}


@app.route('/')
def index():
    # Public first-impression page; authenticated users can continue to their workspace.
    if 'user_id' in session:
        return redirect(url_for('portal') if session.get('role') in ('Organizer','Volunteer','Participant') else url_for('dashboard'))
    return render_template('landing.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        user = query('SELECT u.*, r.name role_name FROM users u JOIN roles r ON r.role_id=u.role_id WHERE lower(u.email)=?', (email,), one=True)
        if user and check_password_hash(user['password_hash'], password):
            if not user['email_verified']:
                flash('Please verify your email before signing in. Enter your email on the verification page.', 'warning')
                return redirect(url_for('verify_email', email=user['email']))
            session.clear()
            session.update(user_id=user['user_id'], name=user['name'], role=user['role_name'], email=user['email'])
            audit('LOGIN','User',user['user_id'],'Successful login')
            flash(f'Welcome, {user["name"]}!', 'success')
            return redirect(url_for('portal') if user['role_name'] in ('Organizer','Volunteer','Participant') else url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'festivals': query('SELECT COUNT(*) c FROM festivals', one=True)['c'],
        'events': query('SELECT COUNT(*) c FROM events', one=True)['c'],
        'registrations': query('SELECT COUNT(*) c FROM registrations', one=True)['c'],
        'revenue': query("SELECT COALESCE(SUM(amount),0) v FROM payments WHERE status='Success'", one=True)['v'],
        'volunteers': query("SELECT COUNT(*) c FROM volunteers WHERE status='Active'", one=True)['c'],
        'sponsors': query("SELECT COUNT(*) c FROM sponsors WHERE status='Active'", one=True)['c'],
    }
    upcoming = query('''SELECT e.*, f.festival_name, ec.name category_name, v.venue_name, s.event_date, s.start_time, s.end_time
                        FROM events e JOIN festivals f ON f.festival_id=e.festival_id
                        JOIN event_categories ec ON ec.category_id=e.category_id
                        LEFT JOIN event_schedules s ON s.event_id=e.event_id
                        LEFT JOIN venues v ON v.venue_id=s.venue_id
                        WHERE e.status != 'Cancelled' ORDER BY s.event_date, s.start_time LIMIT 8''')
    return render_template('dashboard.html', stats=stats, upcoming=upcoming)


# Module 1: festivals
@app.route('/festivals')
@login_required
def festivals():
    rows = query('''SELECT f.*, fc.name category_name, o.organization_name
                    FROM festivals f JOIN festival_categories fc ON fc.category_id=f.category_id
                    LEFT JOIN organizers o ON o.organizer_id=f.organizer_id ORDER BY f.start_date DESC''')
    categories = query('SELECT * FROM festival_categories ORDER BY name')
    organizers = query('SELECT * FROM organizers WHERE approval_status="Approved" ORDER BY organization_name')
    return render_template('festivals.html', festivals=rows, categories=categories, organizers=organizers)


@app.route('/festivals/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_festival():
    data = request.form
    execute('''INSERT INTO festivals(festival_name,description,theme,start_date,end_date,location,category_id,organizer_id,status,budget)
               VALUES (?,?,?,?,?,?,?,?,?,?)''', (data['festival_name'],data.get('description'),data.get('theme'),data['start_date'],data['end_date'],data['location'],data['category_id'],data.get('organizer_id') or None,data.get('status','Upcoming'),float(data.get('budget') or 0)))
    flash('Festival created successfully.', 'success')
    return redirect(url_for('festivals'))


@app.route('/festivals/<int:festival_id>/status', methods=['POST'])
@role_required('Admin','Organizer')
def festival_status(festival_id):
    execute('UPDATE festivals SET status=? WHERE festival_id=?', (request.form['status'], festival_id))
    flash('Festival status updated.', 'success')
    return redirect(url_for('festivals'))


# Module 2: events and venues
@app.route('/events')
@login_required
def events():
    events = query('''SELECT e.*, f.festival_name, ec.name category_name, c.name coordinator_name,
                             s.event_date, s.start_time, s.end_time, v.venue_name
                      FROM events e JOIN festivals f ON f.festival_id=e.festival_id
                      JOIN event_categories ec ON ec.category_id=e.category_id
                      LEFT JOIN event_coordinators c ON c.coordinator_id=e.coordinator_id
                      LEFT JOIN event_schedules s ON s.event_id=e.event_id
                      LEFT JOIN venues v ON v.venue_id=s.venue_id
                      ORDER BY s.event_date DESC, e.event_id DESC''')
    festivals = query('SELECT festival_id,festival_name FROM festivals ORDER BY start_date DESC')
    categories = query('SELECT * FROM event_categories ORDER BY name')
    coordinators = query('SELECT * FROM event_coordinators ORDER BY name')
    venues = query('SELECT * FROM venues ORDER BY venue_name')
    resources = query('SELECT * FROM resources ORDER BY resource_name')
    return render_template('events.html', events=events, festivals=festivals, categories=categories, coordinators=coordinators, venues=venues, resources=resources)


@app.route('/events/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_event():
    d=request.form
    conn=db()
    try:
        max_participants=int(d.get('max_participants') or 0)
        if d.get('venue_id') and d.get('event_date'):
            if d['start_time'] >= d['end_time']: raise ValueError('Event end time must be after start time.')
            venue=conn.execute('SELECT capacity FROM venues WHERE venue_id=?',(d['venue_id'],)).fetchone()
            if venue and max_participants and max_participants > venue['capacity']: raise ValueError('Event participant limit exceeds venue capacity.')
            conflict=conn.execute('SELECT COUNT(*) c FROM event_schedules WHERE venue_id=? AND event_date=? AND start_time < ? AND end_time > ?', (d['venue_id'],d['event_date'],d['end_time'],d['start_time'])).fetchone()['c']
            if conflict: raise ValueError('Selected venue is already booked for the given time.')
        cur=conn.execute('''INSERT INTO events(festival_id,category_id,coordinator_id,event_name,description,rules,eligibility_criteria,max_participants,min_participants,registration_deadline,status)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?)''', (d['festival_id'],d['category_id'],d.get('coordinator_id') or None,d['event_name'],d.get('description'),d.get('rules'),d.get('eligibility_criteria'),max_participants,int(d.get('min_participants') or 0),d.get('registration_deadline'),'Pending Approval'))
        event_id=cur.lastrowid
        conn.execute('INSERT INTO event_approvals(event_id,submitted_by,status) VALUES (?,?,?)',(event_id,session.get('user_id'),'Pending'))
        if d.get('venue_id') and d.get('event_date'):
            conn.execute('INSERT INTO event_schedules(event_id,venue_id,event_date,start_time,end_time,status) VALUES (?,?,?,?,?,?)', (event_id,d['venue_id'],d['event_date'],d['start_time'],d['end_time'],'Scheduled'))
        conn.commit(); audit('CREATE','Event',event_id,d['event_name'])
        flash('Event created and submitted for approval.', 'success')
    except Exception as e:
        conn.rollback(); flash(str(e), 'danger')
    finally: conn.close()
    return redirect(url_for('events'))


@app.route('/events/<int:event_id>/schedule', methods=['POST'])
@role_required('Admin','Organizer')
def schedule_event(event_id):
    d=request.form
    conn=db()
    try:
        if d['start_time'] >= d['end_time']: raise ValueError('Event end time must be after start time.')
        event_row=conn.execute('SELECT max_participants FROM events WHERE event_id=?',(event_id,)).fetchone()
        venue_row=conn.execute('SELECT capacity FROM venues WHERE venue_id=?',(d['venue_id'],)).fetchone()
        if venue_row and event_row and event_row['max_participants'] and event_row['max_participants'] > venue_row['capacity']:
            raise ValueError('Event participant limit exceeds venue capacity.')
        conflict=conn.execute('''SELECT COUNT(*) c FROM event_schedules WHERE venue_id=? AND event_date=? AND start_time < ? AND end_time > ? AND event_id<>?''',
                              (d['venue_id'],d['event_date'],d['end_time'],d['start_time'],event_id)).fetchone()['c']
        if conflict: raise ValueError('Venue/time conflict detected. Choose another slot.')
        conn.execute('DELETE FROM event_schedules WHERE event_id=?',(event_id,))
        conn.execute('INSERT INTO event_schedules(event_id,venue_id,event_date,start_time,end_time,status) VALUES (?,?,?,?,?,?)',
                     (event_id,d['venue_id'],d['event_date'],d['start_time'],d['end_time'],'Scheduled'))
        conn.commit(); flash('Event schedule updated.', 'success')
    except Exception as e:
        conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('events'))


@app.route('/venues/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_venue():
    d=request.form
    execute('INSERT INTO venues(venue_name,location,capacity,venue_type,facilities,status) VALUES (?,?,?,?,?,?)',
            (d['venue_name'],d['location'],int(d['capacity']),d['venue_type'],d.get('facilities'),d.get('status','Available')))
    flash('Venue added.', 'success')
    return redirect(url_for('events'))


# Module 3: registration, tickets, payments, attendance
@app.route('/registrations')
@login_required
def registrations():
    events=query('''SELECT e.event_id,e.event_name,e.max_participants,e.registration_deadline,
                           COALESCE((SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.event_id AND r.status IN ('Pending','Approved')),0) registered
                    FROM events e WHERE e.status='Published' ORDER BY e.event_name''')
    tickets=query('''SELECT tt.*, e.event_name FROM ticket_types tt JOIN events e ON e.event_id=tt.event_id ORDER BY e.event_name, tt.price''')
    payment_methods=query('SELECT * FROM payment_methods ORDER BY method_id')
    regs=query('''SELECT r.*, u.name participant_name,u.email, e.event_name,tt.type_name,t.ticket_no,
                         COALESCE(r.amount_paid,0) paid_amount,r.payment_status payment_status,a.checkin_time,t.ticket_id
                  FROM registrations r JOIN participants pa ON pa.participant_id=r.participant_id
                  JOIN users u ON u.user_id=pa.user_id JOIN events e ON e.event_id=r.event_id
                  LEFT JOIN tickets t ON t.registration_id=r.registration_id LEFT JOIN ticket_types tt ON tt.ticket_type_id=t.ticket_type_id
                  LEFT JOIN attendance a ON a.registration_id=r.registration_id
                  ORDER BY r.registration_date DESC''')
    return render_template('registrations.html', events=events, tickets=tickets, registrations=regs, payment_methods=payment_methods)


@app.route('/registrations/create', methods=['POST'])
@role_required('Admin','Organizer','Participant')
def create_registration():
    d=request.form
    user_id=int(d['user_id']) if session.get('role')=='Admin' and d.get('user_id') else session['user_id']
    conn=db()
    try:
        p=conn.execute('SELECT participant_id FROM participants WHERE user_id=?',(user_id,)).fetchone()
        if not p:
            u=conn.execute('SELECT * FROM users WHERE user_id=?',(user_id,)).fetchone()
            conn.execute('INSERT INTO participants(user_id,name,email,phone) VALUES (?,?,?,?)',(user_id,u['name'],u['email'],u['phone']))
            p=conn.execute('SELECT participant_id FROM participants WHERE user_id=?',(user_id,)).fetchone()
        event_id=int(d['event_id']); ticket_type_id=int(d['ticket_type_id']); qty=max(1,int(d.get('quantity') or 1))
        event_row=conn.execute('SELECT * FROM events WHERE event_id=?',(event_id,)).fetchone()
        if not event_row or event_row['status']!='Published': raise ValueError('This event is not approved for registration yet.')
        if event_row['organizer_user_id'] == user_id: raise ValueError('An event host cannot register as a participant in their own event.')
        if event_row['registration_deadline'] and event_row['registration_deadline'] < datetime.now().strftime('%Y-%m-%d'): raise ValueError('The registration deadline has passed.')
        current_count=conn.execute("SELECT COUNT(*) c FROM registrations WHERE event_id=? AND status IN ('Pending','Approved')",(event_id,)).fetchone()['c']
        if event_row['max_participants'] and current_count+qty>event_row['max_participants']: raise ValueError('Event capacity is full. Join the waitlist from Parking & Safety Hub.')
        tt=conn.execute('SELECT * FROM ticket_types WHERE ticket_type_id=?',(ticket_type_id,)).fetchone()
        if not tt or tt['event_id']!=event_id: raise ValueError('Invalid ticket type for selected event.')
        if tt['available_tickets']<qty: raise ValueError('Not enough tickets available.')
        existing=conn.execute("SELECT COUNT(*) c FROM registrations WHERE participant_id=? AND event_id=? AND status IN ('Pending','Approved')",(p['participant_id'],event_id)).fetchone()['c']
        if existing: raise ValueError('Participant is already registered for this event.')
        total=tt['price']*qty
        cur=conn.execute('INSERT INTO registrations(participant_id,event_id,registration_date,status,payment_status,amount_paid) VALUES (?,?,?,?,?,?)',
                          (p['participant_id'],event_id,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'Approved','Pending',0))
        reg_id=cur.lastrowid
        for _ in range(qty):
            code='EFMS-'+secrets.token_hex(10).upper()
            conn.execute('INSERT INTO tickets(registration_id,ticket_type_id,quantity,unit_price,total_price,final_amount,ticket_no,qr_code,status) VALUES (?,?,?,?,?,?,?,?,?)',
                         (reg_id,ticket_type_id,1,tt['price'],tt['price'],tt['price'],code,code,'Active'))
        conn.execute('UPDATE ticket_types SET available_tickets=available_tickets-? WHERE ticket_type_id=?',(qty,ticket_type_id))
        conn.commit(); flash(f'Registration created. Ticket code: EFMS-{datetime.now().strftime("%y%m%d")}-{reg_id:05d}-1','success')
    except Exception as e:
        conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('registrations'))


@app.route('/payments/create', methods=['POST'])
@role_required('Admin','Organizer','Participant')
def create_payment():
    d=request.form
    conn=db()
    try:
        reg=conn.execute('SELECT * FROM registrations WHERE registration_id=?',(d['registration_id'],)).fetchone()
        if not reg: raise ValueError('Registration not found.')
        amount=float(d['amount']); status=d.get('status','Success')
        conn.execute('INSERT INTO payments(registration_id,amount,payment_method_id,transaction_id,payment_date,status) VALUES (?,?,?,?,?,?)',
                     (reg['registration_id'],amount,d.get('payment_method_id'),d.get('transaction_id') or f'TXN{datetime.now().strftime("%Y%m%d%H%M%S")}',datetime.now().strftime('%Y-%m-%d %H:%M:%S'),status))
        if status=='Success':
            conn.execute("UPDATE registrations SET payment_status='Paid',amount_paid=? WHERE registration_id=?",(amount,reg['registration_id']))
        conn.commit(); flash('Payment recorded.','success')
    except Exception as e:
        conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('registrations'))


@app.route('/registrations/<int:registration_id>/cancel', methods=['POST'])
@login_required
def cancel_registration(registration_id):
    conn=db()
    try:
        reg=conn.execute('SELECT r.*,p.user_id FROM registrations r JOIN participants p ON p.participant_id=r.participant_id WHERE r.registration_id=?',(registration_id,)).fetchone()
        if not reg: raise ValueError('Registration not found.')
        if session.get('role') not in ('Admin','Organizer') and reg['user_id'] != session.get('user_id'):
            abort(403)
        if reg['status']=='Cancelled': raise ValueError('Registration is already cancelled.')
        ticket_rows=conn.execute("SELECT ticket_type_id,COUNT(*) qty FROM tickets WHERE registration_id=? AND status='Active' GROUP BY ticket_type_id",(registration_id,)).fetchall()
        conn.execute("UPDATE registrations SET status='Cancelled' WHERE registration_id=?",(registration_id,))
        conn.execute("UPDATE tickets SET status='Cancelled' WHERE registration_id=?",(registration_id,))
        for row in ticket_rows:
            conn.execute('UPDATE ticket_types SET available_tickets=MIN(total_tickets,available_tickets+?) WHERE ticket_type_id=?',(row['qty'],row['ticket_type_id']))
        # Promote the earliest waiting-list entry for the released event capacity.
        next_wait=conn.execute("SELECT waitlist_id FROM waitlist WHERE event_id=? AND status='Waiting' ORDER BY requested_at LIMIT 1",(reg['event_id'],)).fetchone()
        if next_wait: conn.execute("UPDATE waitlist SET status='Offered' WHERE waitlist_id=?",(next_wait['waitlist_id'],))
        conn.commit(); audit('CANCEL','Registration',registration_id,'Tickets cancelled and inventory restored')
        flash('Registration cancelled; ticket inventory restored.'+(' The next waitlisted participant was marked Offered.' if next_wait else ''),'success')
    except Exception as e:
        conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('registrations'))

@app.route('/attendance/scan', methods=['POST'])
@role_required('Admin','Organizer','Volunteer')
def scan_ticket():
    code=request.form.get('ticket_code','').strip()
    conn=db()
    try:
        ticket=conn.execute("SELECT t.*,r.registration_id,r.status registration_status,r.event_id,e.organizer_user_id FROM tickets t JOIN registrations r ON r.registration_id=t.registration_id JOIN events e ON e.event_id=r.event_id WHERE t.ticket_no=? OR t.qr_code=?",(code,code)).fetchone()
        if not ticket: raise ValueError('Ticket code not found.')
        if ticket['status']!='Active' or ticket['registration_status']=='Cancelled': raise ValueError('This ticket is not active.')
        paid=conn.execute("SELECT payment_status FROM registrations WHERE registration_id=?",(ticket['registration_id'],)).fetchone()
        if not paid or paid['payment_status']!='Paid': raise ValueError('Payment is not confirmed; this ticket cannot be checked in.')
        if session.get('role')=='Organizer' and ticket['organizer_user_id'] != session.get('user_id'): raise ValueError('You can only check in tickets for events you organize.')
        if session.get('role')=='Volunteer':
            assigned=conn.execute("SELECT 1 FROM volunteer_assignments va JOIN volunteers v ON v.volunteer_id=va.volunteer_id WHERE v.user_id=? AND va.event_id=? AND va.status IN ('Assigned','Accepted')",(session['user_id'],ticket['event_id'])).fetchone()
            if not assigned: raise ValueError('You are not assigned to this event and cannot scan its tickets.')
        prior=conn.execute('SELECT status FROM ticket_checkins WHERE ticket_id=(SELECT ticket_id FROM tickets WHERE ticket_no=? OR qr_code=? LIMIT 1)',(code,code)).fetchone()
        if prior and prior['status']=='Present': raise ValueError('This ticket has already been checked in.')
        conn.execute("INSERT INTO ticket_checkins(ticket_id,checkin_time,status,scanned_by) SELECT ticket_id,?,'Present',? FROM tickets WHERE ticket_no=? OR qr_code=? ON CONFLICT(ticket_id) DO UPDATE SET checkin_time=excluded.checkin_time,status='Present',scanned_by=excluded.scanned_by",(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),session['user_id'],code,code))
        conn.commit(); audit('CHECK_IN','Ticket',ticket['ticket_no'],'Ticket code verified')
        flash('Ticket verified and participant checked in.','success')
    except Exception as e:
        conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('registrations'))

@app.route('/attendance/<int:registration_id>', methods=['POST'])
@role_required('Admin','Organizer','Volunteer')
def mark_attendance(registration_id):
    conn=db()
    try:
        reg=conn.execute('SELECT r.*,e.organizer_user_id FROM registrations r JOIN events e ON e.event_id=r.event_id WHERE r.registration_id=?',(registration_id,)).fetchone()
        if not reg: raise ValueError('Registration not found.')
        if reg['payment_status']!='Paid' or reg['status']=='Cancelled': raise ValueError('Only paid, active registrations can be checked in.')
        if session.get('role')=='Organizer' and reg['organizer_user_id']!=session.get('user_id'): raise ValueError('You can only mark attendance for your own events.')
        if session.get('role')=='Volunteer' and not conn.execute("SELECT 1 FROM volunteer_assignments va JOIN volunteers v ON v.volunteer_id=va.volunteer_id WHERE v.user_id=? AND va.event_id=? AND va.status IN ('Assigned','Accepted')",(session['user_id'],reg['event_id'])).fetchone(): raise ValueError('You are not assigned to this event.')
        previous=conn.execute("SELECT status FROM attendance WHERE registration_id=?",(registration_id,)).fetchone()
        if previous and previous['status']=='Present': raise ValueError('Attendance has already been recorded.')
        conn.execute('''INSERT INTO attendance(registration_id,checkin_time,status,scanned_by) VALUES (?,?,?,?)
                        ON CONFLICT(registration_id) DO UPDATE SET checkin_time=excluded.checkin_time,status='Present',scanned_by=excluded.scanned_by''',
                     (registration_id,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'Present',session['user_id']))
        conn.commit(); flash('Attendance marked.','success')
    except Exception as e: conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('registrations'))


# Module 4
@app.route('/operations')
@login_required
def operations():
    volunteers=query('''SELECT v.*,u.email FROM volunteers v JOIN users u ON u.user_id=v.user_id ORDER BY v.name''')
    sponsors=query('''SELECT * FROM sponsors ORDER BY company_name''')
    feedback=query('''SELECT f.*,e.event_name,u.name FROM feedback f JOIN events e ON e.event_id=f.event_id JOIN users u ON u.user_id=f.user_id ORDER BY f.feedback_date DESC''')
    events=query('SELECT event_id,event_name FROM events ORDER BY event_name')
    return render_template('operations.html',volunteers=volunteers,sponsors=sponsors,feedback=feedback,events=events)


@app.route('/volunteers/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_volunteer():
    d=request.form
    conn=db()
    try:
        existing=conn.execute('SELECT user_id FROM users WHERE lower(email)=?',(d['email'].lower(),)).fetchone()
        role=conn.execute('SELECT role_id FROM roles WHERE name="Volunteer"').fetchone()['role_id']
        if existing: uid=existing['user_id']
        else:
            uid=conn.execute('INSERT INTO users(name,email,phone,password_hash,role_id) VALUES (?,?,?,?,?)',
                              (d['name'],d['email'],d.get('phone'),generate_password_hash('vol123'),role)).lastrowid
        conn.execute('INSERT INTO volunteers(user_id,name,phone,email,skills,availability_status,status) VALUES (?,?,?,?,?,?,?)',
                     (uid,d['name'],d.get('phone'),d['email'],d.get('skills'),'Available','Active'))
        conn.commit(); flash('Volunteer added. Default password: vol123','success')
    except Exception as e: conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('operations'))


@app.route('/sponsors/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_sponsor():
    d=request.form
    conn=db()
    try:
        role=conn.execute('SELECT role_id FROM roles WHERE name="Sponsor"').fetchone()['role_id']
        uid=conn.execute('INSERT INTO users(name,email,phone,password_hash,role_id) VALUES (?,?,?,?,?)',
                          (d['contact_person'],d['email'],d.get('phone'),generate_password_hash('sponsor123'),role)).lastrowid
        conn.execute('INSERT INTO sponsors(user_id,company_name,contact_person,phone,email,address,status) VALUES (?,?,?,?,?,?,?)',
                     (uid,d['company_name'],d['contact_person'],d.get('phone'),d['email'],d.get('address'),'Active'))
        conn.commit(); flash('Sponsor added. Default password: sponsor123','success')
    except Exception as e: conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('operations'))


@app.route('/feedback/create', methods=['POST'])
@login_required
def create_feedback():
    d=request.form
    execute('INSERT INTO feedback(event_id,user_id,rating,comments,feedback_date,status) VALUES (?,?,?,?,?,?)',
            (d['event_id'],session['user_id'],int(d['rating']),d.get('comments'),datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'New'))
    flash('Feedback submitted.','success')
    return redirect(url_for('operations'))


# Reports
@app.route('/reports')
@login_required
def reports():
    # Convert sqlite3.Row objects to ordinary dictionaries before passing
    # them to Jinja. The reports template calls stats.items(), row.keys()
    # and row[key], which are consistently supported by dictionaries.
    stats_row = query('''SELECT
        (SELECT COUNT(*) FROM festivals) festivals,
        (SELECT COUNT(*) FROM events) events,
        (SELECT COUNT(*) FROM registrations) registrations,
        (SELECT COUNT(*) FROM attendance WHERE status='Present') attendance,
        (SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='Success') revenue,
        (SELECT COALESCE(SUM(amount),0) FROM sponsorships WHERE status='Active') sponsorship''', one=True)
    stats = dict(stats_row) if stats_row is not None else {}

    event_rows = query('''SELECT e.event_name,f.festival_name,COUNT(DISTINCT r.registration_id) registrations,
                                 COALESCE(SUM(p.amount),0) revenue,COUNT(DISTINCT a.attendance_id) attendance,
                                 ROUND(COALESCE(AVG(fe.rating),0),2) rating
                          FROM events e JOIN festivals f ON f.festival_id=e.festival_id
                          LEFT JOIN registrations r ON r.event_id=e.event_id
                          LEFT JOIN payments p ON p.registration_id=r.registration_id AND p.status='Success'
                          LEFT JOIN attendance a ON a.registration_id=r.registration_id
                          LEFT JOIN feedback fe ON fe.event_id=e.event_id
                          GROUP BY e.event_id ORDER BY registrations DESC''')
    event_report = [dict(row) for row in event_rows]

    venue_rows = query('''SELECT v.venue_name, v.capacity, COUNT(es.schedule_id) bookings
                         FROM venues v LEFT JOIN event_schedules es ON es.venue_id=v.venue_id
                         GROUP BY v.venue_id ORDER BY bookings DESC''')
    venue_report = [dict(row) for row in venue_rows]

    return render_template(
        'reports.html',
        stats=stats,
        event_report=event_report,
        venue_report=venue_report
    )


# Lightweight API endpoints for dynamic frontend
@app.route('/api/events/<int:festival_id>')
def api_events(festival_id):
    return jsonify([dict(r) for r in query("SELECT event_id,event_name,max_participants FROM events WHERE festival_id=? AND status='Published' ORDER BY event_name",(festival_id,))])

@app.route('/api/tickets/<int:event_id>')
def api_tickets(event_id):
    return jsonify([dict(r) for r in query('SELECT ticket_type_id,type_name,price,available_tickets FROM ticket_types WHERE event_id=? ORDER BY price',(event_id,))])


# Upgrade workspace: parking, finance, approvals, safety, communications and maintenance
@app.route('/operations-hub')
@login_required
def operations_hub():
    role=session.get('role')
    zones=query("SELECT z.*, (SELECT COUNT(*) FROM parking_allocations p WHERE p.parking_zone_id=z.parking_zone_id AND p.status IN ('Reserved','Entered')) occupied FROM parking_zones z ORDER BY zone_name")
    parking=query("SELECT p.*,z.zone_name,e.event_name FROM parking_allocations p JOIN parking_zones z ON z.parking_zone_id=p.parking_zone_id LEFT JOIN events e ON e.event_id=p.event_id ORDER BY p.parking_allocation_id DESC LIMIT 30")
    festivals=query('SELECT festival_id,festival_name,budget FROM festivals ORDER BY festival_name')
    events=query('SELECT event_id,event_name,max_participants,status FROM events ORDER BY event_name')
    volunteers=query('SELECT volunteer_id,name FROM volunteers WHERE status="Active" ORDER BY name')
    shifts=query('SELECT sh.*,v.name volunteer_name,e.event_name FROM volunteer_shifts sh JOIN volunteers v ON v.volunteer_id=sh.volunteer_id JOIN events e ON e.event_id=sh.event_id ORDER BY shift_date,start_time DESC LIMIT 30')
    expenses=query('SELECT x.*,f.festival_name,u.name recorder FROM budget_expenses x JOIN festivals f ON f.festival_id=x.festival_id LEFT JOIN users u ON u.user_id=x.recorded_by ORDER BY expense_date DESC LIMIT 30')
    budget_summary=query("SELECT f.festival_id,f.festival_name,f.budget,COALESCE(SUM(CASE WHEN x.status='Approved' THEN x.amount ELSE 0 END),0) spent,(f.budget-COALESCE(SUM(CASE WHEN x.status='Approved' THEN x.amount ELSE 0 END),0)) remaining FROM festivals f LEFT JOIN budget_expenses x ON x.festival_id=f.festival_id GROUP BY f.festival_id ORDER BY f.start_date")
    emergency_contacts=query('SELECT ec.*,e.event_name FROM emergency_contacts ec LEFT JOIN events e ON e.event_id=ec.assigned_event_id ORDER BY ec.name')
    approvals=query('SELECT a.*,e.event_name,f.festival_name,u.name submitter FROM event_approvals a JOIN events e ON e.event_id=a.event_id JOIN festivals f ON f.festival_id=e.festival_id LEFT JOIN users u ON u.user_id=a.submitted_by ORDER BY a.submitted_at DESC')
    waitlist_rows=query('SELECT w.*,e.event_name,u.name,u.email FROM waitlist w JOIN events e ON e.event_id=w.event_id JOIN users u ON u.user_id=w.user_id ORDER BY requested_at')
    lost=query('SELECT l.*,e.event_name FROM lost_found l LEFT JOIN events e ON e.event_id=l.event_id ORDER BY reported_at DESC LIMIT 30')
    announcements=query('SELECT a.*,u.name creator,e.event_name FROM announcements a JOIN users u ON u.user_id=a.created_by LEFT JOIN events e ON e.event_id=a.event_id ORDER BY created_at DESC LIMIT 30')
    crowd=query('SELECT c.*,e.event_name,u.name reporter FROM accessibility_crowd_checks c JOIN events e ON e.event_id=c.event_id LEFT JOIN users u ON u.user_id=c.reported_by ORDER BY created_at DESC LIMIT 20')
    incidents=query('SELECT i.*,e.event_name FROM incidents i LEFT JOIN events e ON e.event_id=i.event_id ORDER BY incident_date DESC LIMIT 20')
    logs=query('SELECT a.*,u.name FROM audit_logs a LEFT JOIN users u ON u.user_id=a.user_id ORDER BY created_at DESC LIMIT 30') if role=='Admin' else []
    certificates=query('SELECT c.*,r.registration_id,e.event_name FROM certificates c JOIN registrations r ON r.registration_id=c.registration_id JOIN events e ON e.event_id=r.event_id ORDER BY c.certificate_id DESC LIMIT 20')
    registrations=query('SELECT r.registration_id,u.name,e.event_name FROM registrations r JOIN participants p ON p.participant_id=r.participant_id JOIN users u ON u.user_id=p.user_id JOIN events e ON e.event_id=r.event_id ORDER BY r.registration_id DESC LIMIT 100')
    return render_template('operations_hub.html',zones=zones,parking=parking,festivals=festivals,events=events,volunteers=volunteers,shifts=shifts,expenses=expenses,approvals=approvals,waitlist_rows=waitlist_rows,lost=lost,announcements=announcements,crowd=crowd,incidents=incidents,logs=logs,certificates=certificates,registrations=registrations,budget_summary=budget_summary,emergency_contacts=emergency_contacts,role=role)

@app.route('/parking/zones/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_parking_zone():
    d=request.form
    try:
        execute('INSERT INTO parking_zones(zone_name,location,vehicle_type,capacity,accessible_spaces,status,notes) VALUES (?,?,?,?,?,?,?)',(d['zone_name'].strip(),d['location'].strip(),d.get('vehicle_type','Any'),int(d['capacity']),int(d.get('accessible_spaces') or 0),d.get('status','Open'),d.get('notes')))
        audit('CREATE','ParkingZone',d['zone_name'],'Created parking zone'); flash('Parking zone created.','success')
    except Exception as e: flash(f'Could not create parking zone: {e}','danger')
    return redirect(url_for('operations_hub'))

@app.route('/parking/allocate', methods=['POST'])
@role_required('Admin','Organizer','Volunteer')
def allocate_parking():
    d=request.form; conn=db()
    try:
        zone=conn.execute('SELECT * FROM parking_zones WHERE parking_zone_id=?',(d['parking_zone_id'],)).fetchone()
        if not zone or zone['status']!='Open': raise ValueError('Parking zone is not open.')
        active=conn.execute("SELECT COUNT(*) c FROM parking_allocations WHERE parking_zone_id=? AND status IN ('Reserved','Entered')",(zone['parking_zone_id'],)).fetchone()['c']
        if active>=zone['capacity']: raise ValueError('Parking zone is full; allocation denied.')
        vtype=d.get('vehicle_type','Car')
        if conn.execute("SELECT COUNT(*) FROM parking_allocations WHERE upper(vehicle_number)=upper(?) AND status IN ('Reserved','Entered')",(d['vehicle_number'].strip(),)).fetchone()[0]: raise ValueError('This vehicle already has an active parking pass.')
        if zone['vehicle_type'] not in ('Any',vtype): raise ValueError('Vehicle type is not allowed in this zone.')
        if d.get('accessible_need') and zone['accessible_spaces']:
            accessible_used=conn.execute("SELECT COUNT(*) FROM parking_allocations WHERE parking_zone_id=? AND accessible_need=1 AND status IN ('Reserved','Entered')",(zone['parking_zone_id'],)).fetchone()[0]
            if accessible_used>=zone['accessible_spaces']: raise ValueError('Accessible spaces are full in this zone.')
        passcode='PARK-'+secrets.token_hex(4).upper()
        conn.execute('INSERT INTO parking_allocations(parking_zone_id,user_id,event_id,visitor_name,vehicle_number,vehicle_type,pass_code,allocated_at,status,fee,accessible_need,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',(zone['parking_zone_id'],session['user_id'],d.get('event_id') or None,d['visitor_name'].strip(),d['vehicle_number'].strip().upper(),vtype,passcode,datetime.now().isoformat(timespec='seconds'),'Reserved',float(d.get('fee') or 0),1 if d.get('accessible_need') else 0,d.get('notes')))
        conn.commit(); audit('CREATE','ParkingAllocation',passcode,'Vehicle '+d['vehicle_number']); flash('Parking allocated. Pass code: '+passcode,'success')
    except Exception as e: conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('operations_hub'))

@app.route('/parking/<int:allocation_id>/<action>', methods=['POST'])
@role_required('Admin','Organizer','Volunteer')
def parking_action(allocation_id,action):
    if action not in ('enter','exit','cancel'): abort(404)
    p=query('SELECT * FROM parking_allocations WHERE parking_allocation_id=?',(allocation_id,),one=True)
    if not p: abort(404)
    now=datetime.now().isoformat(timespec='seconds')
    if action=='enter': execute("UPDATE parking_allocations SET status='Entered',entry_time=? WHERE parking_allocation_id=? AND status='Reserved'",(now,allocation_id))
    elif action=='exit': execute("UPDATE parking_allocations SET status='Exited',exit_time=? WHERE parking_allocation_id=? AND status='Entered'",(now,allocation_id))
    else: execute("UPDATE parking_allocations SET status='Cancelled' WHERE parking_allocation_id=? AND status='Reserved'",(allocation_id,))
    audit(action.upper(),'ParkingAllocation',allocation_id,p['pass_code']); flash('Parking status updated.','success'); return redirect(url_for('operations_hub'))

@app.route('/expenses/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_expense():
    d=request.form
    try:
        execute('INSERT INTO budget_expenses(festival_id,category,description,amount,expense_date,vendor,recorded_by,status) VALUES (?,?,?,?,?,?,?,?)',(d['festival_id'],d['category'],d['description'],float(d['amount']),d['expense_date'],d.get('vendor'),session['user_id'],d.get('status','Approved')))
        audit('CREATE','Expense',d['description'],'Amount='+d['amount']); flash('Expense recorded.','success')
    except Exception as e: flash('Expense not saved: '+str(e),'danger')
    return redirect(url_for('operations_hub'))

@app.route('/events/<int:event_id>/approval', methods=['POST'])
@role_required('Admin','Organizer')
def review_event(event_id):
    d=request.form; status=d.get('status')
    if status not in ('Approved','Rejected','Pending'): abort(400)
    conn=db()
    try:
        conn.execute('INSERT OR IGNORE INTO event_approvals(event_id,submitted_by,status) VALUES (?,?,?)',(event_id,session['user_id'],'Pending'))
        conn.execute('UPDATE event_approvals SET status=?,reviewer_id=?,review_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE event_id=?',(status,session['user_id'],d.get('review_note'),event_id))
        conn.execute('UPDATE events SET status=? WHERE event_id=?',('Published' if status=='Approved' else ('Rejected' if status=='Rejected' else 'Pending Approval'),event_id))
        conn.commit(); audit('REVIEW','Event',event_id,status); flash('Event '+status.lower()+'.','success')
    except Exception as e: conn.rollback(); flash(str(e),'danger')
    finally: conn.close()
    return redirect(url_for('operations_hub'))

@app.route('/volunteer-shifts/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_shift():
    d=request.form
    try:
        if d['start_time']>=d['end_time']: raise ValueError('Shift end time must be after start time.')
        overlaps=query("SELECT COUNT(*) c FROM volunteer_shifts WHERE volunteer_id=? AND shift_date=? AND status='Assigned' AND start_time<? AND end_time>?",(d['volunteer_id'],d['shift_date'],d['end_time'],d['start_time']),one=True)['c']
        if overlaps: raise ValueError('This volunteer already has an overlapping shift.')
        execute('INSERT INTO volunteer_shifts(volunteer_id,event_id,shift_date,start_time,end_time,duty,location,notes) VALUES (?,?,?,?,?,?,?,?)',(d['volunteer_id'],d['event_id'],d['shift_date'],d['start_time'],d['end_time'],d['duty'],d.get('location'),d.get('notes')))
        audit('CREATE','VolunteerShift',d['volunteer_id'],d['duty']); flash('Volunteer shift assigned.','success')
    except Exception as e: flash('Shift not saved: '+str(e),'danger')
    return redirect(url_for('operations_hub'))

@app.route('/waitlist/join', methods=['POST'])
@login_required
def join_waitlist():
    try:
        execute('INSERT INTO waitlist(event_id,user_id,requested_at) VALUES (?,?,?)',(request.form['event_id'],session['user_id'],datetime.now().isoformat(timespec='seconds')))
        audit('JOIN','Waitlist',request.form['event_id'],'Joined event waitlist'); flash('You joined the waitlist.','success')
    except Exception as e: flash('Could not join waitlist: '+str(e),'warning')
    return redirect(url_for('operations_hub'))

@app.route('/waitlist/<int:waitlist_id>/status', methods=['POST'])
@role_required('Admin','Organizer')
def update_waitlist(waitlist_id):
    status=request.form.get('status','Waiting')
    if status not in ('Waiting','Offered','Registered','Cancelled'): abort(400)
    execute('UPDATE waitlist SET status=? WHERE waitlist_id=?',(status,waitlist_id)); audit('UPDATE','Waitlist',waitlist_id,status); flash('Waitlist updated.','success'); return redirect(url_for('operations_hub'))

@app.route('/lost-found/create', methods=['POST'])
@login_required
def create_lost_found():
    d=request.form
    execute('INSERT INTO lost_found(event_id,item_type,item_name,description,location_found,reported_by,contact_info) VALUES (?,?,?,?,?,?,?)',(d.get('event_id') or None,d['item_type'],d['item_name'],d.get('description'),d.get('location_found'),session['user_id'],d.get('contact_info')))
    audit('CREATE','LostFound',d['item_name'],d['item_type']); flash('Lost/found report submitted.','success'); return redirect(url_for('operations_hub'))

@app.route('/lost-found/<int:item_id>/status', methods=['POST'])
@role_required('Admin','Organizer','Volunteer')
def update_lost_found(item_id):
    status=request.form.get('status','Reported')
    if status not in ('Reported','Located','Claimed','Returned','Closed'): abort(400)
    execute("UPDATE lost_found SET status=?,claimed_by=?,resolved_at=CASE WHEN ? IN ('Returned','Closed') THEN CURRENT_TIMESTAMP ELSE resolved_at END WHERE item_id=?",(status,request.form.get('claimed_by'),status,item_id))
    audit('UPDATE','LostFound',item_id,status); flash('Lost-and-found status updated.','success'); return redirect(url_for('operations_hub'))

@app.route('/announcements/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_announcement():
    d=request.form
    audience=d.get('audience','All'); event_id=d.get('event_id') or None
    execute('INSERT INTO announcements(title,message,audience,event_id,created_by,status) VALUES (?,?,?,?,?,?)',(d['title'],d['message'],audience,event_id,session['user_id'],'Published'))
    role_map={'Participants':'Participant','Volunteers':'Volunteer','Organizers':'Organizer','Sponsors':'Sponsor'}
    if audience=='All': recipients=query("SELECT user_id FROM users WHERE status='Active'")
    else: recipients=query("SELECT u.user_id FROM users u JOIN roles r ON r.role_id=u.role_id WHERE r.name=? AND u.status='Active'",(role_map.get(audience,'Participant'),))
    for recipient in recipients:
        execute('INSERT INTO notifications(user_id,title,message,type,event_id,status) VALUES (?,?,?,?,?,?)',(recipient['user_id'],d['title'],d['message'],'Announcement',event_id,'Sent'))
    audit('CREATE','Announcement',d['title'],audience); flash('Announcement published and notification records created for '+str(len(recipients))+' users.','success'); return redirect(url_for('operations_hub'))

@app.route('/crowd-checks/create', methods=['POST'])
@role_required('Admin','Organizer','Volunteer')
def create_crowd_check():
    d=request.form; observed=int(d.get('observed_count') or 0); limit=int(d.get('safe_limit') or 0)
    status='Over Capacity' if limit and observed>limit else ('Near Capacity' if limit and observed>=limit*.85 else 'Normal')
    execute('INSERT INTO accessibility_crowd_checks(event_id,check_type,location,observed_count,safe_limit,accessibility_note,status,reported_by) VALUES (?,?,?,?,?,?,?,?)',(d['event_id'],d['check_type'],d.get('location'),observed,limit,d.get('accessibility_note'),status,session['user_id']))
    audit('CREATE','CrowdCheck',d['event_id'],status); flash('Crowd/accessibility check saved: '+status+'.','success' if status=='Normal' else 'warning'); return redirect(url_for('operations_hub'))

@app.route('/incidents/create', methods=['POST'])
@role_required('Admin','Organizer','Volunteer')
def create_incident():
    d=request.form
    execute('INSERT INTO incidents(event_id,incident_type,description,location,incident_date,severity,status,reported_by) VALUES (?,?,?,?,?,?,?,?)',(d.get('event_id') or None,d['incident_type'],d['description'],d.get('location'),datetime.now().isoformat(timespec='seconds'),d.get('severity','Medium'),'Open',session['user_id']))
    audit('CREATE','Incident',d['incident_type'],d.get('severity','Medium')); flash('Incident recorded. Follow campus emergency procedures for urgent threats.','warning'); return redirect(url_for('operations_hub'))

@app.route('/certificates/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_certificate():
    d=request.form; code='CERT-'+secrets.token_hex(5).upper()
    try:
        execute('INSERT INTO certificates(registration_id,certificate_no,issue_date,status) VALUES (?,?,?,?)',(d['registration_id'],code,datetime.now().strftime('%Y-%m-%d'),'Issued'))
        audit('ISSUE','Certificate',code,d['registration_id']); flash('Certificate issued: '+code,'success')
    except Exception as e: flash('Certificate not issued: '+str(e),'danger')
    return redirect(url_for('operations_hub'))

@app.route('/emergency-contacts/create', methods=['POST'])
@role_required('Admin','Organizer')
def create_emergency_contact():
    d=request.form
    execute('INSERT INTO emergency_contacts(name,role,phone,email,assigned_event_id,status) VALUES (?,?,?,?,?,?)',(d['name'],d.get('role'),d.get('phone'),d.get('email'),d.get('event_id') or None,'Active'))
    audit('CREATE','EmergencyContact',d['name'],d.get('role',''))
    flash('Emergency contact saved. Verify contact details before event day.','success')
    return redirect(url_for('operations_hub'))

@app.route('/tickets/<int:ticket_id>/qr')
@login_required
def ticket_qr(ticket_id):
    ticket=query('SELECT t.*,p.user_id owner_id,r.payment_status,e.organizer_user_id,r.event_id FROM tickets t JOIN registrations r ON r.registration_id=t.registration_id JOIN participants p ON p.participant_id=r.participant_id JOIN events e ON e.event_id=r.event_id WHERE t.ticket_id=?',(ticket_id,),one=True)
    if not ticket: abort(404)
    if ticket['payment_status'] != 'Paid':
        flash('QR ticket is available only after payment confirmation.', 'warning')
        return redirect(url_for('portal'))
    if session.get('role')=='Organizer' and ticket['organizer_user_id'] != session.get('user_id'): abort(403)
    if session.get('role')=='Volunteer' and not query("SELECT 1 FROM volunteer_assignments va JOIN volunteers v ON v.volunteer_id=va.volunteer_id WHERE v.user_id=? AND va.event_id=? AND va.status IN ('Assigned','Accepted')",(session['user_id'],ticket['event_id']),one=True): abort(403)
    if session.get('role') not in ('Admin','Organizer','Volunteer') and ticket['owner_id'] != session.get('user_id'): abort(403)
    try:
        import qrcode
        img=qrcode.make(ticket['qr_code'] or ticket['ticket_no']); output=io.BytesIO(); img.save(output,format='PNG'); output.seek(0)
        return send_file(output,mimetype='image/png',download_name=ticket['ticket_no']+'.png')
    except ImportError:
        return Response('Install qrcode[pil] to render QR images. Ticket code: '+(ticket['qr_code'] or ticket['ticket_no']),mimetype='text/plain')

@app.route('/maintenance/backup')
@role_required('Admin')
def database_backup():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True); backup_path=DB_PATH.parent/('efms_backup_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'.db')
    conn=db(); target=sqlite3.connect(str(backup_path))
    try: conn.backup(target)
    finally: target.close(); conn.close()
    audit('BACKUP','Database',backup_path.name,'SQLite online backup')
    return send_file(backup_path,as_attachment=True,download_name=backup_path.name)

@app.route('/maintenance/validate', methods=['POST'])
@role_required('Admin')
def validate_database():
    conn=db(); integrity=conn.execute('PRAGMA integrity_check').fetchone()[0]; foreign=conn.execute('PRAGMA foreign_key_check').fetchall()
    tables=[r['name'] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    conn.close(); audit('VALIDATE','Database',None,'integrity='+integrity+'; foreign_key_errors='+str(len(foreign)))
    flash('Database integrity: '+integrity+'. Foreign-key violations: '+str(len(foreign))+'. Tables checked: '+str(len(tables))+'.','success' if integrity=='ok' and not foreign else 'danger')
    return redirect(url_for('operations_hub'))

@app.route('/reports/export/<report_type>.csv')
@role_required('Admin','Organizer')
def export_report(report_type):
    reports={'events':('SELECT e.event_id,e.event_name,f.festival_name,e.status,s.event_date,s.start_time,s.end_time,v.venue_name FROM events e JOIN festivals f ON f.festival_id=e.festival_id LEFT JOIN event_schedules s ON s.event_id=e.event_id LEFT JOIN venues v ON v.venue_id=s.venue_id ORDER BY e.event_id','events.csv'),'parking':('SELECT p.pass_code,p.visitor_name,p.vehicle_number,p.vehicle_type,z.zone_name,p.status,p.entry_time,p.exit_time,p.fee FROM parking_allocations p JOIN parking_zones z ON z.parking_zone_id=p.parking_zone_id ORDER BY p.parking_allocation_id','parking.csv'),'expenses':('SELECT f.festival_name,x.category,x.description,x.amount,x.expense_date,x.vendor,x.status FROM budget_expenses x JOIN festivals f ON f.festival_id=x.festival_id ORDER BY x.expense_date','expenses.csv'),'registrations':('SELECT r.registration_id,u.name,u.email,e.event_name,r.registration_date,r.status,r.payment_status,r.amount_paid FROM registrations r JOIN participants p ON p.participant_id=r.participant_id JOIN users u ON u.user_id=p.user_id JOIN events e ON e.event_id=r.event_id ORDER BY r.registration_id','registrations.csv')}
    if report_type not in reports: abort(404)
    sql,filename=reports[report_type]; rows=query(sql); output=io.StringIO(); writer=csv.writer(output)
    if rows: writer.writerow(rows[0].keys()); writer.writerows([tuple(r) for r in rows])
    audit('EXPORT','Report',report_type,str(len(rows))+' rows')
    return Response('\ufeff'+output.getvalue(),mimetype='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename='+filename})

# Self-service profile editing and profile-photo upload.
def allowed_profile_image(filename, file_storage=None):
    if not filename or '.' not in filename:
        return False
    extension = filename.rsplit('.', 1)[1].lower()
    if extension not in ALLOWED_PROFILE_EXTENSIONS or file_storage is None:
        return False
    try:
        from PIL import Image
        file_storage.stream.seek(0)
        with Image.open(file_storage.stream) as image:
            image.verify()
            detected = (image.format or '').lower()
        file_storage.stream.seek(0)
        allowed_formats = {
            'png': {'png'},
            'jpg': {'jpeg'},
            'jpeg': {'jpeg'},
            'webp': {'webp'},
        }
        return detected in allowed_formats.get(extension, set())
    except Exception:
        try:
            file_storage.stream.seek(0)
        except Exception:
            pass
        return False

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    uid = session['user_id']
    conn = db()
    try:
        user = conn.execute('SELECT u.*, r.name AS role_name FROM users u JOIN roles r ON r.role_id=u.role_id WHERE u.user_id=?', (uid,)).fetchone()
        profile = conn.execute('SELECT * FROM user_profiles WHERE user_id=?', (uid,)).fetchone()
        if not profile:
            conn.execute('INSERT INTO user_profiles(user_id) VALUES (?)', (uid,))
            conn.commit()
            profile = conn.execute('SELECT * FROM user_profiles WHERE user_id=?', (uid,)).fetchone()
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            phone = request.form.get('phone', '').strip()
            if not name:
                flash('Full name is required.', 'danger')
                return redirect(url_for('edit_profile'))
            photo_path = profile['profile_photo']
            photo = request.files.get('profile_photo')
            if photo and photo.filename:
                if not allowed_profile_image(photo.filename, photo):
                    flash('Use a PNG, JPG, JPEG or WEBP profile photo.', 'danger')
                    return redirect(url_for('edit_profile'))
                ext = secure_filename(photo.filename).rsplit('.', 1)[1].lower()
                filename = f'user_{uid}_{secrets.token_hex(8)}.{ext}'
                photo.save(PROFILE_UPLOAD_DIR / filename)
                photo_path = f'uploads/profiles/{filename}'
            fields = {key: request.form.get(key, '').strip() for key in ('bio','date_of_birth','address','college','department','organization_name','website','education','experience','skills','availability','emergency_contact')}
            conn.execute('UPDATE users SET name=?, phone=? WHERE user_id=?', (name, phone, uid))
            conn.execute('UPDATE user_profiles SET profile_photo=?, bio=?, date_of_birth=?, address=?, college=?, department=?, organization_name=?, website=?, education=?, experience=?, skills=?, availability=?, emergency_contact=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=?', (photo_path, fields['bio'], fields['date_of_birth'], fields['address'], fields['college'], fields['department'], fields['organization_name'], fields['website'], fields['education'], fields['experience'], fields['skills'], fields['availability'], fields['emergency_contact'], uid))
            role = user['role_name']
            if role == 'Participant':
                conn.execute('UPDATE participants SET name=?, phone=?, dob=?, college_name=?, department=?, address=? WHERE user_id=?', (name, phone, fields['date_of_birth'], fields['college'], fields['department'], fields['address'], uid))
                conn.execute('UPDATE participant_profiles SET date_of_birth=?, college=?, department=?, address=?, emergency_contact=? WHERE user_id=?', (fields['date_of_birth'], fields['college'], fields['department'], fields['address'], fields['emergency_contact'], uid))
            elif role == 'Volunteer':
                conn.execute('UPDATE volunteers SET name=?, phone=?, skills=?, bio=?, education=?, experience=?, address=? WHERE user_id=?', (name, phone, fields['skills'], fields['bio'], fields['education'], fields['experience'], fields['address'], uid))
                conn.execute('UPDATE volunteer_profiles SET bio=?, date_of_birth=?, address=?, education=?, experience=?, skills=?, availability=?, emergency_contact=? WHERE user_id=?', (fields['bio'], fields['date_of_birth'], fields['address'], fields['education'], fields['experience'], fields['skills'], fields['availability'], fields['emergency_contact'], uid))
            elif role == 'Organizer':
                org_name = fields['organization_name'] or name + 's Events'
                conn.execute('UPDATE organizer_profiles SET organization_name=?, bio=?, website=?, address=? WHERE user_id=?', (org_name, fields['bio'], fields['website'], fields['address'], uid))
                conn.execute('UPDATE organizers SET organization_name=?, contact_person=?, phone=?, address=? WHERE user_id=?', (org_name, name, phone, fields['address'], uid))
            conn.commit()
            session['name'] = name
            flash('Your profile has been updated.', 'success')
            return redirect(url_for('edit_profile'))
        profile = conn.execute('SELECT * FROM user_profiles WHERE user_id=?', (uid,)).fetchone()
        return render_template('profile.html', user=user, profile=profile)
    finally:
        conn.close()

# Self-service account and role-specific portal routes.
@app.route('/register', methods=['GET', 'POST'])
@app.route('/register', methods=['GET', 'POST'])
@app.route('/signup', methods=['GET', 'POST'])
def self_register():
    if request.method == 'POST':
        d=request.form; name=d.get('name','').strip(); email=d.get('email','').strip().lower(); phone=d.get('phone','').strip(); password=d.get('password',''); role_name='Participant'
        if not name or not email or len(password)<8:
            flash('Name and email are required; password must be at least 8 characters.','danger'); return redirect(url_for('self_register'))
        conn=db()
        try:
            role=conn.execute('SELECT role_id FROM roles WHERE name=?',(role_name,)).fetchone()
            verified = 0
            uid=conn.execute('INSERT INTO users(name,email,phone,password_hash,role_id,email_verified) VALUES (?,?,?,?,?,?)',(name,email,phone,generate_password_hash(password),role['role_id'],verified)).lastrowid
            conn.execute('INSERT INTO user_profiles(user_id,bio,date_of_birth,address,college,department,organization_name,website,education,experience,skills,availability,emergency_contact) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',(uid,d.get('bio'),d.get('date_of_birth'),d.get('address'),d.get('college'),d.get('department'),d.get('organization_name'),d.get('website'),d.get('education'),d.get('experience'),d.get('skills'),d.get('availability'),d.get('emergency_contact')))
            if role_name=='Organizer':
                org_name=d.get('organization_name','').strip() or name+"'s Events"
                conn.execute('INSERT INTO organizer_profiles(user_id,organization_name,bio,website,address) VALUES (?,?,?,?,?)',(uid,org_name,d.get('bio'),d.get('website'),d.get('address')))
                conn.execute('INSERT INTO organizers(user_id,organization_name,contact_person,phone,email,address,approval_status) VALUES (?,?,?,?,?,?,?)',(uid,org_name,name,phone,email,d.get('address'),'Pending'))
            elif role_name=='Volunteer':
                conn.execute('INSERT INTO volunteers(user_id,name,phone,email,skills,availability_status,status,bio,education,experience,address) VALUES (?,?,?,?,?,?,?,?,?,?,?)',(uid,name,phone,email,d.get('skills'),'Available','Active',d.get('bio'),d.get('education'),d.get('experience'),d.get('address')))
                conn.execute('INSERT INTO volunteer_profiles(user_id,bio,date_of_birth,address,education,experience,skills,availability,emergency_contact) VALUES (?,?,?,?,?,?,?,?,?)',(uid,d.get('bio'),d.get('date_of_birth'),d.get('address'),d.get('education'),d.get('experience'),d.get('skills'),d.get('availability'),d.get('emergency_contact')))
            else:
                conn.execute('INSERT INTO participants(user_id,name,email,phone,dob,college_name,department,address) VALUES (?,?,?,?,?,?,?,?)',(uid,name,email,phone,d.get('date_of_birth'),d.get('college'),d.get('department'),d.get('address')))
                conn.execute('INSERT INTO participant_profiles(user_id,date_of_birth,college,department,address,emergency_contact) VALUES (?,?,?,?,?,?)',(uid,d.get('date_of_birth'),d.get('college'),d.get('department'),d.get('address'),d.get('emergency_contact')))
            conn.commit()
            if smtp_configured():
                try:
                    send_email_otp(uid,email)
                    flash('Account created. Check your email for a 6-digit verification code.', 'success')
                    return redirect(url_for('verify_email', email=email))
                except Exception as mail_error:
                    app.logger.exception('Registration OTP email delivery failed')
                    flash('Account created, but email delivery failed. Check SMTP settings and use Resend code.', 'warning')
                    return redirect(url_for('verify_email', email=email))
            flash('Email verification is required. Configure SMTP in your private .env before creating an account.', 'danger')
            return redirect(url_for('verify_email', email=email))
        except sqlite3.IntegrityError:
            conn.rollback(); flash('That email address is already registered.','danger')
        except Exception as exc:
            conn.rollback(); flash('Could not create account: '+str(exc),'danger')
        finally: conn.close()
    return render_template('register.html')

@app.route('/auth/google')
def google_login():
    requested_role = request.args.get('role', 'Participant')
    session['oauth_signup_role'] = requested_role if requested_role in ('Organizer', 'Volunteer', 'Participant') else 'Participant'
    if not oauth or not GOOGLE_CLIENT_SECRET:
        flash('Google sign-in is not configured yet. Set GOOGLE_CLIENT_SECRET in your .env file; the Client ID is already configured.', 'warning')
        return redirect(url_for('login'))
    redirect_uri = GOOGLE_REDIRECT_URI or url_for('google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    if not oauth or not GOOGLE_CLIENT_SECRET:
        flash('Google sign-in is not configured.', 'warning'); return redirect(url_for('login'))
    try:
        token = oauth.google.authorize_access_token()
        info = token.get('userinfo') or oauth.google.userinfo()
        email = (info.get('email') or '').strip().lower()
        if not email or not info.get('email_verified'):
            flash('Google did not return a verified email address.', 'danger'); return redirect(url_for('login'))
        conn=db()
        try:
            user=conn.execute('SELECT u.*,r.name role_name FROM users u JOIN roles r ON r.role_id=u.role_id WHERE lower(u.email)=?',(email,)).fetchone()
            if not user:
                chosen_role = session.pop('oauth_signup_role', 'Participant')
                role=conn.execute('SELECT role_id FROM roles WHERE name=?',(chosen_role,)).fetchone()
                display_name = info.get('name') or email.split('@')[0]
                uid=conn.execute('INSERT INTO users(name,email,password_hash,role_id,email_verified) VALUES (?,?,?,?,1)',(display_name,email,generate_password_hash(secrets.token_urlsafe(32)),role['role_id'])).lastrowid
                conn.execute('INSERT INTO user_profiles(user_id) VALUES (?)',(uid,))
                if chosen_role == 'Organizer':
                    conn.execute('INSERT INTO organizer_profiles(user_id,organization_name) VALUES (?,?)',(uid,display_name+"'s Events"))
                    conn.execute('INSERT INTO organizers(user_id,organization_name,contact_person,phone,email,approval_status) VALUES (?,?,?,?,?,?)',(uid,display_name+"'s Events",display_name,'',email,'Pending'))
                elif chosen_role == 'Volunteer':
                    conn.execute('INSERT INTO volunteers(user_id,name,phone,email,skills,availability_status,status) VALUES (?,?,?,?,?,?,?)',(uid,display_name,'',email,'','Available','Active'))
                    conn.execute('INSERT INTO volunteer_profiles(user_id) VALUES (?)',(uid,))
                else:
                    conn.execute('INSERT INTO participants(user_id,name,email,phone) VALUES (?,?,?,?)',(uid,display_name,email,''))
                    conn.execute('INSERT INTO participant_profiles(user_id) VALUES (?)',(uid,))
                conn.commit(); user=conn.execute('SELECT u.*,r.name role_name FROM users u JOIN roles r ON r.role_id=u.role_id WHERE u.user_id=?',(uid,)).fetchone()
            else:
                session.pop('oauth_signup_role', None)
            session.clear(); session.update(user_id=user['user_id'],name=user['name'],role=user['role_name'],email=user['email'])
            audit('GOOGLE_LOGIN','User',user['user_id'],'Google OAuth login')
            return redirect(url_for('portal') if user['role_name'] in ('Organizer','Volunteer','Participant') else url_for('dashboard'))
        finally: conn.close()
    except Exception as exc:
        app.logger.exception('Google OAuth callback failed')
        flash('Google sign-in failed. Check OAuth client secret and the authorized redirect URI. Details: '+str(exc), 'danger')
        return redirect(url_for('login'))

@app.route('/verify-email', methods=['GET','POST'])
def verify_email():
    email=request.values.get('email','').strip().lower()
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); code=(request.form.get('code') or request.form.get('otp') or '').strip()
        user=query('SELECT user_id,email_verified FROM users WHERE lower(email)=?',(email,),one=True)
        if not user: flash('No account found for that email.','danger')
        elif user['email_verified']: flash('This email is already verified. Please sign in.','success'); return redirect(url_for('login'))
        else:
            otp=query('SELECT * FROM email_otps WHERE user_id=? AND used_at IS NULL ORDER BY otp_id DESC LIMIT 1',(user['user_id'],),one=True)
            if not otp or datetime.fromisoformat(otp['expires_at']) < datetime.utcnow() or not check_password_hash(otp['code_hash'],code):
                flash('The code is invalid or expired. Request a new code.', 'danger')
            else:
                execute('UPDATE email_otps SET used_at=? WHERE otp_id=?',(datetime.utcnow().isoformat(),otp['otp_id']))
                execute('UPDATE users SET email_verified=1 WHERE user_id=?',(user['user_id'],))
                flash('Email verified. You can now sign in.','success'); return redirect(url_for('login'))
    return render_template('verify_email.html',email=email)

@app.route('/verify-email/resend', methods=['POST'])
def resend_email_otp():
    email=request.form.get('email') or request.args.get('email',''); email=email.strip().lower(); user=query('SELECT user_id,email_verified FROM users WHERE lower(email)=?',(email,),one=True)
    if not smtp_configured(): flash('SMTP is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD and SMTP_FROM in .env.', 'warning')
    elif not user: flash('No account found for that email.', 'danger')
    elif user['email_verified']: flash('Email already verified. Please sign in.', 'success')
    else:
        try: send_email_otp(user['user_id'],email); flash('A new verification code was sent.', 'success')
        except Exception:
            app.logger.exception('Resending verification OTP failed')
            flash('Email delivery failed. Check SMTP settings and try again later.', 'danger')
    return redirect(url_for('verify_email',email=email))

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        user = query('SELECT user_id,email_verified FROM users WHERE lower(email)=?', (email,), one=True)
        if not user:
            flash('If that account exists, a reset code can be sent to its email.', 'info')
            return redirect(url_for('forgot_password'))
        if not user['email_verified']:
            flash('Verify your email before resetting your password.', 'warning')
            return redirect(url_for('verify_email', email=email))
        if not smtp_configured():
            flash('Password reset email is unavailable. Configure SMTP in your private .env.', 'danger')
            return redirect(url_for('forgot_password'))
        code = f'{secrets.randbelow(1000000):06d}'
        try:
            if not send_email(email, 'EFMS password reset code', f'Your EFMS password reset code is {code}. It expires in 10 minutes.'):
                raise RuntimeError('SMTP is not configured.')
            execute('UPDATE password_reset_otps SET used_at=? WHERE user_id=? AND used_at IS NULL', (datetime.utcnow().isoformat(), user['user_id']))
            execute('INSERT INTO password_reset_otps(user_id,code_hash,expires_at) VALUES (?,?,?)', (user['user_id'], generate_password_hash(code), (datetime.utcnow()+timedelta(minutes=10)).isoformat()))
            flash('A password reset code has been sent to your email.', 'success')
            return redirect(url_for('reset_password', email=email))
        except Exception:
            app.logger.exception('Password reset email failed')
            flash('Could not send the reset code. Check your email configuration.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET','POST'])
def reset_password():
    email = (request.values.get('email') or '').strip().lower()
    if request.method == 'POST':
        code = request.form.get('code','').strip(); password = request.form.get('password','')
        user = query('SELECT user_id FROM users WHERE lower(email)=?', (email,), one=True)
        otp = query('SELECT * FROM password_reset_otps WHERE user_id=? AND used_at IS NULL ORDER BY reset_id DESC LIMIT 1', (user['user_id'],), one=True) if user else None
        if not user or not otp or datetime.fromisoformat(otp['expires_at']) < datetime.utcnow() or not check_password_hash(otp['code_hash'], code):
            flash('The reset code is invalid or expired.', 'danger')
        elif len(password) < 8:
            flash('Choose a password with at least 8 characters.', 'danger')
        else:
            execute('UPDATE users SET password_hash=? WHERE user_id=?', (generate_password_hash(password), user['user_id']))
            execute('UPDATE password_reset_otps SET used_at=? WHERE reset_id=?', (datetime.utcnow().isoformat(), otp['reset_id']))
            flash('Password updated. You can now sign in.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', email=email)

@app.route('/browse-events')
def browse_events():
    category=request.args.get('category','').strip(); search=request.args.get('q','').strip()
    sql="""SELECT e.*,ec.name category_name,f.festival_name,s.event_date,s.start_time,s.end_time,v.venue_name,v.location venue_location,(SELECT MIN(price) FROM ticket_types tt WHERE tt.event_id=e.event_id) min_price,(SELECT ticket_type_id FROM ticket_types tx WHERE tx.event_id=e.event_id ORDER BY price LIMIT 1) ticket_type_id FROM events e JOIN event_categories ec ON ec.category_id=e.category_id JOIN festivals f ON f.festival_id=e.festival_id LEFT JOIN event_schedules s ON s.event_id=e.event_id LEFT JOIN venues v ON v.venue_id=s.venue_id WHERE e.status='Published'"""
    params=[]
    if category: sql+=' AND ec.name=?'; params.append(category)
    if search: sql+=" AND (e.event_name LIKE ? OR e.description LIKE ? OR COALESCE(e.location,v.location,'') LIKE ?)"; params.extend(['%'+search+'%']*3)
    sql+=' ORDER BY s.event_date,e.event_name'
    return render_template('browse_events.html',events=query(sql,params),categories=query('SELECT name FROM event_categories ORDER BY name'))

@app.route('/portal')
@login_required
def portal():
    role=session.get('role'); uid=session['user_id']
    if role in ('Organizer','Admin'):
        events=query("""SELECT e.*,ec.name category_name,s.event_date,s.start_time,s.end_time,v.venue_name,(SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.event_id AND r.status!='Cancelled') participant_count,(SELECT COALESCE(SUM(p.amount),0) FROM payments p JOIN registrations r ON r.registration_id=p.registration_id WHERE r.event_id=e.event_id AND p.status='Success') revenue FROM events e JOIN event_categories ec ON ec.category_id=e.category_id LEFT JOIN event_schedules s ON s.event_id=e.event_id LEFT JOIN venues v ON v.venue_id=s.venue_id WHERE e.organizer_user_id=? OR ?='Admin' ORDER BY e.created_at DESC""",(uid,role))
        participants=query("""SELECT u.name,u.email,u.phone,e.event_name,r.registration_date,r.payment_status,r.amount_paid,t.ticket_no,t.ticket_id,t.status ticket_status,a.status attendance_status FROM registrations r JOIN participants p ON p.participant_id=r.participant_id JOIN users u ON u.user_id=p.user_id JOIN events e ON e.event_id=r.event_id LEFT JOIN tickets t ON t.registration_id=r.registration_id LEFT JOIN ticket_checkins a ON a.ticket_id=t.ticket_id WHERE e.organizer_user_id=? OR ?='Admin' ORDER BY r.registration_date DESC""",(uid,role))
        applications=query("""SELECT va.*,u.name volunteer_name,u.email volunteer_email,v.phone,v.skills,v.bio,v.education,v.experience,e.event_name FROM volunteer_applications va JOIN volunteers v ON v.volunteer_id=va.volunteer_id JOIN users u ON u.user_id=v.user_id JOIN events e ON e.event_id=va.event_id WHERE e.organizer_user_id=? OR ?='Admin' ORDER BY va.applied_at DESC""",(uid,role))
        volunteers=query("SELECT u.user_id,u.name,u.email,u.phone,v.skills,v.bio,v.education,v.experience,v.availability_status FROM volunteers v JOIN users u ON u.user_id=v.user_id ORDER BY u.name")
        messages=query("SELECT m.*,u.name sender_name,e.event_name FROM direct_messages m JOIN users u ON u.user_id=m.sender_id LEFT JOIN events e ON e.event_id=m.event_id WHERE m.recipient_id=? OR m.sender_id=? ORDER BY m.sent_at DESC LIMIT 100",(uid,uid))
        festivals=query("SELECT festival_id,festival_name FROM festivals WHERE organizer_id IN (SELECT organizer_id FROM organizers WHERE user_id=?) OR ?='Admin' ORDER BY start_date DESC",(uid,role)); categories=query('SELECT * FROM event_categories ORDER BY name'); venues=query('SELECT * FROM venues ORDER BY venue_name'); zones=query('SELECT * FROM parking_zones ORDER BY zone_name')
        expenses=query("SELECT x.*,f.festival_name FROM budget_expenses x JOIN festivals f ON f.festival_id=x.festival_id WHERE f.organizer_id IN (SELECT organizer_id FROM organizers WHERE user_id=?) OR ?='Admin' ORDER BY x.expense_date DESC",(uid,role))
        inbox_people=query("SELECT user_id,name,email FROM users WHERE user_id<>? AND status='Active' ORDER BY name",(uid,))
        return render_template('portal.html',role=role,events=events,participants=participants,applications=applications,volunteers=volunteers,messages=messages,festivals=festivals,categories=categories,venues=venues,zones=zones,expenses=expenses,inbox_people=inbox_people)
    if role=='Volunteer':
        profile=query("SELECT v.*,u.email,vp.date_of_birth,vp.address,vp.education,vp.experience,vp.emergency_contact FROM volunteers v JOIN users u ON u.user_id=v.user_id LEFT JOIN volunteer_profiles vp ON vp.user_id=u.user_id WHERE u.user_id=?",(uid,),one=True)
        applications=query("SELECT va.*,e.event_name,e.description,e.location,e.winning_prize,s.event_date,s.start_time,v.venue_name FROM volunteer_applications va JOIN events e ON e.event_id=va.event_id LEFT JOIN event_schedules s ON s.event_id=e.event_id LEFT JOIN venues v ON v.venue_id=s.venue_id WHERE va.volunteer_id=(SELECT volunteer_id FROM volunteers WHERE user_id=?) ORDER BY va.applied_at DESC",(uid,))
        events=query("SELECT e.*,ec.name category_name,s.event_date,s.start_time,v.venue_name FROM events e JOIN event_categories ec ON ec.category_id=e.category_id LEFT JOIN event_schedules s ON s.event_id=e.event_id LEFT JOIN venues v ON v.venue_id=s.venue_id WHERE e.status='Published' AND e.event_id NOT IN (SELECT event_id FROM volunteer_applications WHERE volunteer_id=(SELECT volunteer_id FROM volunteers WHERE user_id=?)) ORDER BY s.event_date",(uid,))
        organizers=query("SELECT u.user_id,u.name,u.email FROM users u JOIN roles r ON r.role_id=u.role_id WHERE r.name IN ('Organizer','Admin') ORDER BY u.name")
        messages=query("SELECT m.*,u.name other_name,e.event_name FROM direct_messages m JOIN users u ON u.user_id=CASE WHEN m.sender_id=? THEN m.recipient_id ELSE m.sender_id END LEFT JOIN events e ON e.event_id=m.event_id WHERE m.sender_id=? OR m.recipient_id=? ORDER BY m.sent_at DESC",(uid,uid,uid))
        return render_template('portal.html',role=role,profile=profile,applications=applications,events=events,organizers=organizers,messages=messages)
    if role=='Participant':
        profile=query('SELECT p.*,u.email FROM participants p JOIN users u ON u.user_id=p.user_id WHERE u.user_id=?',(uid,),one=True)
        registrations=query("SELECT r.*,e.event_name,e.description,e.location,e.winning_prize,s.event_date,s.start_time,v.venue_name,t.ticket_id,t.ticket_no,t.status ticket_status,tt.type_name,tt.price FROM registrations r JOIN events e ON e.event_id=r.event_id LEFT JOIN event_schedules s ON s.event_id=e.event_id LEFT JOIN venues v ON v.venue_id=s.venue_id LEFT JOIN tickets t ON t.registration_id=r.registration_id LEFT JOIN ticket_types tt ON tt.ticket_type_id=t.ticket_type_id JOIN participants p ON p.participant_id=r.participant_id WHERE p.user_id=? ORDER BY r.registration_date DESC",(uid,))
        events=query("SELECT e.*,ec.name category_name,s.event_date,s.start_time,v.venue_name,v.location venue_location,(SELECT MIN(price) FROM ticket_types tt WHERE tt.event_id=e.event_id) min_price,(SELECT ticket_type_id FROM ticket_types tx WHERE tx.event_id=e.event_id ORDER BY price LIMIT 1) ticket_type_id FROM events e JOIN event_categories ec ON ec.category_id=e.category_id LEFT JOIN event_schedules s ON s.event_id=e.event_id LEFT JOIN venues v ON v.venue_id=s.venue_id WHERE e.status='Published' ORDER BY s.event_date")
        categories=query('SELECT * FROM event_categories ORDER BY name')
        return render_template('portal.html',role=role,profile=profile,registrations=registrations,events=events,categories=categories)
    return redirect(url_for('dashboard'))

@app.route('/portal/events/create',methods=['POST'])
@role_required('Organizer','Admin')
def portal_create_event():
    d=request.form; uid=session['user_id']; conn=db()
    try:
        name=d.get('event_name','').strip(); location=d.get('location','').strip(); description=d.get('description','').strip()
        if not name or not location or not description: raise ValueError('Event name, location and description are required.')
        org=conn.execute('SELECT organizer_id FROM organizers WHERE user_id=?',(uid,)).fetchone()
        if not org:
            org_id=conn.execute('INSERT INTO organizers(user_id,organization_name,contact_person,phone,email,approval_status) VALUES (?,?,?,?,?,?)',(uid,d.get('organization_name') or session.get('name'),session.get('name'),d.get('contact_phone'),session.get('email'),'Pending')).lastrowid
        else: org_id=org['organizer_id']
        if d.get('festival_id'):
            fid=int(d['festival_id'])
            if session.get('role')!='Admin' and not conn.execute('SELECT 1 FROM festivals WHERE festival_id=? AND organizer_id=?',(fid,org_id)).fetchone(): raise ValueError('Choose your own festival or create a new one by leaving the festival field blank.')
        else:
            fc=conn.execute('SELECT category_id FROM festival_categories ORDER BY category_id LIMIT 1').fetchone()
            fid=conn.execute('INSERT INTO festivals(festival_name,description,theme,start_date,end_date,location,category_id,organizer_id,status,budget) VALUES (?,?,?,?,?,?,?,?,?,?)',(d.get('festival_name') or name+' Festival',description,d.get('theme'),d['event_date'],d['event_date'],location,fc['category_id'],org_id,'Upcoming',float(d.get('event_budget') or 0))).lastrowid
        max_people=max(1,int(d.get('max_participants') or 100)); budget=max(0,float(d.get('event_budget') or 0)); start=d.get('start_time') or '09:00'; end=d.get('end_time') or '17:00'
        if start>=end: raise ValueError('End time must be after start time.')
        if d.get('venue_id'):
            venue=conn.execute('SELECT capacity FROM venues WHERE venue_id=?',(d['venue_id'],)).fetchone()
            if venue and max_people>venue['capacity']: raise ValueError('Participant capacity exceeds venue capacity.')
            if conn.execute('SELECT 1 FROM event_schedules WHERE venue_id=? AND event_date=? AND start_time<? AND end_time>?',(d['venue_id'],d['event_date'],end,start)).fetchone(): raise ValueError('Venue already booked for that time.')
        cid=int(d['category_id']); price=max(0,float(d.get('ticket_price') or 0))
        eid=conn.execute("INSERT INTO events(festival_id,category_id,event_name,description,rules,eligibility_criteria,max_participants,min_participants,registration_deadline,status,location,winning_prize,organizer_user_id,event_budget,payment_note,contact_email,contact_phone) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(fid,cid,name,description,d.get('rules'),d.get('eligibility_criteria'),max_people,int(d.get('min_participants') or 0),d.get('registration_deadline') or None,'Published',location,d.get('winning_prize'),uid,budget,d.get('payment_note'),session.get('email'),d.get('contact_phone'))).lastrowid
        if d.get('venue_id'): conn.execute('INSERT INTO event_schedules(event_id,venue_id,event_date,start_time,end_time,status) VALUES (?,?,?,?,?,?)',(eid,d['venue_id'],d['event_date'],start,end,'Scheduled'))
        conn.execute('INSERT INTO ticket_types(event_id,type_name,price,total_tickets,available_tickets,description) VALUES (?,?,?,?,?,?)',(eid,d.get('ticket_type') or 'General',price,max_people,max_people,d.get('ticket_description') or 'Standard ticket'))
        conn.execute('INSERT OR IGNORE INTO event_approvals(event_id,submitted_by,status,review_note) VALUES (?,?,?,?)',(eid,uid,'Approved','Self-service portal listing'))
        conn.commit(); audit('CREATE','Event',eid,name); flash('Event published. Payment collection is currently simulated for this academic prototype.','success')
    except Exception as exc: conn.rollback(); flash(str(exc),'danger')
    finally: conn.close()
    return redirect(url_for('portal'))

@app.route('/portal/register/<int:event_id>',methods=['POST'])
@role_required('Participant')
def portal_register_event(event_id):
    d=request.form; uid=session['user_id']; conn=db()
    try:
        part=conn.execute('SELECT participant_id FROM participants WHERE user_id=?',(uid,)).fetchone(); event=conn.execute("SELECT * FROM events WHERE event_id=? AND status='Published'",(event_id,)).fetchone()
        if not part or not event: raise ValueError('Participant profile or published event not found.')
        if event['registration_deadline'] and event['registration_deadline']<datetime.now().strftime('%Y-%m-%d'): raise ValueError('Registration deadline has passed.')
        tt=conn.execute('SELECT * FROM ticket_types WHERE ticket_type_id=? AND event_id=?',(d.get('ticket_type_id'),event_id)).fetchone()
        if not tt: raise ValueError('Invalid ticket type.')
        qty=max(1,min(10,int(d.get('quantity') or 1)))
        if tt['available_tickets']<qty: raise ValueError('Not enough tickets remain.')
        count=conn.execute("SELECT COUNT(*) c FROM registrations WHERE event_id=? AND status!='Cancelled'",(event_id,)).fetchone()['c']
        if event['max_participants'] and count+qty>event['max_participants']: raise ValueError('Event capacity is full.')
        if conn.execute("SELECT 1 FROM registrations WHERE participant_id=? AND event_id=? AND status!='Cancelled'",(part['participant_id'],event_id)).fetchone(): raise ValueError('You are already registered for this event.')
        method_name=(d.get('payment_method') or 'Demo').strip()
        if method_name.lower() == 'razorpay':
            if float(tt['price']) <= 0: raise ValueError('This event has a free ticket price. Choose Demo payment to issue a no-charge ticket.')
            if not (razorpay and RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET): raise ValueError('Razorpay is not configured. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to .env, or choose Demo payment for local testing.')
            amount=round(float(tt['price'])*qty,2)
            reg=conn.execute('INSERT INTO registrations(participant_id,event_id,registration_date,status,payment_status,amount_paid) VALUES (?,?,?,?,?,?)',(part['participant_id'],event_id,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'Pending','Pending',0)).lastrowid
            codes=[]
            for i in range(qty):
                code='EFMS-'+secrets.token_hex(16).upper(); codes.append(code)
                conn.execute("INSERT INTO tickets(registration_id,ticket_type_id,quantity,unit_price,total_price,final_amount,ticket_no,qr_code,status) VALUES (?,?,?,?,?,?,?,?,?)",(reg,tt['ticket_type_id'],1,tt['price'],tt['price'],tt['price'],code,code,'Pending'))
            client=razorpay.Client(auth=(RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET))
            order=client.order.create(data={'amount':int(round(amount*100)),'currency':'INR','receipt':f'EFMS-{reg}','notes':{'registration_id':str(reg),'event_id':str(event_id)}})
            method=conn.execute("SELECT method_id FROM payment_methods WHERE lower(method_name)='razorpay' LIMIT 1").fetchone()
            conn.execute('INSERT INTO payments(registration_id,amount,payment_method_id,transaction_id,payment_date,status) VALUES (?,?,?,?,?,?)',(reg,amount,method['method_id'] if method else None,order['id'],datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'Pending'))
            conn.execute('UPDATE ticket_types SET available_tickets=available_tickets-? WHERE ticket_type_id=?',(qty,tt['ticket_type_id']))
            conn.commit()
            return render_template('razorpay_checkout.html',key_id=RAZORPAY_KEY_ID,order_id=order['id'],amount=int(round(amount*100)),currency='INR',registration_id=reg,event_name=event['event_name'],email=session.get('email'),name=session.get('name'),phone=query('SELECT phone FROM users WHERE user_id=?',(uid,),one=True)['phone'] or '')
        if d.get('confirm_demo_payment') != 'yes': raise ValueError('For demo checkout, tick the demo-payment confirmation. No real money is charged.')
        reg=conn.execute('INSERT INTO registrations(participant_id,event_id,registration_date,status,payment_status,amount_paid) VALUES (?,?,?,?,?,?)',(part['participant_id'],event_id,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'Approved','Pending',0)).lastrowid
        codes=[]
        for i in range(qty):
            code='EFMS-'+secrets.token_hex(16).upper(); codes.append(code)
            conn.execute('INSERT INTO tickets(registration_id,ticket_type_id,quantity,unit_price,total_price,final_amount,ticket_no,qr_code,status) VALUES (?,?,?,?,?,?,?,?,?)',(reg,tt['ticket_type_id'],1,tt['price'],tt['price'],tt['price'],code,code,'Active'))
        amount=tt['price']*qty; method=conn.execute('SELECT method_id FROM payment_methods WHERE lower(method_name)=?',(method_name.lower(),)).fetchone()
        if not method: method=conn.execute("SELECT method_id FROM payment_methods WHERE lower(method_name)='demo' LIMIT 1").fetchone()
        demo_reference='DEMO-'+secrets.token_hex(8).upper()
        conn.execute('INSERT INTO payments(registration_id,amount,payment_method_id,transaction_id,payment_date,status) VALUES (?,?,?,?,?,?)',(reg,amount,method['method_id'] if method else None,demo_reference,datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'Demo'))
        conn.execute("UPDATE registrations SET payment_status='Paid',amount_paid=? WHERE registration_id=?",(amount,reg))
        conn.execute('UPDATE ticket_types SET available_tickets=available_tickets-? WHERE ticket_type_id=?',(qty,tt['ticket_type_id']))
        conn.commit(); audit('REGISTER','Event',event_id,'participant='+str(uid)+'; demo payment')
        email_row=conn.execute('SELECT email,name FROM users WHERE user_id=?',(uid,)).fetchone()
        email_sent=False
        if smtp_configured():
            try: email_sent=send_email(email_row['email'],'EFMS demo ticket confirmation: '+event['event_name'],f"Hello {email_row['name']},\n\nThis is a DEMO ticket confirmation for {event['event_name']}. No real money was charged. Demo reference: {demo_reference}. Ticket IDs:\n"+'\n'.join(codes)+'\n\nSign in to EFMS to download your QR codes.')
            except Exception: app.logger.exception('Demo ticket email failed')
        issued_tickets=query('SELECT ticket_id,ticket_no FROM tickets WHERE registration_id=? ORDER BY ticket_id',(reg,))
        return render_template('demo_payment_success.html',event_name=event['event_name'],registration_id=reg,amount=amount,reference=demo_reference,tickets=issued_tickets,email_sent=email_sent,email_configured=smtp_configured())
    except Exception as exc:
        conn.rollback(); flash(str(exc),'danger')
    finally: conn.close()
    return redirect(url_for('portal'))

@app.route('/payments/razorpay/verify',methods=['POST'])
@role_required('Participant')
def razorpay_verify():
    if not (razorpay and RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET): return jsonify(ok=False,error='Razorpay is not configured.'),400
    data=request.get_json(silent=True) or request.form
    order_id=data.get('razorpay_order_id',''); payment_id=data.get('razorpay_payment_id',''); signature=data.get('razorpay_signature','')
    if not all((order_id,payment_id,signature)): return jsonify(ok=False,error='Missing Razorpay verification fields.'),400
    conn=db()
    try:
        row=conn.execute('SELECT p.payment_id,p.registration_id,p.amount,p.status,r.participant_id,u.email,u.name,e.event_name FROM payments p JOIN registrations r ON r.registration_id=p.registration_id JOIN participants pt ON pt.participant_id=r.participant_id JOIN users u ON u.user_id=pt.user_id JOIN events e ON e.event_id=r.event_id WHERE p.transaction_id=? AND u.user_id=?',(order_id,session['user_id'])).fetchone()
        if not row: return jsonify(ok=False,error='Order not found for this account.'),404
        client=razorpay.Client(auth=(RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET))
        client.utility.verify_payment_signature({'razorpay_order_id':order_id,'razorpay_payment_id':payment_id,'razorpay_signature':signature})
        payment_details=client.payment.fetch(payment_id)
        if payment_details.get('status') != 'captured':
            return jsonify(ok=False,error='Razorpay has not marked this payment as captured yet. Ticket remains pending.'),409
        email_sent=False
        if row['status']!='Success':
            conn.execute("UPDATE payments SET status='Success',gateway_payment_id=? WHERE payment_id=?",(payment_id,row['payment_id']))
            conn.execute("UPDATE registrations SET payment_status='Paid',status='Approved',amount_paid=? WHERE registration_id=?",(row['amount'],row['registration_id']))
            conn.execute("UPDATE tickets SET status='Active' WHERE registration_id=?",(row['registration_id'],))
            conn.commit()
            tickets=conn.execute('SELECT ticket_no FROM tickets WHERE registration_id=?',(row['registration_id'],)).fetchall()
            body=f"Hello {row['name']},\n\nYour payment for {row['event_name']} was verified. Your EFMS ticket IDs are:\n"+'\n'.join(t['ticket_no'] for t in tickets)+'\n\nSign in to EFMS to download the QR codes.'
            try: email_sent=send_email(row['email'],f'EFMS ticket confirmation: {row["event_name"]}',body)
            except Exception: app.logger.exception('Ticket confirmation email failed'); email_sent=False
            audit('PAYMENT_SUCCESS','Registration',row['registration_id'],'Razorpay signature verified; email_sent='+str(email_sent))
        return jsonify(ok=True,redirect=url_for('portal'),email_sent=email_sent)
    except Exception as exc:
        conn.rollback(); app.logger.exception('Razorpay payment verification failed')
        return jsonify(ok=False,error='Payment signature verification failed. '+str(exc)),400
    finally: conn.close()

@app.route('/portal/volunteer/apply/<int:event_id>',methods=['POST'])
@login_required
def volunteer_apply(event_id):
    conn=db()
    try:
        vol=conn.execute('SELECT volunteer_id FROM volunteers WHERE user_id=?',(session['user_id'],)).fetchone()
        if not vol:
            u=conn.execute('SELECT name,email,phone FROM users WHERE user_id=?',(session['user_id'],)).fetchone()
            conn.execute('INSERT INTO volunteers(user_id,name,phone,email,availability_status,status) VALUES (?,?,?,?,?,?)',(session['user_id'],u['name'],u['phone'],u['email'],'Available','Active'))
            vol=conn.execute('SELECT volunteer_id FROM volunteers WHERE user_id=?',(session['user_id'],)).fetchone()
        event=conn.execute("SELECT event_id,organizer_user_id FROM events WHERE event_id=? AND status='Published'",(event_id,)).fetchone()
        if not event: raise ValueError('Published event not found.')
        if event['organizer_user_id'] == session['user_id']: raise ValueError('An event host cannot volunteer for their own event.')
        conn.execute('INSERT INTO volunteer_applications(volunteer_id,event_id,message,status) VALUES (?,?,?,?)',(vol['volunteer_id'],event_id,request.form.get('message'),'Pending')); conn.commit(); flash('Application sent to the organizer.','success')
    except sqlite3.IntegrityError: conn.rollback(); flash('You already applied for this event.','warning')
    except Exception as exc: conn.rollback(); flash(str(exc),'danger')
    finally: conn.close()
    return redirect(url_for('portal'))

@app.route('/portal/volunteer/application/<int:application_id>/<decision>',methods=['POST'])
@role_required('Organizer','Admin')
def review_volunteer_application(application_id,decision):
    if decision not in ('Accepted','Rejected'): abort(400)
    conn=db()
    try:
        row=conn.execute('SELECT va.*,e.organizer_user_id FROM volunteer_applications va JOIN events e ON e.event_id=va.event_id WHERE va.application_id=?',(application_id,)).fetchone()
        if not row: abort(404)
        if session.get('role')!='Admin' and row['organizer_user_id']!=session['user_id']: abort(403)
        conn.execute('UPDATE volunteer_applications SET status=?,reviewed_by=?,review_note=? WHERE application_id=?',(decision,session['user_id'],request.form.get('review_note'),application_id))
        if decision=='Accepted': conn.execute('INSERT OR IGNORE INTO volunteer_assignments(volunteer_id,event_id,role,duty_description,status) VALUES (?,?,?,?,?)',(row['volunteer_id'],row['event_id'],request.form.get('duty') or 'Event Volunteer',request.form.get('duty_description') or 'Assigned by organizer','Assigned'))
        conn.commit(); flash('Volunteer application '+decision.lower()+'.','success')
    except Exception as exc: conn.rollback(); flash(str(exc),'danger')
    finally: conn.close()
    return redirect(url_for('portal'))

@app.route('/portal/message',methods=['POST'])
@login_required
def send_direct_message():
    d=request.form; recipient=d.get('recipient_id','').strip(); subject=d.get('subject','').strip(); body=d.get('body','').strip()
    if not recipient or not subject or not body: flash('Recipient, subject and message are required.','danger'); return redirect(url_for('portal'))
    if int(recipient)==session['user_id']: flash('You cannot message your own account.','danger'); return redirect(url_for('portal'))
    try: execute('INSERT INTO direct_messages(sender_id,recipient_id,event_id,subject,body) VALUES (?,?,?,?,?)',(session['user_id'],int(recipient),d.get('event_id') or None,subject,body)); flash('Message saved to EFMS inbox. External email/SMS delivery is not configured.','success')
    except Exception as exc: flash('Could not send message: '+str(exc),'danger')
    return redirect(url_for('portal'))

@app.route('/portal/parking/create',methods=['POST'])
@role_required('Organizer','Admin')
def portal_create_parking():
    d=request.form
    try: execute('INSERT INTO parking_zones(zone_name,location,vehicle_type,capacity,accessible_spaces,status,notes) VALUES (?,?,?,?,?,?,?)',(d['zone_name'],d['location'],d.get('vehicle_type') or 'Any',max(0,int(d.get('capacity') or 0)),max(0,int(d.get('accessible_spaces') or 0)),d.get('status') or 'Open',d.get('notes'))); flash('Parking zone saved.','success')
    except Exception as exc: flash('Could not save parking zone: '+str(exc),'danger')
    return redirect(url_for('portal'))

@app.route('/portal/expense/create',methods=['POST'])
@role_required('Organizer','Admin')
def portal_create_expense():
    d=request.form; conn=db()
    try:
        fid=int(d['festival_id'])
        if session.get('role')!='Admin' and not conn.execute('SELECT 1 FROM festivals f JOIN organizers o ON o.organizer_id=f.organizer_id WHERE f.festival_id=? AND o.user_id=?',(fid,session['user_id'])).fetchone(): raise ValueError('You can only record expenses for your own festival.')
        amount=float(d['amount'])
        if amount<0: raise ValueError('Amount cannot be negative.')
        conn.execute('INSERT INTO budget_expenses(festival_id,category,description,amount,expense_date,vendor,recorded_by,status) VALUES (?,?,?,?,?,?,?,?)',(fid,d['category'],d['description'],amount,d.get('expense_date') or datetime.now().strftime('%Y-%m-%d'),d.get('vendor'),session['user_id'],'Approved')); conn.commit(); flash('Expense recorded.','success')
    except Exception as exc: conn.rollback(); flash(str(exc),'danger')
    finally: conn.close()
    return redirect(url_for('portal'))


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Page not found.'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, message='Unexpected server error.'), 500



# Initialize database when the application starts,
# including when launched through Gunicorn on Render.
init_db()
print('EFMS database ready:', DB_PATH)

if __name__ == '__main__':
    app.run(
        debug=DEBUG,
        host='0.0.0.0',
        port=int(os.getenv('PORT', '5000'))
    )


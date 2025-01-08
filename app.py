from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import mysql.connector
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from requests_oauthlib import OAuth2Session
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'default_secret_key_for_development')

# Add these configurations after app creation
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID', '')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET', '')
GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_CALLBACK_URL = os.environ.get('GITHUB_CALLBACK_URL', 'http://localhost:5000/github-callback')

# Add database configuration
DB_CONFIG = {
    'host': 'sql12.freesqldatabase.com',
    'database': 'sql12756481',
    'user': 'sql12756481',
    'password': 'IYiqPGzplj',
    'port': 3306
}

# Modify the database connection function
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Modify init_db function
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table with new columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            whatsapp_number VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL CHECK(role IN ('Developer', 'Founder')),
            cv_link TEXT,
            github_token TEXT
        )
    ''')
    
    # Create projects table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS projects (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) UNIQUE NOT NULL,
            description TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            founder_name VARCHAR(255) NOT NULL,
            is_completed BOOLEAN DEFAULT FALSE,
            FOREIGN KEY (founder_name) REFERENCES users (username)
        )
    ''')
    
    # Create project_applications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS project_applications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            project_id INT NOT NULL,
            user_id INT NOT NULL,
            status VARCHAR(50) DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (project_id) REFERENCES projects (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(project_id, user_id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Routes
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)  # Use dictionary cursor for named columns
        cursor.execute('SELECT * FROM users WHERE email = %s AND password = %s', (email, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f"Welcome back, {user['username']}!", "success")
            if user['role'] == 'Developer':
                return redirect(url_for('developer_dashboard'))
            return redirect(url_for('founder_dashboard'))  
        else:
            flash("Invalid email or password.", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        whatsapp_number = request.form['whatsapp_number']
        role = request.form['role']

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password, whatsapp_number, role) VALUES (%s, %s, %s, %s, %s)',
                           (username, email, password, whatsapp_number, role))
            conn.commit()
            conn.close()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash("Username or email already exists.", "danger")
    return render_template('register.html')

@app.route('/developer-dashboard')
def developer_dashboard():
    if 'user_id' not in session or session.get('role') != 'Developer':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if developer is authorized (has both CV and GitHub)
    cursor.execute('''
        SELECT cv_link, github_token 
        FROM users 
        WHERE id = %s
    ''', (session['user_id'],))
    user_auth = cursor.fetchone()
    is_authorized = user_auth[0] is not None and user_auth[1] is not None
    
    # Get active projects
    cursor.execute('''
        SELECT p.title, p.description, p.founder_name, p.created_at, p.id
        FROM projects p
        WHERE (p.is_completed = FALSE OR p.is_completed IS NULL)
        ORDER BY p.created_at DESC
    ''')
    active_projects = cursor.fetchall()
    
    # Get selected projects (where developer was accepted)
    cursor.execute('''
        SELECT 
            p.title, 
            p.description, 
            p.founder_name, 
            p.created_at, 
            p.id,
            u.email as founder_email,
            u.whatsapp_number as founder_whatsapp
        FROM projects p
        JOIN project_applications pa ON p.id = pa.project_id
        JOIN users u ON p.founder_name = u.username
        WHERE pa.user_id = %s 
        AND pa.status = 'accepted'
        AND p.is_completed = TRUE
        ORDER BY p.created_at DESC
    ''', (session['user_id'],))
    selected_projects = cursor.fetchall()
    
    # Get projects that the developer has already applied to
    cursor.execute('''
        SELECT project_id 
        FROM project_applications 
        WHERE user_id = %s
    ''', (session['user_id'],))
    applied_projects = {row[0] for row in cursor.fetchall()}
    
    conn.close()
    
    return render_template(
        'developer_dashboard.html',
        username=session['username'],
        active_projects=active_projects,
        selected_projects=selected_projects,
        applied_projects=applied_projects,
        is_authorized=is_authorized
    )

@app.route('/apply-project/<int:project_id>', methods=['POST'])
def apply_project(project_id):
    if 'user_id' not in session or session.get('role') != 'Developer':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO project_applications (project_id, user_id)
            VALUES (%s, %s)
        ''', (project_id, session['user_id']))
        conn.commit()
        flash("Successfully applied to the project!", "success")
    except mysql.connector.IntegrityError:
        flash("You have already applied to this project.", "danger")
    
    conn.close()
    return redirect(url_for('developer_dashboard'))

@app.route('/founder-dashboard')
def founder_dashboard():
    if 'user_id' not in session or session.get('role') != 'Founder':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get all projects, ordered by status (active first) and then by creation date
    cursor.execute('''
        SELECT id, title, description, created_at, is_completed 
        FROM projects 
        WHERE founder_name = %s
        ORDER BY 
            is_completed ASC,  -- False (0) comes before True (1)
            created_at DESC    -- Most recent first within each group
    ''', (session['username'],))
    projects = cursor.fetchall()
    
    # Get application statistics for each project
    project_stats = {}
    for project in projects:
        cursor.execute('''
            SELECT COUNT(*), 
                   SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as accepted
            FROM project_applications 
            WHERE project_id = %s
        ''', (project[0],))
        stats = cursor.fetchone()
        project_stats[project[0]] = {
            'total_applications': stats[0] or 0,
            'accepted_developer': stats[1] or 0
        }

    conn.close()

    return render_template(
        'founder_dashboard.html',
        username=session['username'],
        projects=projects,
        project_stats=project_stats
    )

@app.route('/create-project', methods=['GET', 'POST'])
def create_project():
    if 'user_id' not in session or session.get('role') != 'Founder':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO projects (title, description, founder_name)
            VALUES (%s, %s, %s)
        ''', (title, description, session['username']))
        conn.commit()
        conn.close()
        
        flash("Project created successfully!", "success")
        return redirect(url_for('founder_dashboard'))
        
    return render_template('create_project.html')

@app.route('/edit-project/<int:project_id>', methods=['GET', 'POST'])
def edit_project(project_id):
    if 'user_id' not in session or session.get('role') != 'Founder':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify project ownership
    cursor.execute('SELECT * FROM projects WHERE id = %s AND founder_name = %s', 
                  (project_id, session['username']))
    project = cursor.fetchone()
    
    if not project:
        flash("Project not found or unauthorized.", "danger")
        return redirect(url_for('founder_dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        cursor.execute('''
            UPDATE projects 
            SET title = %s, description = %s 
            WHERE id = %s AND founder_name = %s
        ''', (title, description, project_id, session['username']))
        conn.commit()
        flash("Project updated successfully!", "success")
        return redirect(url_for('founder_dashboard'))

    conn.close()
    return render_template('edit_project.html', project=project)

@app.route('/delete-project/<int:project_id>', methods=['POST'])
def delete_project(project_id):
    if 'user_id' not in session or session.get('role') != 'Founder':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify project ownership
    cursor.execute('SELECT * FROM projects WHERE id = %s AND founder_name = %s', 
                  (project_id, session['username']))
    project = cursor.fetchone()
    
    if not project:
        flash("Project not found or unauthorized.", "danger")
    else:
        # Delete associated applications first
        cursor.execute('DELETE FROM project_applications WHERE project_id = %s', 
                      (project_id,))
        # Delete the project
        cursor.execute('DELETE FROM projects WHERE id = %s', (project_id,))
        conn.commit()
        flash("Project deleted successfully!", "success")
    
    conn.close()
    return redirect(url_for('founder_dashboard'))

@app.route('/view-applications/<int:project_id>')
def view_applications(project_id):
    if 'user_id' not in session or session.get('role') != 'Founder':
        flash("Unauthorized access.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify project ownership
    cursor.execute('SELECT * FROM projects WHERE id = %s AND founder_name = %s', 
                  (project_id, session['username']))
    project = cursor.fetchone()
    
    if not project:
        flash("Project not found or unauthorized.", "danger")
        return redirect(url_for('founder_dashboard'))

    # Get all applications for the project
    cursor.execute('''
        SELECT u.username, u.email, u.whatsapp_number, pa.created_at, pa.status
        FROM users u 
        JOIN project_applications pa ON u.id = pa.user_id 
        WHERE pa.project_id = %s
        ORDER BY pa.created_at DESC
    ''', (project_id,))
    applications = cursor.fetchall()
    
    conn.close()
    return render_template(
        'view_applications.html',
        project=project,
        applications=applications
    )

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.template_filter('datetime')
def format_datetime(value):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime('%B %d, %Y at %I:%M %p')

@app.route('/get-applications/<int:project_id>')
def get_applications(project_id):
    if 'user_id' not in session or session.get('role') != 'Founder':
        return jsonify({'error': 'Unauthorized'}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verify project ownership and get project status
    cursor.execute('SELECT is_completed FROM projects WHERE id = %s AND founder_name = %s', 
                  (project_id, session['username']))
    project = cursor.fetchone()
    
    if not project:
        return jsonify({'error': 'Project not found'}), 404

    if project[0]:  # If project is completed
        # Get only the accepted developer's details
        cursor.execute('''
            SELECT u.username, pa.created_at, u.cv_link, u.whatsapp_number
            FROM users u 
            JOIN project_applications pa ON u.id = pa.user_id 
            WHERE pa.project_id = %s AND pa.status = 'accepted'
            LIMIT 1
        ''', (project_id,))
    else:
        # Get all applications for active projects
        cursor.execute('''
            SELECT u.username, pa.created_at, u.cv_link, u.id
            FROM users u 
            JOIN project_applications pa ON u.id = pa.user_id 
            WHERE pa.project_id = %s
            ORDER BY pa.created_at DESC
        ''', (project_id,))
    
    applications = cursor.fetchall()
    conn.close()
    
    # Format applications based on project status
    if project[0]:  # Completed project
        formatted_applications = [
            {
                'username': app[0],
                'created_at': format_datetime(app[1]),
                'cv_link': app[2] or 'No resume provided',
                'whatsapp_number': app[3]
            }
            for app in applications
        ]
    else:  # Active project
        formatted_applications = [
            {
                'username': app[0],
                'created_at': format_datetime(app[1]),
                'cv_link': app[2] or 'No resume provided',
                'developer_id': app[3]
            }
            for app in applications
        ]
    
    return jsonify({
        'applications': formatted_applications,
        'is_completed': project[0]
    })

@app.route('/save-cv-link', methods=['POST'])
def save_cv_link():
    if 'user_id' not in session or session.get('role') != 'Developer':
        return jsonify({'error': 'Unauthorized'}), 403

    cv_link = request.form.get('cv_link')
    if not cv_link:
        flash('No CV link provided', 'danger')
        return redirect(url_for('developer_dashboard'))

    # Basic validation for Google Drive link
    if not ('drive.google.com' in cv_link or 'docs.google.com' in cv_link):
        flash('Please provide a valid Google Drive link', 'danger')
        return redirect(url_for('developer_dashboard'))

    # Save link in database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET cv_link = %s WHERE id = %s', 
                  (cv_link, session['user_id']))
    conn.commit()
    conn.close()

    flash('CV link saved successfully!', 'success')
    return redirect(url_for('developer_dashboard'))

@app.route('/github-auth')
def github_auth():
    if 'user_id' not in session or session.get('role') != 'Developer':
        return jsonify({'error': 'Unauthorized'}), 403

    github = OAuth2Session(GITHUB_CLIENT_ID, redirect_uri=GITHUB_CALLBACK_URL)
    authorization_url, state = github.authorization_url(GITHUB_AUTHORIZE_URL)
    
    # Store the state for later validation
    session['oauth_state'] = state
    
    return redirect(authorization_url)

@app.route('/github-callback')
def github_callback():
    try:
        github = OAuth2Session(
            GITHUB_CLIENT_ID,
            state=session['oauth_state'],
            redirect_uri=GITHUB_CALLBACK_URL
        )
        
        # Fetch the token
        token = github.fetch_token(
            GITHUB_TOKEN_URL,
            client_secret=GITHUB_CLIENT_SECRET,
            authorization_response=request.url.replace('http://', 'https://')
        )

        # Store the token in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET github_token = %s WHERE id = %s', 
                      (token['access_token'], session['user_id']))
        conn.commit()
        conn.close()

        flash('Successfully connected with GitHub!', 'success')
    except Exception as e:
        print(f"GitHub Auth Error: {str(e)}")  # For debugging
        flash('GitHub authentication failed. Please try again.', 'danger')

    return redirect(url_for('developer_dashboard'))

@app.route('/finalize-project/<int:project_id>/<int:developer_id>', methods=['POST'])
def finalize_project(project_id, developer_id):
    if 'user_id' not in session or session.get('role') != 'Founder':
        return jsonify({'error': 'Unauthorized'}), 403

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Verify project ownership
        cursor.execute('SELECT * FROM projects WHERE id = %s AND founder_name = %s', 
                      (project_id, session['username']))
        project = cursor.fetchone()
        
        if not project:
            return jsonify({'error': 'Project not found'}), 404

        # Mark project as completed
        cursor.execute('UPDATE projects SET is_completed = TRUE WHERE id = %s', 
                      (project_id,))
        
        # Update the selected application status
        cursor.execute('''
            UPDATE project_applications 
            SET status = CASE 
                WHEN user_id = %s THEN 'accepted'
                ELSE 'rejected'
            END 
            WHERE project_id = %s
        ''', (developer_id, project_id))
        
        conn.commit()
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Finalization Error: {str(e)}")
        return jsonify({'error': 'Failed to finalize project'}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    app.run()


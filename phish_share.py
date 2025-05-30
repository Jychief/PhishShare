import pymysql
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, g
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import csv
import io
import openai
import json
import os
from time import time
from collections import defaultdict

# Initialize OpenAI client (using the new v1.0+ API)
from openai import OpenAI

# Load environment variables from .env file
load_dotenv()

# Set OpenAI API key securely
client = OpenAI(
    api_key=os.getenv('OPENAI_API_KEY')
)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# MySQL configuration
app.config['MYSQL_HOST'] = os.getenv('MYSQLHOST')
app.config['MYSQL_USER'] = os.getenv('MYSQLUSER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQLPASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQLDATABASE')

# Rate limiting setup
request_counts = defaultdict(lambda: {'count': 0, 'window_start': time()})

@app.before_request
def rate_limit():
    ip = request.remote_addr
    current_time = time()
    window_size = 60  # 1 minute window
    max_requests = 30  # Max 30 requests per minute
    
    # Reset window if it's been longer than window_size
    if current_time - request_counts[ip]['window_start'] > window_size:
        request_counts[ip] = {'count': 1, 'window_start': current_time}
    else:
        request_counts[ip]['count'] += 1
    
    # Check if limit exceeded
    if request_counts[ip]['count'] > max_requests:
        return "Rate limit exceeded. Too many requests.", 429

def get_db():
    """Get database connection"""
    return pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB'],
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
def analyze_email_with_ai(sender, subject, body):
    """
    Analyze email content using OpenAI to determine phishing likelihood
    Returns dict with phishing_chance, reasons, and recommendation
    """
    try:
        print(f"Starting AI analysis for email from: {sender}")
        
        prompt = f"""
        Analyze the following email for potential phishing indicators:
        
        Sender: {sender}
        Subject: {subject}
        Body: {body}
        
        Please provide your analysis in the following JSON format:
        {{
            "phishing_chance": "High/Medium/Low",
            "reasons": [
                "Reason 1",
                "Reason 2", 
                "Reason 3"
            ],
            "recommendation": "One sentence recommendation"
        }}
        
        Consider factors like:
        - Urgency language
        - Suspicious links or attachments mentioned
        - Grammar and spelling errors
        - Sender authenticity
        - Requests for personal information
        - Generic greetings
        - Threatening language
        """
        
        # Use new OpenAI API format (v1.0+)
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert specializing in phishing email detection. Provide accurate, helpful analysis in the requested JSON format."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=500,
            temperature=0.3
        )
        
        # Extract and parse the JSON response
        content = response.choices[0].message.content.strip()
        print(f"OpenAI Response: {content}")
        
        # Try to extract JSON from the response
        try:
            # Look for JSON content between curly braces
            start = content.find('{')
            end = content.rfind('}') + 1
            if start != -1 and end != 0:
                json_str = content[start:end]
                analysis = json.loads(json_str)
                print(f"Successfully parsed JSON: {analysis}")
            else:
                raise ValueError("No JSON found in response")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"JSON parsing error: {e}")
            # Fallback if JSON parsing fails
            analysis = {
                "phishing_chance": "Medium",
                "reasons": ["Unable to parse detailed analysis", "Manual review recommended", "Check sender authenticity"],
                "recommendation": "Exercise caution and verify the sender's identity before taking any action."
            }
        
        # Validate the response structure
        if not all(key in analysis for key in ["phishing_chance", "reasons", "recommendation"]):
            print("Analysis structure incomplete")
            raise ValueError("Incomplete analysis structure")
            
        # Ensure phishing_chance is valid
        if analysis["phishing_chance"] not in ["High", "Medium", "Low"]:
            print(f"Invalid phishing_chance: {analysis['phishing_chance']}")
            analysis["phishing_chance"] = "Medium"
            
        # Ensure reasons is a list with at least 3 items
        if not isinstance(analysis["reasons"], list) or len(analysis["reasons"]) < 3:
            print("Reasons list invalid")
            analysis["reasons"] = ["Analysis incomplete", "Manual review needed", "Verify sender authenticity"]
            
        print(f"Final analysis result: {analysis}")
        return analysis
        
    except Exception as e:
        print(f"OpenAI API Error: {str(e)}")
        # Return fallback analysis if API fails
        return {
            "phishing_chance": "Medium",
            "reasons": ["AI analysis unavailable", "Manual review required", "Verify sender and content carefully"],
            "recommendation": "Unable to complete automated analysis - please review manually and exercise caution."
        }

def save_ai_analysis(submission_id, analysis):
    """
    Save AI analysis results to the database
    """
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Fixed: Removed extra parameter - only 6 placeholders for 6 values
        cursor.execute('''
            INSERT INTO ai_analysis (submission_id, phishing_chance, reason_1, reason_2, reason_3, recommendation)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            phishing_chance = VALUES(phishing_chance),
            reason_1 = VALUES(reason_1),
            reason_2 = VALUES(reason_2),
            reason_3 = VALUES(reason_3),
            recommendation = VALUES(recommendation)
        ''', (
            submission_id,
            analysis["phishing_chance"],
            analysis["reasons"][0] if len(analysis["reasons"]) > 0 else "",
            analysis["reasons"][1] if len(analysis["reasons"]) > 1 else "",
            analysis["reasons"][2] if len(analysis["reasons"]) > 2 else "",
            analysis["recommendation"]
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"Database error saving AI analysis: {str(e)}")
        if 'conn' in locals():
            conn.close()
        return False

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/community')
def community():
    conn = get_db()
    cursor = conn.cursor()

    # Get all email submissions and their AI analysis with detailed breakdown
    query = """
        SELECT 
            e.id, e.email_sender, e.email_subject, e.email_body, e.date_submitted,
            a.phishing_chance, a.reason_1, a.reason_2, a.reason_3, a.recommendation
        FROM email_submissions e
        LEFT JOIN ai_analysis a ON e.id = a.submission_id
        ORDER BY e.id DESC
    """
    cursor.execute(query)
    submissions = cursor.fetchall()

    for submission in submissions:
        # Fixed: Check for the correct field name and provide fallback
        if not submission.get('recommendation'):
            submission['analysis_summary'] = "Analysis is pending for this submission."
        else:
            submission['analysis_summary'] = f"Risk: {submission.get('phishing_chance', 'Unknown')} - {submission.get('recommendation', 'No recommendation')}"
        
        # Add structured analysis data
        submission['ai_analysis'] = {
            'phishing_chance': submission.get('phishing_chance'),
            'reasons': [
                submission.get('reason_1'),
                submission.get('reason_2'),
                submission.get('reason_3')
            ],
            'recommendation': submission.get('recommendation')
        }

    # Check user login status
    logged_in = session.get('user_logged_in', False) and 'user_id' in session

    rated_ids = []
    if logged_in:
        user_id = session['user_id']
        cursor.execute(
            "SELECT email_submission_id FROM comments_ratings WHERE user_id = %s", (user_id,)
        )
        rated_ids = [row['email_submission_id'] for row in cursor.fetchall()]

    # Get feedback (comments and ratings) with usernames
    submission_ids = [sub['id'] for sub in submissions]
    feedback_map = {}
    if submission_ids:
        placeholders = ','.join(['%s'] * len(submission_ids))
        feedback_query = f"""
            SELECT c.email_submission_id, c.rating, c.comment, c.timestamp, u.username
            FROM comments_ratings c
            JOIN users u ON c.user_id = u.id
            WHERE c.email_submission_id IN ({placeholders})
            ORDER BY c.timestamp DESC
        """
        cursor.execute(feedback_query, tuple(submission_ids))
        feedbacks = cursor.fetchall()

        for feedback in feedbacks:
            feedback_map.setdefault(feedback['email_submission_id'], []).append({
                'username': feedback['username'],
                'rating': feedback['rating'],
                'comment': feedback['comment'],
                'timestamp': feedback['timestamp'].strftime('%Y-%m-%d %H:%M')
            })

    # Attach feedback to each submission
    for sub in submissions:
        sub['feedback'] = feedback_map.get(sub['id'], [])

    cursor.close()
    conn.close()

    return render_template(
        'community.html',
        submissions=submissions,
        logged_in=logged_in,
        rated_ids=rated_ids
    )

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    print("Form data received:", request.form)
    print("Session data:", session)
    print("User logged in status:", session.get('user_logged_in'))
    print("User ID in session:", session.get('user_id'))

    if not session.get('user_logged_in'):
        print("ERROR: User not logged in according to session")
        flash("You must be logged in to submit feedback.", "danger")
        return redirect(url_for('login'))
    else:
        print("User is logged in, continuing with form processing")

    user_id = session.get('user_id')
    email_submission_id = request.form.get('email_submission_id')
    rating = request.form.get('rating')
    comment = request.form.get('comment', '').strip()

    print(f"User ID: {user_id}")
    print(f"Email Submission ID: {email_submission_id}")
    print(f"Rating: {rating}")
    print(f"Comment: {comment}")

    if not email_submission_id or not rating:
        flash("Rating and submission reference required.", "danger")
        return redirect(url_for('community'))

    try:
        user_id = int(user_id)
        email_submission_id = int(email_submission_id)
        rating = int(rating)

        conn = get_db()
        cursor = conn.cursor()

        print("Database cursor created successfully")

        # Check if user has already rated this submission
        cursor.execute("""
            SELECT id FROM comments_ratings 
            WHERE user_id = %s AND email_submission_id = %s
        """, (user_id, email_submission_id))
        
        existing_rating = cursor.fetchone()
        
        if existing_rating:
            # Update existing rating
            cursor.execute("""
                UPDATE comments_ratings 
                SET rating = %s, comment = %s, timestamp = NOW()
                WHERE user_id = %s AND email_submission_id = %s
            """, (rating, comment, user_id, email_submission_id))
            flash("Your feedback has been updated!", "success")
        else:
            # Insert new rating
            cursor.execute("""
                INSERT INTO comments_ratings (user_id, email_submission_id, rating, comment, timestamp)
                VALUES (%s, %s, %s, %s, NOW())
            """, (user_id, email_submission_id, rating, comment))
            flash("Thank you for your feedback!", "success")

        conn.commit()
        print("Transaction committed successfully")
        cursor.close()
        conn.close()

    except ValueError as e:
        print(f"ValueError: {str(e)}")
        flash(f"Invalid data format: {str(e)}", "danger")
    except Exception as e:
        print(f"Exception: {str(e)}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        flash(f"Error submitting feedback: {str(e)}", "danger")

    return redirect(url_for('community'))

from datetime import datetime

@app.route('/login', methods=['GET', 'POST'])
def login():
    rated_submissions = []
    total_rated = 0
    average_rating = 0

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('community'))
        else:
            flash('Invalid credentials', 'danger')

    if session.get('user_id'):
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT es.id, es.email_sender, es.email_subject, es.email_body,
                   cr.rating, cr.comment, cr.timestamp,
                   a.phishing_chance, a.reason_1, a.reason_2, a.reason_3, a.recommendation
            FROM comments_ratings cr
            JOIN email_submissions es ON cr.email_submission_id = es.id
            LEFT JOIN ai_analysis a ON es.id = a.submission_id
            WHERE cr.user_id = %s
            ORDER BY cr.timestamp DESC
        """, (session['user_id'],))
        rows = cur.fetchall()
        cur.close()
        conn.close()

        for row in rows:
            timestamp_str = row['timestamp'].strftime('%Y-%m-%d %H:%M') if row['timestamp'] else 'N/A'

            # Build ai_analysis dict with fallback defaults
            ai_analysis = {
                'phishing_chance': row['phishing_chance'] if row['phishing_chance'] is not None else 'Pending',
                'reasons': [r for r in (row['reason_1'], row['reason_2'], row['reason_3']) if r],
                'recommendation': row['recommendation'] if row['recommendation'] else 'Pending',
            }

            analysis_summary = (
                f"Risk: {ai_analysis['phishing_chance']} - {ai_analysis['recommendation']}"
                if row['recommendation'] else
                "Analysis is pending for this submission."
            )

            rated_submissions.append({
                'id': row['id'],
                'email_sender': row['email_sender'] or '',
                'email_subject': row['email_subject'] or '',
                'email_body': row['email_body'] or '',
                'rating': row['rating'] or 0,
                'comment': row['comment'] or '',
                'timestamp': timestamp_str,
                'ai_analysis': ai_analysis,
                'analysis_summary': analysis_summary,
        })


        total_rated = len(rated_submissions)
        average_rating = round(sum(s['rating'] for s in rated_submissions) / total_rated, 2) if total_rated > 0 else 0

    return render_template(
        "login.html",
        rated_submissions=rated_submissions,
        total_rated=total_rated,
        average_rating=average_rating
    )

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user_id', None)
    session.pop('user_logged_in', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        print("Form data received:", request.form)  # Debug: print all form data
        
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')

        print(f"Parsed username: {username}, email: {email}, password: {password}, confirm_password: {confirm_password}")

        # Basic validation
        if not username or not email or not password:
            print("Validation failed: missing fields")
            flash("All fields are required.", "danger")
            return render_template('register.html')

        if len(password) < 6:
            print("Validation failed: password too short")
            flash("Password must be at least 6 characters long.", "danger")
            return render_template('register.html')

        if password != confirm_password:
            print("Validation failed: passwords do not match")
            flash("Passwords do not match.", "danger")
            return render_template('register.html')

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Check if username or email already exists
            cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
            account = cursor.fetchone()

            if account:
                print(f"Account already exists: {account}")
                if account['username'] == username:
                    flash("Username already exists. Please choose a different one.", "danger")
                elif account['email'] == email:
                    flash("Email already registered. Please use a different email.", "danger")
                return render_template('register.html')

            # Hash the password and insert the user
            hashed_password = generate_password_hash(password)
            print(f"Inserting user: {username}, {email}, [hashed_password]")  # Debug
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                          (username, email, hashed_password))
            conn.commit()
            print("Insert and commit successful")  # Debug
            flash("Registration successful! Please log in.", "success")
            
        except Exception as e:
            print(f"Registration error: {str(e)}")
            conn.rollback()
            flash(f"Registration failed: {str(e)}", "danger")
            return render_template('register.html')

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/submit_email', methods=['POST'])
def submit_email():
    try:
        sender = request.form.get('sender_email')
        subject = request.form.get('subject', '')
        body = request.form.get('body')

        print(f"Received: sender={sender}, subject={subject}, body={body}")

        if not sender or not body:
            flash("Sender email and body are required.", "danger")
            return redirect(url_for('home'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO email_submissions (email_sender, email_subject, email_body, date_submitted)
            VALUES (%s, %s, %s, NOW())
        ''', (sender, subject, body))
        conn.commit()

        submission_id = cursor.lastrowid
        cursor.close()
        conn.close()

        analysis = analyze_email_with_ai(sender, subject, body)

        if not save_ai_analysis(submission_id, analysis):
            print("Failed to save AI analysis")

    except Exception as e:
        print(f"Error in submit_email: {e}")
        flash(f"An error occurred: {e}", "danger")
        return redirect(url_for('home'))

    return render_template('results.html', 
                           sender=sender, 
                           subject=subject, 
                           body=body, 
                           analysis=analysis)


@app.route('/download_submissions')
def download_submissions():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT e.email_sender, e.email_subject, e.email_body, e.date_submitted,
                   a.phishing_chance, a.recommendation, 
                   a.reason_1, a.reason_2, a.reason_3
            FROM email_submissions e
            LEFT JOIN ai_analysis a ON e.id = a.submission_id
            ORDER BY e.date_submitted DESC
        """)
        submissions = cur.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'Sender', 'Subject', 'Body', 'Timestamp', 
            'Phishing Risk', 'AI Recommendation', 
            'Reason 1', 'Reason 2', 'Reason 3'
        ])

        for sub in submissions:
            sender = sub['email_sender']
            subject = sub['email_subject']
            body = sub['email_body']
            date_submitted = sub['date_submitted']
            phishing_chance = sub['phishing_chance']
            recommendation = sub['recommendation']
            reason_1 = sub['reason_1']
            reason_2 = sub['reason_2']
            reason_3 = sub['reason_3']
            
            if hasattr(date_submitted, 'strftime'):
                date_submitted = date_submitted.strftime('%Y-%m-%d %H:%M:%S')

            writer.writerow([
                sender, 
                subject, 
                body, 
                date_submitted, 
                phishing_chance or 'Not analyzed', 
                recommendation or 'No recommendation',
                reason_1 or '',
                reason_2 or '',
                reason_3 or ''
            ])

        output.seek(0)
        cur.close()
        conn.close()

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=PhishShare_Submissions.csv"}
        )

    except Exception as e:
        flash(f"Error downloading submissions: {str(e)}", "danger")
        return redirect(url_for('community'))


if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from flask_mysqldb import MySQL
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import MySQLdb.cursors
import csv
import io

app = Flask(__name__)
app.secret_key = 'aB3kLm9PqRsTuVwXyZ1EfGhJy'

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'phishsharedb'

mysql = MySQL(app)

@app.route('/') #Route to home
def home():
    return render_template('home.html')

@app.route('/community')
def community():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Get all email submissions and their AI analysis
    query = """
        SELECT 
            e.id, e.email_sender, e.email_subject, e.email_body, e.date_submitted,
            a.analysis_summary
        FROM email_submissions e
        LEFT JOIN ai_analysis a ON e.id = a.submission_id
        ORDER BY e.id DESC
    """
    cursor.execute(query)
    submissions = cursor.fetchall()

    for submission in submissions:
        if not submission['analysis_summary']:
            submission['analysis_summary'] = "Analysis is pending for this submission."

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

        cursor = mysql.connection.cursor()

        print("Database cursor created successfully")

        # ✅ Include `comment` in the column list to match value count
        insert_query = """
            INSERT INTO comments_ratings (user_id, email_submission_id, rating, comment, timestamp)
            VALUES (%s, %s, %s, %s, NOW())
        """
        print("Executing query with values:", (user_id, email_submission_id, rating, comment))
        cursor.execute(insert_query, (user_id, email_submission_id, rating, comment))

        print("Query executed successfully, committing transaction")

        mysql.connection.commit()
        print("Transaction committed successfully")

        flash("Thank you for your feedback!", "success")
        cursor.close()

    except ValueError as e:
        print(f"ValueError: {str(e)}")
        flash(f"Invalid data format: {str(e)}", "danger")
    except Exception as e:
        print(f"Exception: {str(e)}")
        mysql.connection.rollback()
        flash(f"Error submitting feedback: {str(e)}", "danger")
        if 'cursor' in locals():
            cursor.close()

    return redirect(url_for('community'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    rated_submissions = []  # ✅ Define this first so it's always accessible
    total_rated = 0
    average_rating = 0

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        print(f"=== LOGIN ATTEMPT ===")
        print(f"Email: {email}")
        print(f"Session before login: {dict(session)}")

        cur = mysql.connection.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['user_logged_in'] = True

            print(f"Login successful for user ID: {user[0]}")
            print(f"Session after login: {dict(session)}")

            flash('Login successful!', 'success')
            return redirect(url_for('login'))
        else:
            print("Login failed - invalid credentials")
            flash('Invalid credentials', 'danger')

    if session.get('user_id'):
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT es.id, es.email_sender, es.email_subject, es.email_body,
                   cr.rating, cr.comment, cr.timestamp
            FROM comments_ratings cr
            JOIN email_submissions es ON cr.email_submission_id = es.id
            WHERE cr.user_id = %s
        """, (session['user_id'],))
        rows = cur.fetchall()
        cur.close()

        for row in rows:
            rated_submissions.append({
                'id': row[0],
                'email_sender': row[1],
                'email_subject': row[2],
                'email_body': row[3],
                'rating': row[4],
                'comment': row[5],
                'timestamp': row[6],
            })
        total_rated = len(rated_submissions)
        average_rating = round(sum([s['rating'] for s in rated_submissions]) / total_rated, 2) if total_rated > 0 else 0

    return render_template("login.html", rated_submissions=rated_submissions, total_rated=total_rated, average_rating=average_rating)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST']) #Route ro Registration
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        account = cursor.fetchone()

        if account:
            return "Username or email already exists. Please try a different one."

        # Hash the password and insert the user
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                       (username, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))  # Redirects to /login after successful registration

    return render_template('register.html')

@app.route('/submit_email', methods=['POST']) #Route to Submission
def submit_email():
    try:
        sender = request.form['sender_email']
        subject = request.form['subject']
        body = request.form['body']

        # Example placeholder AI response – replace with real AI integration later
        ai_analysis = f"The email from '{sender}' appears to be safe, but always verify links and sender addresses."

        # Save to DB
        cursor = mysql.connection.cursor()
        cursor.execute('''
            INSERT INTO email_submissions (email_sender, email_subject, email_body)
            VALUES (%s, %s, %s)
        ''', (sender, subject, body))
        mysql.connection.commit()
        cursor.close()

    except Exception as e:
        return f"An error occurred: {e}"
    
    # Pass the submitted data and AI response to the results template
    return render_template('results.html', sender=sender, subject=subject, body=body, analysis=ai_analysis)

@app.route('/download_submissions')
def download_submissions():
    cur = mysql.connection.cursor()
    cur.execute("SELECT email_sender, email_subject, email_body, date_submitted FROM email_submissions ORDER BY date_submitted DESC")
    submissions = cur.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Sender', 'Subject', 'Body', 'Timestamp'])  # Header

    for sub in submissions:
        sender, subject, body, date_submitted = sub
        if hasattr(date_submitted, 'strftime'):
            date_submitted = date_submitted.strftime('%Y-%m-%d %H:%M:%S')
        writer.writerow([sender, subject, body, date_submitted])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=PhishShare_Submissions.csv"}
    )

if __name__ == '__main__':
    app.run(debug=True)
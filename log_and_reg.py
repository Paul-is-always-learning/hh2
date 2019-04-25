from flask import Flask, render_template, request, redirect, session
from flask import flash
from flask_bcrypt import Bcrypt
import re
from mysqlconnection import connectToMySQL
app = Flask(__name__)
app.secret_key="Super secret!"
bcrypt=Bcrypt(app)

@app.route("/")
def login_and_registration_page():
    print("*"*80)
    mysql = connectToMySQL('belt_db')
    print("Connected to our database!")
    return render_template("main.html")

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*?\d)(?=.*?[A-Z])(?=.*?[a-z])[A-Za-z\d]{8,15}$')

@app.route("/register", methods=["POST"])
def validate_registration():
    print("*"*80)
    is_valid=True

    if len(request.form['fname']) < 2:
        is_valid=False
        flash("First name must contain at least two letters and contain only letters")

    elif (request.form['fname']).isalpha() == False:
        is_valid=False
        flash("First name must contain at least two letters and contain only letters")

    if len(request.form['lname']) < 2:
        is_valid=False
        flash("Last name must contain at least two letters and contain only letters")

    elif (request.form['lname']).isalpha() == False:
        is_valid=False
        flash("Last name must contain at least two letters and contain only letters")

    if not EMAIL_REGEX.match(request.form['email']):
        is_valid=False
        flash("Invalid email address")

    if not PASSWORD_REGEX.match(request.form["password"]):
        is_valid=False
        flash("Password must contain a number, a capital letter, and be between 8-15 characters")

    if not (request.form["password"]) == (request.form["confirm_password"]):
        is_valid=False
        flash("Passwords must match")

    db = connectToMySQL("belt_db")
    query = "SELECT * FROM users WHERE email=%(em)s;"
    data = {
    "em": request.form['email']
    }
    result=db.query_db(query, data)
    print(result)

    if len(result) != 0:
        is_valid=False
        flash("Email is already taken!")

    if not is_valid:
        return redirect(('/'))

    else:
        print(f"Name: {request.form['fname']}")
        print(f"Alias: {request.form['lname']}")
        print(f"Email: {request.form['email']}")
        print(f"Password: {request.form['password']}")

# GENERATE PASSWORD HASH

        bcrypt.generate_password_hash(request.form["password"])
        print(bcrypt.generate_password_hash)
        pw_hash=bcrypt.generate_password_hash(request.form["password"])
        print(pw_hash)

        db = connectToMySQL("belt_db")

        query = "INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (%(fn)s, %(ln)s, %(em)s, %(pwh)s, NOW(), NOW());"
        data = {
        "fn": request.form["fname"],
        "ln": request.form["lname"],
        "em": request.form["email"],
        "pwh": pw_hash
        }

    db.query_db(query, data)

    print("*"*80)
    db = connectToMySQL("belt_db")
    query = "SELECT * FROM users WHERE email=%(em)s;"
    data = {
        "em": request.form["email"]
    }

    result=db.query_db(query, data)
    print(result)
    print(data)

    session['user_id']=result[0]['user_id']
    return redirect("/dashboard")


@app.route('/login', methods=['POST'])
def login():
    is_valid=True

    db = connectToMySQL("belt_db")
    query = "SELECT * FROM users WHERE email=%(em)s;"
    data = {
        "em": request.form["email"]
    }

    result=db.query_db(query, data)
    print(result)
    print(data)

# TO VERIFY USERS PW IN DB, COMPARE PASSWORDS BY PROVIDING THE HASH AS THE 1ST ARGUMENT AND THE PW TO BE CHECKED AS THE 2ND
        # bcrypt.check_password_hash(hashed_password, password_string)

    if len(result) > 0:
        if bcrypt.check_password_hash(result[0]['pw_hash'], request.form['pw_hash']):
            session['user_id'] = result[0]['user_id']

            return redirect("/dashboard")

    flash("You could not be logged in")
    return redirect("/")


@app.route('/dashboard')
def dashboard():
    print("*"*80)
    if 'user_id' in session:
        print('key exists!')
        print(session['user_id'])
    else:
        print("key 'user_id' does NOT exist")

    if 'user_id' not in session:
        return redirect(('/'))

    db = connectToMySQL("belt_db")
    query = "SELECT first_name FROM users WHERE user_id=%(id)s;"
    data = {
    "id": session['user_id']
    }
    result = db.query_db(query, data)
    print(result)


    print("*"*80)
    db = connectToMySQL("belt_db")
    query = ("SELECT * FROM jobs;")

    jobs = db.query_db(query, data)
    print(jobs)

    return render_template("dashboard.html", result=result, jobs=jobs)


@app.route('/jobs/new')
def add_job():
    print("*"*80)

    db = connectToMySQL("belt_db")
    query = "SELECT first_name FROM users WHERE user_id=%(id)s;"
    data = {
    "id": session['user_id']
    }
    result = db.query_db(query, data)
    print(result)

    return render_template('jobs_new.html', result=result)


@app.route('/add_job', methods=['POST'])
def add_to_jobs():
    print("*"*80)

    is_valid=True

    if len(request.form['job_title']) < 3:
        is_valid=False
        flash("Job Title must contain at least 3 characters")

    if len(request.form['job_description']) < 3:
        is_valid=False
        flash("Job description must contain at least 3 characters")

    if len(request.form['job_location']) < 3:
        is_valid=False
        flash("Job location must contain at least 3 characters")

    if not is_valid:
        return redirect('/jobs/new')
    else:

        db = connectToMySQL("belt_db")
        query = "INSERT INTO jobs (created_by_user_id, job_title, job_location, job_description, created_at, updated_at) VALUES (%(cbid)s, %(jt)s, %(jl)s, %(jd)s, NOW(), NOW());"
        print(session['user_id'])

        data = {
        "cbid": session['user_id'],
        "jt": request.form["job_title"],
        "jl": request.form['job_location'],
        "jd": request.form['job_description']
        }

    db.query_db(query, data)

    return redirect('/dashboard')


@app.route('/jobs/<id>')
def view_job(id):
    print("*"*80)

    db = connectToMySQL("belt_db")
    query = "SELECT first_name FROM users WHERE user_id=%(id)s;"
    data = {
    "id": session['user_id']
    }
    result = db.query_db(query, data)
    print(result)

    db = connectToMySQL("belt_db")
    query = '''
         SELECT * 
           FROM jobs
           JOIN users
             ON user_id = created_by_user_id
          WHERE job_id = %(id)s;'''

    data = {
    "id": id
    }
    jobs=db.query_db(query, data)

    return render_template('view_job.html', result=result, jobs=jobs)


@app.route('/jobs/edit/<id>')
def edit_user(id):
    print("*"*80)

    db = connectToMySQL("belt_db")
    query = "SELECT first_name FROM users WHERE user_id=%(id)s;"
    data = {
    "id": session['user_id']
    }
    result = db.query_db(query, data)
    print(result)

    return render_template("edit_job.html", result=result)


@app.route('/jobs/update/<id>', methods=['POST'])
def update_user(id):
    print("*"*80)

    is_valid=True

    if len(request.form['job_title']) < 3:
        is_valid=False
        flash("Job Title must contain at least 3 characters")

    if len(request.form['job_description']) < 3:
        is_valid=False
        flash("Job description must contain at least 3 characters")

    if len(request.form['job_location']) < 3:
        is_valid=False
        flash("Job location must contain at least 3 characters")

    if not is_valid:
        return redirect('/jobs/edit/<id>')
    else:

        db = connectToMySQL("belt_db")
        query = "UPDATE jobs SET job_title=%(jt)s, job_description=%(jd)s, job_location=%(jl)s, updated_at=NOW() WHERE created_by_user_id=%(sid)s;"
        print(session['user_id'])

        data = {
        "jt": request.form["job_title"],
        "jd": request.form['job_description'],
        "jl": request.form['job_location'],
        "sid": session['user_id']
        }

    db.query_db(query, data)

    return redirect("/dashboard")


@app.route('/delete_job/<id>')
def delete_job(id):
    print("*"*80)
    print(request.form)

    db = connectToMySQL("belt_db")
    query = "DELETE FROM jobs WHERE job_id=%(jid)s;"
    data = {
        "jid": id
    }

    db.query_db(query, data)

    return redirect("/dashboard")

@app.route('/logout', methods=['POST'])
def clear_session_keys():
    print("*"*80)
    session.clear()
    return redirect(('/'))

if __name__ == "__main__":
    app.run(debug=True)
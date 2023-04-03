from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DATABASE = "smile.db"
app = Flask(__name__)

bcrypt = Bcrypt(app)
app.secret_key = "aj;f3jp89j"


# create connection function
def create_connection(db_file):
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


# get list function
def get_list(query, execute):
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, execute)
    category_list = cur.fetchall()
    con.close()
    return category_list


# insert data function
def insert_data(query, params):
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, params)
    con.commit()
    con.close()


# check if user is logged in
def is_logged_in():
    if session.get('email') is None:
        return False
    else:
        return True


# home page
@app.route('/')
def home_page():
    return render_template("home.html", logged_in=is_logged_in())


# signup page
@app.route('/signup')
def signup_page():
    if is_logged_in():
        return redirect("/menu/1")
    if request.method == 'POST':
        print(request.form)

        firstname = request.form.get('fname').title().strip()
        lastname = request.form.get('lname').title().strip()
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password_2 = request.form.get('password_2')

        print(password)
        print(password_2)

        if password != password_2:
            return redirect("/signup?error=Passwords+do+not+match")

        hashed_password = bcrypt.generate_password_hash(password)

        try:
            insert_data("INSERT INTO user (fname, lname, email, password) VALUES (?, ?, ?, ?)",
                        (firstname, lastname, email, hashed_password))
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

        return redirect('/login')
    return render_template("signup.html")

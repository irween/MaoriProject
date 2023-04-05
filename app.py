from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

DATABASE = "maoridb"
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
def get_list(query, params):
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, params)
    query_list = cur.fetchall()
    con.close()
    return query_list


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


# check if user is a teacher
def is_teacher():
    teacher_list = get_list("SELECT teacher FROM users", "")
    print(teacher_list)
    if 1 in teacher_list[0]:
        return True
    return False


# home page
@app.route('/')
def home_page():
    category_list = get_list("SELECT id, name FROM categories", "")
    return render_template("home.html", logged_in=is_logged_in(),
                           category_list=category_list, is_teacher=is_teacher())


# login page
@app.route('/login', methods=['POST', 'GET'])
def login_page():
    if is_logged_in():
        return redirect("/")
    print("Logging In")
    category_list = get_list("SELECT id, name FROM categories", "")
    if request.method == "POST":
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        user_data = get_list("SELECT id, firstname, password FROM users WHERE email = ?", (email,))

        try:
            user_id = user_data[0]
            first_name = user_id[1]
            db_password = user_id[2]

        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        session['email'] = email
        session['user_id'] = user_id
        session['firstname'] = first_name
        session['cart'] = []
        print(session)
        return redirect('/')
    return render_template("login.html", logged_in=is_logged_in(),
                           category_list=category_list, is_teacher=is_teacher())


# signup page
@app.route('/signup', methods=['POST', 'GET'])
def signup_page():
    category_list = get_list("SELECT id, name FROM categories", "")
    if is_logged_in():
        return redirect("/")
    if request.method == 'POST':
        print(request.form)

        firstname = request.form.get('firstname').title().strip()
        lastname = request.form.get('lastname').title().strip()
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password_2 = request.form.get('password_2')
        teacher = request.form.get('teacher')

        print(password)
        print(password_2)

        if password != password_2:
            return redirect("/signup?error=Passwords+do+not+match")

        hashed_password = bcrypt.generate_password_hash(password)

        if teacher is not None:
            teacher = 1
            query = "INSERT INTO users (firstname, lastname, email, password" + teacher + ") VALUES (?, ?, ?, ?, ?)"
            print(query)
        else:
            teacher = 0
            query = "INSERT INTO users (firstname, lastname, email, password" + teacher + ") VALUES (?, ?, ?, ?)"
        try:
            insert_data(query, (firstname, lastname, email, hashed_password))
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

        return redirect('/login')
    return render_template("signup.html", logged_in=is_logged_in(),
                           category_list=category_list, is_teacher=is_teacher())


# logout page function
@app.route('/logout')
def logout_page():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=You+have+successfully+logged+out')


# dictionary page
@app.route('/dictionary')
def dictionary_page():
    if not is_logged_in():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    dictionary_list = get_list("SELECT maori, english, category, definition, level FROM vocabulary", "")
    category_list = get_list("SELECT id, name FROM categories", "")

    return render_template("dictionary.html", logged_in=is_logged_in(), dictionary_list=dictionary_list,
                           category_list=category_list, is_teacher=is_teacher())


# category page
@app.route('/category/<cat_id>')
def category_page(cat_id):
    if not is_logged_in():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")
    print(cat_id)
    category_list = get_list("SELECT id, name FROM categories", "")
    dictionary_list = get_list("SELECT maori, english, category, definition, level FROM vocabulary WHERE category_id=?",
                               (cat_id, ))
    return render_template("dictionary.html", logged_in=is_logged_in(), dictionary_list=dictionary_list,
                           category_list=category_list, is_teacher=is_teacher())


# admin page
@app.route('/admin')
def admin_page():
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+or+admin+to+access+this+page")

    category_list = get_list("SELECT * FROM categories", "")

    return render_template("admin.html", logged_in=is_logged_in(), category_list=category_list, is_teacher=is_teacher())


# add category page
@app.route('/add_category', methods=['POST', 'GET'])
def add_category_page():
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    if request.method == 'POST':
        print(request.form)

        category = request.form.get('category_name').lower().strip()

        query = "INSERT INTO categories (name) VALUES (?)"
        try:
            insert_data(query, (category,))
        except sqlite3.IntegrityError:
            return redirect('/add_category?error=Category+already+exists')

        return redirect('/admin')
    return render_template("add_category.html", logged_in=is_logged_in(), is_teacher=is_teacher())


# delete category page
@app.route('/delete_category/', methods=['POST'])
def delete_category_page():
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    if request.method == 'POST':
        category = request.form.get('cat_id')
        print(category)
        category = category.split(",")
        cat_id = category[1]
        cat_name = category[0]
        print(category, cat_id, cat_name)
        return render_template("delete_category.html", id=cat_id, cat_name=cat_name, type=category)

    return redirect('/admin')


# delete_confirm category
@app.route('/delete_category_confirm/<cat_id>')
def delete_category(cat_id):
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    insert_data("DELETE FROM categories WHERE id=?", (cat_id,))
    return redirect('/admin')


# page not found error page
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', logged_in=is_logged_in(), message=e), 404


# internal server error page
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', logged_in=is_logged_in(), message=e), 500


if __name__ == '__main__':
    app.run()

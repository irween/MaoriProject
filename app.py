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
    if not is_logged_in():
        return False

    teacher_list = get_list("SELECT teacher FROM users WHERE email = ?", (session['email'],))
    if teacher_list[0][0] == 1:
        print(teacher_list)
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
        print(session)
        return redirect('/')
    return render_template("login.html", logged_in=is_logged_in(),
                           category_list=category_list)


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
        else:
            teacher = 0
        try:
            query = "INSERT INTO users (firstname, lastname, email, password, teacher) VALUES (?, ?, ?, ?, ?)"
            print(query)
            insert_data(query, (firstname, lastname, email, hashed_password, teacher))
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

        return redirect('/login')
    return render_template("signup.html", logged_in=is_logged_in(),
                           category_list=category_list)


# logout page function
@app.route('/logout')
def logout_page():
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/?message=You+have+successfully+logged+out')


# dictionary page
@app.route('/dictionary/<cat_type>/<cat_id>')
def dictionary_page(cat_type, cat_id):
    dictionary_list = []
    if cat_type == "category":
        dictionary_list = get_list("SELECT id, maori, english, category, definition, level, added_by, category_id "
                                   "FROM vocabulary WHERE category_id=?",
                                   (cat_id,))
    elif cat_type == "level":
        dictionary_list = get_list("SELECT id, maori, english, category, definition, level, added_by, category_id "
                                   "FROM vocabulary WHERE level=?",
                                   (cat_id,))
    elif cat_type == "all_words":
        dictionary_list = get_list("SELECT id, maori, english, category, definition, level, added_by, category_id "
                                   "FROM vocabulary", "")

    category_list = get_list("SELECT id, name FROM categories", "")

    print(dictionary_list)
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


# delete category page
@app.route('/delete_category/', methods=['POST'])
def delete_category_page():
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    if request.method == 'POST':
        category = request.form.get('cat_id')
        print(category)
        category = category.split(",")
        cat_id = category[0]
        cat_name = category[1]
        print(category, cat_id, cat_name)
        return render_template("delete_confirm.html", id=cat_id, cat_name=cat_name, type="category")

    return redirect('/admin')


# delete_confirm category
@app.route('/delete_confirm/<deletion>')
def delete_category(deletion):
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    delete_type = deletion.split(",")[0]
    if delete_type == "category":
        cat_id = deletion.split(",")[1]
        print(cat_id)
        insert_data("DELETE FROM vocabulary WHERE category_id=?", (cat_id,))
        insert_data("DELETE FROM categories WHERE id=?", (cat_id,))
    elif delete_type == "word":
        word_id = deletion.split(",")[1]
        print(word_id)
        insert_data("DELETE FROM vocabulary WHERE id=?", (word_id,))
    insert_data("UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM vocabulary) WHERE name = 'vocabulary'", "")
    insert_data("UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM categories) WHERE name = 'categories'", "")
    return redirect('/admin')


# delete word page
@app.route('/delete_word/', methods=['POST'])
def delete_word_page():
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    if request.method == 'POST':
        word = request.form.get('word')
        print(word)
        word = word.split(",")
        word_id = word[0]
        word_name = word[1]
        return render_template("delete_confirm.html", id=word_id, word_name=word_name, type="word")

    return redirect('/admin')


# add word page
@app.route('/add_word', methods=['POST', 'GET'])
def add_word_page():
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    if request.method == 'POST':
        print(request.form)

        maori = request.form.get('maori').lower().strip()
        print("maori: " + maori)
        english = request.form.get('english').lower().strip()
        print("english: " + english)
        category = request.form.get('category').split(",")
        print(category)
        definition = request.form.get('definition').lower().strip()
        print("definition: " + definition)
        level = request.form.get('level').lower().strip()
        print("level: " + level)

        user = session['firstname'] + " " + session['email']
        print(user)

        dictionary_list = get_list("SELECT maori, english FROM vocabulary", "")
        for word in dictionary_list:
            if maori == word[0] and english == word[1]:
                return redirect('/admin?error=Word+already+exists')

        try:
            insert_data("INSERT INTO vocabulary (maori, english, category, definition, level, added_by, category_id) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (maori, english, category[1], definition, level, user, category[0]))
        except sqlite3.IntegrityError:
            return redirect('/add_word?error=Word+already+exists')
    return redirect('/admin')


# edit word page
@app.route('/edit_word/', methods=['POST'])
def edit_word_page():
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    if request.method == 'POST':
        maori_word = request.form.get('maori')
        print(maori_word)
        english_word = request.form.get('english')
        print(english_word)
        category = request.form.get('category').split(",")
        print(category)
        definition = request.form.get('definition')
        print(definition)
        level = request.form.get('level')
        print(level)
        word_id = request.form.get('id')
        print(word_id)

        insert_data("UPDATE vocabulary SET maori=?, english=?, category=?, definition=?, level=?, category_id=? "
                    "WHERE id=?", (maori_word, english_word, category[1], definition, level, category[0], word_id))
        return redirect(request.referrer + "?=edit_word")

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

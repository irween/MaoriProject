from flask import Flask, render_template, redirect, request, session
import sqlite3
from sqlite3 import Error
from flask_bcrypt import Bcrypt

# setting the database file name
DATABASE = "maoridb"
app = Flask(__name__)

# using bcrypt for password encryption
bcrypt = Bcrypt(app)
app.secret_key = "aj;f3jp89j"


# create connection function
def create_connection(db_file):
    """
    create a database connection to the SQLite database specified by db_file
    @param db_file: the database file
    @return: the connection to the database, or nothing if there is an error
    """
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
    return None


# get list function
def get_list(query, params):
    """
    query all rows in the table
    @param query: the query to be executed
    @param params: the parameters of the query
    @return: returns the list from the query
    """
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, params)
    query_list = cur.fetchall()
    con.close()
    return query_list


# insert data function
def insert_data(query, params):
    """
    insert and change data into the database
    @param query: query: the query to be executed
    @param params: params: the parameters of the query
    @return: returns nothing
    """
    con = create_connection(DATABASE)
    cur = con.cursor()
    cur.execute(query, params)
    con.commit()
    con.close()


# get junk id
def junk_id():
    """
    gets the id of the junk category
    @return:
    """
    id_junk = get_list("SELECT id FROM categories WHERE name='junk'", "")
    return id_junk[0][0]


# check if user is logged in
def is_logged_in():
    """
    check if the user is logged in
    @return: returns true if the user is logged in, false if not
    """
    if session.get('email') is None:  # checks if the user has an email in the current session, i.e. logged in
        return False
    else:
        return True


# check if user is a teacher
def is_teacher():
    """
    check if the user is a teacher
    @return: returns true if the user is a teacher, false if not
    """
    if not is_logged_in():  # makes sure that the user is logged in
        return False

    # gets the teacher value from the database for the given user
    teacher_list = get_list("SELECT teacher FROM users WHERE email = ?", (session['email'],))
    if teacher_list[0][0] == 1:  # checks if the accounts teacher value is 1 (true) or 0 (false)
        print(teacher_list)
        return True
    return False


# home page
@app.route('/')
def home_page():
    """
    renders the home page
    @return:
    """
    return render_template("home.html", logged_in=is_logged_in(),
                           category_list=get_list("SELECT id, name FROM categories", ""), is_teacher=is_teacher(),
                           junk_id=junk_id())


# login page
@app.route('/login', methods=['POST', 'GET'])
def login_page():
    """
    renders the login page
    uses the is_logged_in() function to check if the user is already logged in
    gets the form values from the login form and checks if the email and password are correct
    @return:
    """
    if is_logged_in():
        return redirect("/")
    print("Logging In")

    if request.method == "POST":
        # gets the email and password from the login form
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        # gets the user data from the database
        user_data = get_list("SELECT id, firstname, password FROM users WHERE email = ?", (email,))

        # checks if the user exists
        try:
            user_id = user_data[0]
            first_name = user_id[1]
            db_password = user_id[2]

        # if the user does not exist, redirect to the login page with an error message
        except IndexError:
            return redirect("/login?error=Email+invalid+or+password+incorrect")

        # checks if the password is correct
        if not bcrypt.check_password_hash(db_password, password):
            return redirect(request.referrer + "?error=Email+invalid+or+password+incorrect")

        # if the password is correct, set the session variables and redirect to the home page
        session['email'] = email
        session['user_id'] = user_id
        session['firstname'] = first_name
        print(session)
        return redirect('/')
    return render_template("login.html", logged_in=is_logged_in(),
                           category_list=get_list("SELECT id, name FROM categories", ""),
                           junk_id=junk_id(), message=request.args.get('message'))


# signup page
@app.route('/signup', methods=['POST', 'GET'])
def signup_page():
    """
    renders the signup page
    uses the is_logged_in() function to check if the user is already logged in
    gets the form values from the signup form and inserts them into the database
    @return:
    """

    if is_logged_in():
        return redirect("/")

    # if the request method is POST, get the form values and insert them into the database
    if request.method == 'POST':
        print(request.form)

        # gets the form values
        firstname = request.form.get('firstname').title().strip()
        lastname = request.form.get('lastname').title().strip()
        email = request.form.get('email').lower().strip()
        password = request.form.get('password')
        password_2 = request.form.get('password_2')
        teacher = request.form.get('teacher')

        print(password)
        print(password_2)

        # checks if the passwords match
        if password != password_2:
            return redirect("/signup?error=Passwords+do+not+match")

        # hashes the password using bcrypt
        hashed_password = bcrypt.generate_password_hash(password)

        # checks if the user selected that they're a teacher
        if teacher is not None:
            teacher = 1
        else:
            teacher = 0

        # inserts the user data into the database
        try:
            insert_data("INSERT INTO users (firstname, lastname, email, password, teacher) VALUES (?, ?, ?, ?, ?)",
                        (firstname, lastname, email, hashed_password, teacher))

        # if the email is already in use, redirect to the signup page with an error message
        except sqlite3.IntegrityError:
            return redirect('/signup?error=Email+is+already+used')

        return redirect('/login')
    return render_template("signup.html", logged_in=is_logged_in(),
                           category_list=get_list("SELECT id, name FROM categories", ""),
                           junk_id=junk_id(), message=request.args.get('message'))


# logout page function
@app.route('/logout')
def logout_page():
    """
    logs the user out by removing the session variables
    @return:
    """
    print(list(session.keys()))
    [session.pop(key) for key in list(session.keys())]
    print(list(session.keys()))
    return redirect('/login?message=You+have+successfully+logged+out')


# dictionary page
@app.route('/dictionary/<cat_type>/<cat_id>')
def dictionary_page(cat_type, cat_id):
    """
    renders the dictionary page
    @param cat_type:
    @param cat_id:
    @return:
    """
    dictionary_list = []

    # gets the list of words from the specific category if the current page is for category
    if cat_type == "category":
        dictionary_list = get_list("SELECT id, maori, english, category, definition, level, added_by, category_id "
                                   "FROM vocabulary WHERE category_id=?",
                                   (cat_id,))

    # gets the list of all words if the current page is for all words
    elif cat_type == "all_words":
        dictionary_list = get_list("SELECT id, maori, english, category, definition, level, added_by, category_id "
                                   "FROM vocabulary", "")

    print(dictionary_list)
    return render_template("dictionary.html", logged_in=is_logged_in(), dictionary_list=dictionary_list,
                           category_list=get_list("SELECT id, name FROM categories", ""), is_teacher=is_teacher(),
                           junk_id=junk_id(), message=request.args.get('message'))


# word page
@app.route('/word/<word_id>')
def word_page(word_id):
    """
    renders the word page
    @param word_id:
    @return:
    """
    # gets the word data from the database
    words = get_list("SELECT id, maori, english, category, definition, level, added_by "
                     "FROM vocabulary WHERE id=?", (word_id,))[0]

    return render_template("word.html", logged_in=is_logged_in(), word=words,
                           category_list=get_list("SELECT id, name FROM categories", ""), is_teacher=is_teacher(),
                           junk_id=junk_id())


# admin page
@app.route('/admin')
def admin_page():
    """
    renders the admin page
    uses is_logged_in() and is_teacher to check if the user is logged in and is a teacher
    @return:
    """
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+or+admin+to+access+this+page")

    return render_template("admin.html", logged_in=is_logged_in(),
                           category_list=get_list("SELECT id, name FROM categories", ""), is_teacher=is_teacher(),
                           junk_id=junk_id(), message=request.args.get('message'))


# add category page
@app.route('/add_category', methods=['POST', 'GET'])
def add_category_page():
    """
    renders the add category page
    uses is_logged_in() and is_teacher to check if the user is logged in and is a teacher
    gets the form values from the add category form and inserts them into the database
    @return:
    """
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    # gets the data from the form if the request method is POST
    if request.method == 'POST':
        print(request.form)

        # gets the form values
        category = request.form.get('category_name').lower().strip()

        # inserts the category into the database
        try:
            insert_data("INSERT INTO categories (name) VALUES (?)", (category,))

        # if the category already exists, redirect to the add category page with an error message
        except sqlite3.IntegrityError:
            return redirect('/add_category?error=Category+already+exists')
    return redirect('/admin')


# delete category page
@app.route('/delete_category/', methods=['POST'])
def delete_category_page():
    """
    renders the delete category page
    uses is_logged_in() and is_teacher to check if the user is logged in and is a teacher
    gets the form values from the delete category form and inserts them into the database
    @return:
    """
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    # gets the data from the form if the request method is POST
    if request.method == 'POST':
        # gets the form values
        category = request.form.get('cat_id')
        print(category)

        # making cat_id and cat_name variables equal to the correct values
        category = category.split(",")
        cat_id = category[0]
        cat_name = category[1]
        print(category, cat_id, cat_name)
        return render_template("delete_confirm.html", id=cat_id, cat_name=cat_name, type="category")

    return redirect('/admin')


# delete_confirm category
@app.route('/delete_confirm/<deletion>')
def delete_category(deletion):
    """
    deletes the category from the database
    uses is_logged_in() and is_teacher to check if the user is logged in and is a teacher
    gets deletion type from the url and deletes the category or word(s) from the database
    @param deletion:
    @return:
    """
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    # getting the type of deletion from the url
    delete_type = deletion.split(",")[0]

    # deleting the category from the category database and moving the words to a "junk" category incase they are needed
    if delete_type == "category":
        cat_id = deletion.split(",")[1]
        print(cat_id)
        # moving the words to the junk category
        insert_data("UPDATE vocabulary SET category_id=17 WHERE category_id=?", (cat_id,))
        # deleting the category
        insert_data("DELETE FROM categories WHERE id=?", (cat_id,))

    # deleting the word from the database
    elif delete_type == "word":
        word_id = deletion.split(",")[1]
        print(word_id)
        insert_data("DELETE FROM vocabulary WHERE id=?", (word_id,))

    # deleting the all the words in the junk category but keeping the category
    elif delete_type == "junk":
        cat_id = deletion.split(",")[1]
        insert_data("DELETE FROM vocabulary WHERE category_id=?", (cat_id,))
    insert_data("UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM vocabulary) WHERE name = 'vocabulary'", "")
    insert_data("UPDATE sqlite_sequence SET seq = (SELECT MAX(id) FROM categories) WHERE name = 'categories'", "")
    return redirect('/admin')


# delete word page
@app.route('/delete_word/', methods=['POST'])
def delete_word_page():
    """
    renders the delete word page
    uses is_logged_in() and is_teacher to check if the user is logged in and is a teacher
    gets the form values from the delete word button and sends them to the delete_confirm page
    @return:
    """
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    # gets the data from the form if the request method is POST
    if request.method == 'POST':
        word = request.form.get('word')
        print(word)
        # splits the word into the name and id
        word = word.split(",")
        word_id = word[0]
        word_name = word[1]
        return render_template("delete_confirm.html", id=word_id, word_name=word_name, type="word")

    return redirect('/admin')


# add word page
@app.route('/add_word', methods=['POST', 'GET'])
def add_word_page():
    """
    renders the add word page
    uses is_logged_in() and is_teacher to check if the user is logged in and is a teacher
    gets the form values from the add word form and inserts them into the database
    @return:
    """
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    # gets the data from the form if the request method is POST
    if request.method == 'POST':
        print(request.form)

        # gets the form values
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

        # getting the username and email from the session to add to the database
        user = session['firstname'] + " " + session['email']
        print(user)

        # checking if the word already exists in the database
        dictionary_list = get_list("SELECT maori, english FROM vocabulary", "")
        for word in dictionary_list:
            if maori == word[0] and english == word[1]:
                return redirect('/admin?error=Word+already+exists')

        # inserting the data into the database
        try:
            insert_data("INSERT INTO vocabulary (maori, english, category, definition, level, added_by, category_id) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (maori, english, category[1], definition, level, user, category[0]))
        # if the word already exists in the database redirects to the add word page with an error
        except sqlite3.IntegrityError:
            return redirect('/add_word?error=Word+already+exists')
    return redirect('/admin')


# edit word page
@app.route('/edit_word/', methods=['POST'])
def edit_word_page():
    """
    renders the edit word page
    uses is_logged_in() and is_teacher to check if the user is logged in and is a teacher
    gets the form values from the edit word form and sends them to the edit_confirm page
    @return:
    """
    if not is_logged_in() and 1 not in is_teacher():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    # gets the data from the form if the request method is POST
    if request.method == 'POST':
        # gets the form values
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

        # updating the database with the new values
        insert_data("UPDATE vocabulary SET maori=?, english=?, category=?, definition=?, level=?, category_id=? "
                    "WHERE id=?", (maori_word, english_word, category[1], definition, level, category[0], word_id))
        return redirect(request.referrer + "?=edit_word")

    return redirect('/admin')


# delete junk words
@app.route('/delete_junk_words', methods=['POST'])
def delete_junk_words():
    """
    renders the delete junk words page
    uses is_logged_in() and is_teacher to check if the user is logged in and is a teacher
gets the form values from the delete junk words button and sends them to the delete_confirm page
    @return:
    """
    if not is_logged_in():
        return redirect("/login?error=You+must+be+logged+in+to+access+this+page")

    # gets the data from the button if the request method is POST
    if request.method == 'POST':
        category_name = request.form.get('junk')
        # gets the id of the category "junk"
        cat_id = get_list("SELECT id FROM categories WHERE name=?", (category_name,))[0][0]
        print(cat_id)

        return render_template("delete_confirm.html", id=cat_id, cat_name=category_name, type="junk")

    return redirect('/admin')


# page not found error page
@app.errorhandler(404)
def page_not_found(e):
    """
    renders the page not found error page
    @param e: the error message
    @return:
    """
    return render_template('error.html', logged_in=is_logged_in(), message=e), 404


# internal server error page
@app.errorhandler(500)
def internal_server_error(e):
    """
    renders the internal server error page
    @param e: the error message
    @return:
    """
    return render_template('error.html', logged_in=is_logged_in(), message=e), 500


if __name__ == '__main__':
    app.run()

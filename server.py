
# ? Importing all the libraries and technologies needed for the project
from flask import Flask, request, redirect, session, flash, render_template
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

#? initializing the app and bcrypt
app = Flask(__name__)
app.secret_key = ('damascusXIII')  # create the secret key for flash and session
bcrypt = Bcrypt(app)        # create the Bcrypt for hashing the password
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')      # created the regex check for the emails entered

# ? Home route this is the first page the user will see
@app.route('/')
def index():
    session['user_id'] = '' # reset the user_id if the user came from the account profile page
    return render_template('index.html')

# ? Welcome page after a user successfully log-in
@app.route('/welcome')
def welcome():
    if session['logged_in']:
        data = {
            'user_id': session['user_id']   # it is initialized once the user has submitted a valid login
        }
        user = connectToMySQL('login_registration').query_db("SELECT * FROM users WHERE id=%(user_id)s",data)   # only pull the information for the current user
        return render_template('welcome.html', user_tp=user)    # pass along the user_tp to be used by the html file
    else:
        return redirect('/')

# * Clear the user_id after the user logs out of the account info page
@app.route('/logout')
def logout():
    session['user_id'] = ''
    session['logged_in'] = False
    return redirect('/')

# * Validate the user login attempt - redirect to welcome page if approved
@app.route('/login', methods=['POST'])
def login():
    # validating the login attempt
    is_valid = True
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash('* Enter a valid email address', 'email_log')
    if len(request.form['password'])<8 or len(request.form['password'])>30:
        is_valid = False
        flash('* Password must be between 8 and 30 characters long', 'password_log')

    if not is_valid:    # if not valid redirecting to the home page for the user to try again
        return redirect('/')
    else:   #otherwise we will check whether the email can be found in our database
        is_user = False
        users = connectToMySQL('login_registration').query_db("SELECT * FROM users;")

        for user in users:
            if user['email'] == request.form['email']:
                is_user = True
                check_user = user['email']
                break
        
        if not is_user: # is the email entered cannot be found then flash this message and redirect to the home page
            flash('* That account does not exist', 'l_email_log')
            return redirect('/')
        else:   #otherwise we will now check the password to see if it is matching the username entered
            for user in users:
                if user['email'] == check_user:
                    if bcrypt.check_password_hash(user['password'],request.form['password']):
                        session['user_id'] = user['id']
                        session['logged_in'] = True
                        return redirect('/welcome')

            flash('* Incorrect password try again', 'l_password_log') # if it exits the loop it means no password was found with that entered password
            return redirect('/')

# * Validate, or submit the account information - dependant on the users submission
@app.route('/create', methods=['POST'])
def create():
    # validating the creation attempt
    is_valid = True
    if request.form['f_name'].isalpha()==False or len(request.form['f_name'])<2:
        is_valid = False
        flash('* First name must be at least 2 character and nothing but letters', 'first_sign')
    if request.form['l_name'].isalpha()==False or len(request.form['l_name'])<2:
        is_valid = False
        flash('* Last name must be at least 2 character and nothing but letters', 'last_sign')
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash('* Enter a valid email address', 'email_sign')
    if len(request.form['password'])<8 or len(request.form['password'])>30:
        is_valid = False
        flash('* Password must be between 8 and 30 characters long', 'password_sign')
    if request.form['password'] != request.form['c_password']:
        is_valid = False
        flash('* Password doesn\'t match', 'c_password_sign')

    if not is_valid:    # if not valid redirecting to the home page for the user to try again
        return redirect('/')
    else:   # otherwise we will check if the input is unique now
        is_unique = True
        users = connectToMySQL('login_registration').query_db('SELECT * FROM users;')

        for password in users:  # check if the password is unique
            if bcrypt.check_password_hash(password['password'], request.form['password']):
                is_unique = False
                flash('* Password is taken', 'u_password_sign')
                break
        
        for email in users: # check if the email is unique
            if email['email'] == request.form['email']:
                is_unique = False
                flash('* Email is taken', 'u_email_sign')
                break
        
        if not is_unique:   # if not unique redirecting to the home for the user to try again
            return redirect('/')
        else:               # if all checks are complete now it will insert the data into the table
            data = {
                'f_name': request.form['f_name'],
                'l_name': request.form['l_name'],
                'email': request.form['email'],
                'password': bcrypt.generate_password_hash(request.form['password'])
            }
            query = "INSERT INTO users(first_name,last_name,email,password) VALUES(%(f_name)s,%(l_name)s,%(email)s,%(password)s);"  # enter the information of the user in order and formated to enter the database
            query = connectToMySQL('login_registration').query_db(query,data)
            return redirect('/')    # redirect to the login page for the user to login to their account

if __name__ == '__main__':
    app.run(debug=True)
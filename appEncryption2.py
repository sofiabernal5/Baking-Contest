from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
from cryptography.fernet import Fernet

app = Flask(__name__)
DATABASE = 'baking_contest.db'
app.secret_key = 'your_secret_key'  # Replace with a secure key


# Encryption setup
def generate_key():
    """Generate a new encryption key and save it to a file."""
    key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(key)

def load_key():
    """Load the encryption key from a file."""
    if not os.path.exists('secret.key'):
        generate_key()
    with open('secret.key', 'rb') as key_file:
        return key_file.read()

key = load_key()
cipher = Fernet(key)

def encrypt(data: str) -> str:
    """Encrypt a string."""
    return cipher.encrypt(data.encode()).decode()

def decrypt(data: str) -> str:
    """Decrypt a string."""
    return cipher.decrypt(data.encode()).decode()


# Database initialization
def init_db():
    """Initialize the database and create tables."""
    if not os.path.exists(DATABASE):
        create_database()

def create_database():
    """Create a new database with the required schema."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS BakingContestPeople (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            phone_number TEXT NOT NULL,
            security_level INTEGER NOT NULL,
            login_password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS BakingContestEntries (
            entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            baking_item_name TEXT NOT NULL,
            excellent_votes INTEGER DEFAULT 0,
            ok_votes INTEGER DEFAULT 0,
            bad_votes INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES BakingContestPeople(id)
        )
    ''')
    conn.commit()
    conn.close()
    print("New database created successfully.")


@app.route('/')
def home():
    """Homepage based on user security level."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    username = session['username']
    security_level = session['security_level']

    if security_level == 1:
        return render_template('home_sec1.html', username=username)
    elif security_level == 2:
        return render_template('home_sec2.html', username=username)
    elif security_level == 3:
        return render_template('home_sec3.html', username=username)
    else:
        return "Page not found", 404


@app.route('/addUser', methods=['GET', 'POST'])
def addUser():
    """Add a new user to the database with encrypted fields."""
    if request.method == 'POST':
        # Collect data from the form
        name = request.form.get('name', '').strip()
        age = request.form.get('age', '').strip()
        phone_number = request.form.get('phone_number', '').strip()
        security_level = request.form.get('security_level', '').strip()
        login_password = request.form.get('login_password', '').strip()

        # Validate inputs
        errors = []
        if not name:
            errors.append("Name is missing.")
        if not age or not age.isdigit() or not (1 <= int(age) <= 120):
            errors.append("The Age must be a whole number between 1 and 120.")
        if not phone_number:
            errors.append("Phone number is missing.")
        if not security_level or not security_level.isdigit() or not (1 <= int(security_level) <= 3):
            errors.append("SecurityLevel must be a numeric value between 1 and 3.")
        if not login_password:
            errors.append("Password is missing.")

        if errors:
            return render_template('UserResults.html', errors=errors)

        # Encrypt sensitive fields
        try:
            encrypted_name = encrypt(name)
            encrypted_phone_number = encrypt(phone_number)
            encrypted_password = encrypt(login_password)

            # Debugging print statements
            print(f"Original Name: {name}, Encrypted Name: {encrypted_name}")
            print(f"Original Phone Number: {phone_number}, Encrypted Phone Number: {encrypted_phone_number}")
            print(f"Original Password: {login_password}, Encrypted Password: {encrypted_password}")

            # Insert the data into the database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO BakingContestPeople (name, age, phone_number, security_level, login_password)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                encrypted_name,
                int(age),
                encrypted_phone_number,
                int(security_level),
                encrypted_password
            ))
            conn.commit()
            conn.close()

            # Render success message
            success_message = "Record successfully added."
            return render_template('UserResults.html', success_message=success_message)

        except sqlite3.Error as e:
            # Handle database errors
            print(f"Database error during user addition: {e}")
            return render_template('UserResults.html', errors=[f"An error occurred: {e}"])

    # Render the form for GET requests
    return render_template('addUser.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login a user."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            print("Login failed: Missing username or password.")  # Debug statement
            return render_template('login.html', error="Username and password are required!")

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            # Query the database for all stored usernames and passwords
            cursor.execute('SELECT id, name, login_password, security_level FROM BakingContestPeople')
            users = cursor.fetchall()
            conn.close()

            # Iterate through stored users to validate login
            for user in users:
                user_id, encrypted_name, encrypted_password, security_level = user
                
                # Decrypt the stored username and password
                decrypted_name = decrypt(encrypted_name)
                decrypted_password = decrypt(encrypted_password)

                # Debugging output for verification
                print(f"Decrypted Username: {decrypted_name}, Decrypted Password: {decrypted_password}")

                # Check if the decrypted username and password match the input
                if decrypted_name == username and decrypted_password == password:
                    print("Login successful!")  # Debug statement
                    session['user_id'] = user_id
                    session['username'] = username
                    session['security_level'] = security_level
                    return redirect(url_for('home'))

            # If no match is found
            print("Login failed: Username or password incorrect.")  # Debug statement
            return render_template('login.html', error="Invalid username or password!")
        except Exception as e:
            print(f"An error occurred during login: {e}")  # Debug statement
            return render_template('login.html', error=f"An error occurred: {e}")

    return render_template('login.html')


@app.route('/list_Results')
def list_Results():
    """List all users with decrypted fields."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, age, phone_number, security_level, login_password FROM BakingContestPeople")
    users = cursor.fetchall()
    conn.close()

    # Decrypt sensitive fields
    decrypted_users = []
    for user in users:
        decrypted_user = {
            'id': user[0],
            'name': decrypt(user[1]),
            'age': user[2],
            'phone_number': decrypt(user[3]),
            'security_level': user[4],
            'login_password': decrypt(user[5])
        }
        # Print decrypted values to verify
        #print(f"Decrypted Username: {decrypted_user['name']}, Decrypted Password: {decrypted_user['login_password']}")
        decrypted_users.append(decrypted_user)

    return render_template('list_Results.html', users=decrypted_users)



@app.route('/logout', methods=['GET'])
def logout():
    """Log out the user."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/add_entry', methods=['GET', 'POST'])
def add_entry():
    """Add a baking contest entry."""
    if request.method == 'POST':
        baking_item_name = request.form.get('baking_item_name', '').strip()
        excellent_votes = request.form.get('excellent_votes', '').strip()
        ok_votes = request.form.get('ok_votes', '').strip()
        bad_votes = request.form.get('bad_votes', '').strip()

        errors = []
        if not baking_item_name:
            errors.append("The Name of the Baking Item cannot be empty.")
        if not excellent_votes.isdigit() or int(excellent_votes) < 0:
            errors.append("Number of Excellent Votes must be a non-negative integer.")
        if not ok_votes.isdigit() or int(ok_votes) < 0:
            errors.append("Number of OK Votes must be a non-negative integer.")
        if not bad_votes.isdigit() or int(bad_votes) < 0:
            errors.append("Number of Bad Votes must be a non-negative integer.")

        if errors:
            return render_template('add_entry.html', errors=errors)

        try:
            user_id = session.get('user_id')
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO BakingContestEntries (user_id, baking_item_name, excellent_votes, ok_votes, bad_votes)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                user_id,
                baking_item_name,
                int(excellent_votes),
                int(ok_votes),
                int(bad_votes)
            ))
            conn.commit()
            conn.close()
            success_message = "Entry successfully added."
            return render_template('add_entry.html', success_message=success_message)
        except sqlite3.Error as e:
            return render_template('add_entry.html', errors=[f"Database error: {e}"])

    return render_template('add_entry.html')


@app.route('/my_entries')
def my_entries():
    """Display contest entries submitted by the logged-in user."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        user_id = session['user_id']  # Get the logged-in user's ID
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT baking_item_name, excellent_votes, ok_votes, bad_votes
            FROM BakingContestEntries
            WHERE user_id = ?
        ''', (user_id,))
        entries = cursor.fetchall()
        conn.close()

        return render_template('myEntries.html', entries=entries)
    except sqlite3.Error as e:
        return f"Database error: {e}"


@app.route('/contest_results')
def contest_results():
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Fetch all contest entries, including encrypted user information
        cursor.execute('''
            SELECT B.entry_id, P.name, B.baking_item_name, B.excellent_votes, B.ok_votes, B.bad_votes
            FROM BakingContestEntries B
            JOIN BakingContestPeople P ON B.user_id = P.id
        ''')
        entries = cursor.fetchall()

        # Decrypt only the user name (2nd field in each entry)
        decrypted_entries = [(entry[0], decrypt(entry[1]), *entry[2:]) for entry in entries]

        conn.close()

        # Pass the entries with decrypted usernames to the template
        return render_template('BakingEntryresults.html', entries=decrypted_entries)

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return f"Database error: {e}"
    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred: {e}"







@app.route('/results')
def UserResults():
    """Display results."""
    return render_template('UserResults.html', msg="Some message")

@app.route('/results')
def BakingEntryresults():
    """Display results."""
    return render_template('BakingEntryresults.html', msg="Some message")



if __name__ == "__main__":
    init_db()
    app.run(host='127.0.0.1', port=50001, debug=True)

"""
def print_user_credentials()
    #Print usernames and passwords from the database, showing both encrypted and decrypted values.
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Query for usernames and passwords
        cursor.execute("SELECT name, login_password FROM BakingContestPeople")
        rows = cursor.fetchall()
        conn.close()

        # Display user credentials
        print("User Credentials:")
        for encrypted_name, encrypted_password in rows:
            try:
                decrypted_name = decrypt(encrypted_name)
                decrypted_password = decrypt(encrypted_password)
                print(f"Encrypted Username: {encrypted_name}, Decrypted Username: {decrypted_name}")
                print(f"Encrypted Password: {encrypted_password}, Decrypted Password: {decrypted_password}")
            except Exception as e:
                print(f"Error decrypting data: {e}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

"""
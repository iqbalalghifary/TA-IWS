from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from flask import send_from_directory #untuk simpan report di server
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.hash import bcrypt
import os
import fitz
import re
import psycopg2
import io
from dotenv import load_dotenv #nambahin env
from datetime import datetime  # Import the datetime module

from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
load_dotenv() #load .env

# Configuring Flask-Mail
app.config['MAIL_SERVER'] = os.environ.get("MAIL_SERVER")
app.config['MAIL_PORT'] = os.environ.get("MAIL_PORT")
app.config['MAIL_USE_TLS'] = os.environ.get("MAIL_USE_TLS")
app.config['MAIL_USE_SSL'] = os.environ.get("MAIL_USE_SSL")
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_DEFAULT_SENDER")
app.config['MAIL_MAX_EMAILS'] = os.environ.get("MAIL_MAX_EMAILS")
app.config['MAIL_SUPPRESS_SEND'] = os.environ.get("MAIL_SUPPRESS_SEND")

mail = Mail(app)

app.secret_key = os.environ.get("SECRET_KEY")
app.config['SECURITY_PASSWORD_SALT'] = 'your_secret_salt_value'

app.config['SESSION_TYPE'] = 'filesystem'

# Database configurations
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL") or 'postgresql://postgres:1234@localhost/lemper'


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
uploads_directory = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/uploads')
reports_directory = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/reports')

# Inisialisasi Flask-Login
# LoginManager menyediakan alat yang sangat membantu dalam manajemen autentikasi pengguna
login_manager = LoginManager()
login_manager.init_app(app)

# Model user
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(255))
    student_id = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))

    def get_id(self):
        return str(self.id)
    
    reports = relationship('Report', backref='user', lazy=True)

# Model report
class Report(db.Model):
    id_report = db.Column(db.Integer, primary_key=True)
    path_file = db.Column(db.String(255), nullable=False)
    tanggal = db.Column(db.DateTime, nullable=False)
    title_report = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)

    # Foreign key to link with User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Model lecturer 
class Lecturer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nip = db.Column(db.String(255), unique=True, nullable=True)
    full_name = db.Column(db.String(255), nullable=True)
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/send_email')
def send_email():
    return render_template('send_email.html')

@app.route('/change_password')
def change_password():
    return render_template('change_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.verify(password, user.password):
            login_user(user)
            flash('Login successful!', 'success')
            session['logged_in'] = True  # Menyimpan status login dalam sesi
            return redirect(url_for('dashboard'))

        flash('Invalid email or password. Please try again.', 'danger')

    return render_template('login.html')

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    session['logged_in'] = False  # Mengubah status login dalam sesi
    return redirect(url_for('login'))

# Function to generate a reset password token
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])
    
# Function to decode a reset password token
def decode_reset_token(token):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'])
        return email
    except Exception as e:
        print(f"Token decoding error: {e}")
        return None

# Forgot Password Route
@app.route('/lupa_password', methods=['GET', 'POST'])
def lupa_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate a token for password reset
            token = generate_reset_token(user.email)

            # Send email with the reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            print(f"Reset Link: {reset_link}")

            message = Message("Password Reset", recipients=[user.email])
            message.body = f"Click the link to reset your password: {reset_link}"
        
            try:
                mail.send(message)
                flash("Password reset link sent to your email.")
            except Exception as e:
                flash(f"Error sending email: {str(e)}", 'error')
                app.logger.error(f"Error sending email: {str(e)}")

        else:
            flash("Email not found.", 'error')

    return render_template('lupa_password.html')

# Password Reset Route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
     # Decode the token to get the user's email
    user_email = decode_reset_token(token)

    if not user_email:
        flash("Invalid token.", 'error')
        return redirect(url_for('login'))

    # Find the user based on the email
    user = User.query.filter_by(email=user_email).first()

    if not user:
        flash("User not found.", 'error')
        return redirect(url_for('login'))

    # TODO: Implement password reset logic here

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            # Update the user's password in the database
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()

            flash("Password reset successfully.", 'success')
            return redirect(url_for('login'))
        else:
            flash("Passwords do not match.", 'error')

    return render_template('reset_password.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        student_id = request.form['student_id']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('login'))

        hashed_password = bcrypt.hash(password)

        new_user = User(full_name=full_name, student_id=student_id, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

# Menampilkan halaman history
@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # Fetch all reports for the current user from the database
    user_reports = Report.query.filter_by(user_id=current_user.id).all()

    # Format the timestamp to a readable string
    formatted_reports = [
        {
            'id': report.id_report,
            'title': report.title_report,
            'status': report.status,
            'file': report.path_file,
            'tanggal': report.tanggal
        }
        for report in user_reports
    ]

    return render_template('dashboard.html', reports=formatted_reports)

# Menampilkan halaman input file pdf
@app.route('/input_file')
@login_required
def input_file(): 
    return render_template('input_file.html')

# Fungsi Pengecekan Judul menggunakan PyMuPDF (MuPDF)
def cek_judul(pdf_path):
    doc = fitz.open(pdf_path)  # membuka file pdf

    results = []  # Inisialisasi list untuk menyimpan hasil pengecekan judul
    word_count_result = "FAIL"  # Inisialisasi hasil default
    ket_status_judul = ""
    get_judul = ""

    for page_num in range(doc.page_count):
        page = doc[page_num]
        text = page.get_text() #ekstraksi atau pengambilan teks dari setiap halaman pdf

        #disini proses pengecekan judul dimulai
        lines = text.split('\n')
        found_disusun_oleh = False # kondisi jika kata "Disusun oleh" tidak ditemukan
        jumlah_kata = 0
       
        for line in lines: # pada setiap halaman, dilakukan pencarian kata 'Disusun oleh' untuk menemukan awal judul.
            if 'Disusun oleh' in line:
                found_disusun_oleh = True
                break

            # Menyimpan teks sebelum 'Disusun oleh'
            get_judul += line + '\n'

            # Hitung jumlah kata sebelum 'Disusun oleh'
            jumlah_kata += len(line.split())

        # Jika sudah ditemukan kata 'Disusun oleh', berhenti dari loop
        if found_disusun_oleh:
            break

    # Cetak judul yang terdeteksi
    print(f"Teks yang diinput :\n{text}")

    # Cetak judul yang terdeteksi
    print(f"Judul :\n{get_judul}")

    # Berikan status sesuai jumlah kata
    if 12 <= jumlah_kata <= 20:
        word_count_result = "PASS"
        ket_status_judul = f"Jumlah kata yang terdeteksi {jumlah_kata} kata. Jumlah kata pada judul sudah sesuai aturan."
        print(f"Status judul : {word_count_result}") #terminal
        print(f"Jumlah kata yang terdeteksi {jumlah_kata} kata. Jumlah kata pada judul sudah sesuai aturan.\n") #terminal
    elif jumlah_kata > 20 or jumlah_kata < 12: #kalau tidak ada judul masuk ke sini
        word_count_result = "FAIL" 
        ket_status_judul = f"Jumlah kata yang terdeteksi {jumlah_kata} kata. Jumlah kata pada judul belum sesuai aturan. seharusnya terdiri dari 12-20 kata"
        print(f"Status judul : {word_count_result}") #terminal
        print(f"Jumlah kata yang terdeteksi {jumlah_kata} kata. Jumlah kata pada judul belum sesuai aturan.\n") #terminal

    doc.close()
    return results, word_count_result, ket_status_judul if 'ket_status_judul' in locals() else "Kalimat 'Disusun oleh' tidak ditemukan"

def cek_identitas_kaprodi(pdf_path):
    try:
        start_keyword = "ketua" 
        pdf_document = fitz.open(pdf_path)

        # default
        match_found = False
        status_kaprodi = "FAIL"
        ket_status_kaprodi = "Nama dan Gelar Ketua Prodi tidak ditemukan"
        status_nip_kaprodi = "FAIL"
        ket_status_nip_kaprodi = "NIP Ketua Prodi tidak ditemukan"
        numbers = []

        for page_num in range(pdf_document.page_count):
            page = pdf_document[page_num]
            page_text = page.get_text()

            start_index = page_text.lower().find(start_keyword)
            if start_index != -1:
                extracted_text = page_text[start_index + len(start_keyword):].strip() #Jika kata kunci ditemukan, teks setelahnya diekstrak untuk pencarian lebih lanjut.
                print(f"\nrange text untuk pencarian kaprodi:\n{extracted_text}") 

                pattern_santi = r'Santi Sundari, S\.Si\., M\.T\.'
                pattern_ghifari = r'Ghifari Munawar, S\.Kom\., M\.T\.'

                match_santi = re.search(pattern_santi, extracted_text) #re.search() digunakan untuk mencari pola regex dalam teks extracted_text.
                match_ghifari = re.search(pattern_ghifari, extracted_text)

                if match_santi:
                    match_found = True
                    remaining_text = extracted_text[match_santi.end():]
                    numbers = re.findall(r'\d+', remaining_text)
                    status_kaprodi = "PASS"
                    ket_status_kaprodi = f"Nama Ketua Prodi sesuai dengan data dosen!"
                    print(f"NIP Ketua Prodi yang ditemukan: {numbers}")
                    print(f"Nama ditemukan di halaman {page_num + 1}: Santi Sundari, S.Si., M.T.")

                elif match_ghifari:
                    match_found = True
                    remaining_text = extracted_text[match_ghifari.end():] #remaining_text menyimpan text setelah match ghifari
                    numbers = re.findall(r'\d+', remaining_text) #dari remaining_text diambil angkanya saja
                    status_kaprodi = "PASS"
                    ket_status_kaprodi = f"Nama Ketua Prodi sesuai dengan data dosen!"
                    print(f"NIP Ketua Prodi yang ditemukan: {numbers}")
                    print(f"Nama ditemukan di halaman {page_num + 1}: Ghifari Munawar, S.Kom., M.T.")

        # Mencocokkan nomor dengan nip pada tabel
        # Mencocokkan nomor dengan nip pada tabel
        for number in numbers:
            lecturer = None

            if match_santi:
                lecturer = Lecturer.query.filter(
                    Lecturer.nip == number,
                    Lecturer.full_name == 'Santi Sundari, S.Si., M.T.'
                ).first()
            elif match_ghifari:
                lecturer = Lecturer.query.filter(
                    Lecturer.nip == number,
                    Lecturer.full_name == 'Ghifari Munawar, S.Kom., M.T.'
                ).first()

            if lecturer:
                print(f"NIP {number} sudah benar. Nama: {lecturer.full_name}")
                status_nip_kaprodi = "PASS"
                ket_status_nip_kaprodi = f"NIP Pembimbing sudah tepat! NIP yang terdeteksi : {number}"
            else:
                print(f"NIP {number} tidak ditemukan dalam tabel lecturer.")
                status_nip_kaprodi = "FAIL"
                ket_status_nip_kaprodi = f"NIP Pembimbing belum tepat! NIP yang terdeteksi : {number} Seharusnya NIP Pembimbing D4 : NIP Pembimbing D3 : "

        if not match_found:
            status_kaprodi = "FAIL"
            ket_status_kaprodi = f"Data tidak sesuai dengan data nama lengkap dan gelar Ketua Prodi!"
            print("Data tidak sesuai dengan data nama lengkap dan gelar Ketua Prodi!")
            status_nip_kaprodi = "FAIL"
            ket_status_nip_kaprodi = "Data tidak sesuai dengan data NIP Ketua Prodi"
            print("Data tidak sesuai dengan data NIP Ketua Prodi!")
        
        pdf_document.close()
        
        return status_kaprodi, ket_status_kaprodi, status_nip_kaprodi, ket_status_nip_kaprodi

    except Exception as e:
        return str(e)

def cek_dosbing(pdf_path, keyword_start, keyword_end, database_url):
    # Set the start and end keywords
    start_keyword = keyword_start
    end_keyword = keyword_end

    # Buka file PDF
    pdf_document = fitz.open(pdf_path)

    # Inisialisasi teks hasil ekstraksi
    extracted_text = ""

    # Loop melalui setiap halaman dan ekstrak teks
    for page_number in range(pdf_document.page_count):
        page = pdf_document[page_number]
        page_text = page.get_text()

        # Cari indeks kata kunci awal
        start_index = page_text.find(start_keyword)

        # Cari indeks kata kunci akhir
        end_index = page_text.find(end_keyword)

        # Ekstrak teks di antara dua kata kunci (jika ditemukan)
        if start_index != -1 and end_index != -1:
            extracted_text += page_text[start_index + len(start_keyword):end_index].strip()

    # Tutup file PDF
    pdf_document.close()

    # Create a SQLAlchemy engine
    engine = create_engine(database_url)

    # Connect to the database using the engine
    with engine.connect() as connection:
        # Use SQLAlchemy text() function to create a text-based SQL query
        query = text('SELECT full_name FROM lecturer')

        # Execute the query
        result_set = connection.execute(query)

        # List to store similar keywords
        similar_keywords = []

        # Iterate through the database results
        for row in result_set:
            nama_database = row[0]
            
            # Check if the database keyword is present in the extracted text
            if nama_database in extracted_text:
                similar_keywords.append(nama_database)

    # Display similar keywords
    if similar_keywords:
        keterangan = f"Penulisan Pembimbing Jurusan sudah sesuai dengan data dosen!"
        for keyword in similar_keywords:
            print(keyword)
            print('PASS')
            status_nama_dosbing = "PASS"
    else:
        keterangan = f"Penulisan Pembimbing Jurusan belum sesuai dengan data dosen!"
        print('FAIL')
        status_nama_dosbing = "FAIL"
    return status_nama_dosbing, keterangan

def cek_nip_dosbing(pdf_path, start_keyword, end_keyword, database_url):
    # Initialize variables with default values
    status_nip_dosbing = "FAIL"
    ket_nip_dosbing = "NIP Dosbing tidak ditemukan"
    
    def extract_text_from_pdf(pdf_path):
        pdf_document = fitz.open(pdf_path)
        text = ""

        for page_number in range(pdf_document.page_count):
            page = pdf_document[page_number]
            page_text = page.get_text()
            text += page_text

        pdf_document.close()
        return text

    def fetch_full_names_from_database(database_url):
        try:
            engine = create_engine(database_url)
            Session = sessionmaker(bind=engine)
            session = Session()

            result = session.execute(text("SELECT full_name FROM lecturer"))
            full_names = [row[0] for row in result.fetchall()]

            return full_names

        except Exception as error:
            print("Error while connecting to the database:", error)

        finally:
            session.close()

    def extract_nip_from_pdf(pdf_path):
        pdf_document = fitz.open(pdf_path)
        text = ""

        for page_number in range(pdf_document.page_count):
            page = pdf_document[page_number]
            page_text = page.get_text()
            text += page_text

        pdf_document.close()

        nip_match = re.search(r'NIP\.?\s*(\d+)', text)
        if nip_match:
            extracted_nip = nip_match.group(1)
            return extracted_nip
        else:
            return None

    pdf_text = extract_text_from_pdf(pdf_path)

    start_index = pdf_text.find(start_keyword)
    end_index = pdf_text.find(end_keyword)

    if start_index != -1 and end_index != -1:
        extracted_text = pdf_text[start_index + len(start_keyword):end_index].strip()

        full_names_from_db = fetch_full_names_from_database(database_url)

        matching_names = [name for name in full_names_from_db if any(word.lower() in name.lower() for word in extracted_text.split())]

        if matching_names:
            best_match = None
            max_matching_words = 0

            for matching_name in matching_names:
                matching_words = [word for word in matching_name.split() if word.lower() in extracted_text.lower()]
                if len(matching_words) > max_matching_words:
                    best_match = matching_name
                    max_matching_words = len(matching_words)

            if best_match:
                try:
                    engine = create_engine(database_url)
                    Session = sessionmaker(bind=engine)
                    session = Session()

                    result = session.execute(text("SELECT nip FROM lecturer WHERE full_name = :name"), {"name": best_match})
                    nip_result = result.fetchone()

                    if nip_result:
                        print(f"Seharusnya NIP ditulis: {nip_result[0]}")

                        extracted_nip_same = extract_nip_from_pdf(pdf_path)

                        if extracted_nip_same:
                            print(f"NIP yang anda tulis: {extracted_nip_same}")

                            if extracted_nip_same == nip_result[0]:
                                status_nip_dosbing = "PASS"
                                ket_nip_dosbing = f"NIP sudah tepat. NIP yang terdeteksi : {extracted_nip_same}"
                            else:
                                status_nip_dosbing = "FAIL"
                                ket_nip_dosbing = f"NIP belum tepat. NIP yang terdeteksi : {extracted_nip_same}. Seharusnya {nip_result[0]}"
                        else:
                            print("NIP tidak ditemukan pada laporan")
                    else:
                        print("NIP tidak ditemukan pada database")

                except Exception as error:
                    print("Error while connecting to the database:", error)

                finally:
                    session.close()

            else:
                print("No Matching Words Found")
        else:
            print("\nNo Matching Names Found in Database")
    else:
        print("Keywords not found in the extracted text.")
    return status_nip_dosbing, ket_nip_dosbing

@app.route('/save_pdf', methods=['POST'])
def save_pdf():
    pdf_file = request.files['pdf_file']

    if pdf_file:
        # Membuat nama file PDF yang unik dengan user name dan report ID
        report = Report.query.filter_by(user_id=current_user.id).order_by(Report.id_report.desc()).first()
        report_id = report.id_report if report else 1  # Default to 1 if no report found

        # Membuat nama file PDF yang unik dengan user name
        pdf_filename = f"Report_{current_user.full_name}_versi_{report_id}.pdf"

        pdf_path = os.path.join(reports_directory, pdf_filename)

        # Simpan file PDF di direktori reports_directory
        pdf_file.save(pdf_path)

        title = session.get('title', '')  # Retrieve title from the session
        ket_fail_count = session.get('ket_fail_count', '')  # Retrieve ket_fail_count from the session

        # Insert data into the Report table
        report = Report(
            path_file=f"{url_for('static', filename='reports')}/{pdf_filename}",
            tanggal=datetime.now(),
            title_report=title,  # Use the retrieved title
            status=ket_fail_count,  # Use the retrieved ket_fail_count
            user=current_user  # Assuming you have the current_user object available
        )

        db.session.add(report)
        db.session.commit()

        return jsonify({'filename': pdf_filename})
    else:
        return jsonify({'error': 'No PDF file received'}), 400

def count_fail_occurrences(*args):
    fail_count = sum(1 for status in args if status == 'FAIL')
    return fail_count
    
@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files['pdf_file']

    if uploaded_file.filename != '':
        # Simpan file PDF yang diunggah di server
        pdf_path = os.path.join(uploads_directory, uploaded_file.filename)
        uploaded_file.save(pdf_path)
        database_url = os.environ.get("DATABASE_URL")

        # mengambil nama dan nim user untuk ditampilkan pada report
        user_name = current_user.full_name
        user_nim = current_user.student_id

        # Tangkap nilai 'Title' dari formulir
        title = request.form.get('title')
        #biar bisa ditangkap di route save pdf
        session['title'] = title  # Store title in the session

        # Set the start and end keywords untuk cek nama dosbing
        start_keyword = 'Pembimbing'
        end_keyword = 'NIP'

        # Lakukan pengecekan judul
        title_messages, word_count_result, ket_status_judul = cek_judul(pdf_path)

        # Lakukan pengecekan nama dosbing
        status_nama_dosbing, keterangan = cek_dosbing(pdf_path, start_keyword, end_keyword, database_url)

        # Lakukan pengecekan nip dosbing
        status_nip_dosbing, ket_nip_dosbing = cek_nip_dosbing(pdf_path, start_keyword, end_keyword, database_url)

        # Lakukan pengecekan kaprodi
        status_kaprodi, ket_status_kaprodi, status_nip_kaprodi, ket_status_nip_kaprodi = cek_identitas_kaprodi(pdf_path)

        # Display the values in the terminal
        print("word_count_result:", word_count_result)
        print("status_nama_dosbing:", status_nama_dosbing)
        print("status_nip_dosbing:", status_nip_dosbing)
        print("status_kaprodi:", status_kaprodi)
        print("status_nip_kaprodi:", status_nip_kaprodi)

        # Count 'FAIL' occurrences
        fail_count = count_fail_occurrences(word_count_result, status_nama_dosbing, status_nip_dosbing, status_kaprodi, status_nip_kaprodi)

        # keterangan total salah
        ket_fail_count = f"{fail_count} FAIL"
        session['ket_fail_count'] = ket_fail_count  # Store ket_fail_count in the session

        # Print the total count
        print(f"Total 'FAIL' occurrences: {fail_count}")

        # Check if there are no errors
        if fail_count == 0:
            print("Tidak ada kesalahan")

    #Data ini disampaikan langsung ke template report.html sebagai argumen dari fungsi render_template, jadi tidak disimpan di server
    return render_template('report.html', title_messages=title_messages, user_name=user_name, user_nim=user_nim, word_count_result=word_count_result, ket_status_judul=ket_status_judul, status_nama_dosbing=status_nama_dosbing, keterangan=keterangan, status_nip_dosbing=status_nip_dosbing, ket_nip_dosbing=ket_nip_dosbing, status_kaprodi=status_kaprodi, ket_status_kaprodi=ket_status_kaprodi, status_nip_kaprodi=status_nip_kaprodi, ket_status_nip_kaprodi=ket_status_nip_kaprodi, fail_count=fail_count)

if __name__ == '__main__':
    app.run()


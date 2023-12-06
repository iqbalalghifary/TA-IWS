from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
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


app = Flask(__name__)
load_dotenv() #load .env

app.secret_key = os.environ.get("SECRET_KEY")
app.config['SESSION_TYPE'] = 'filesystem'

# Database configurations
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")

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

@app.route('/send_email')
def lupa_password():
    return render_template('send_email.html')

@app.route('/change_password')
def change_password():
    return render_template('change_password.html')
    
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

        flash('You are now registered and can log in.', 'success')
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

# Fungsi Pengecekan Judul
def cek_judul(pdf_path):
    doc = fitz.open(pdf_path) #buka pdf

    results = []  # Inisialisasi list untuk menyimpan hasil pengecekan judul

    for page_num in range(doc.page_count):
        page = doc[page_num]
        text = page.get_text()

        lines = text.split('\n')
        previous_lines = []

        for line in lines:
            if not line.strip():
                # Jika menemukan baris baru kosong, tambahkan bagian sebelumnya ke list results
                if previous_lines:
                    result = ' '.join(previous_lines)
                    print(result) # print judul yang terdeteksi

                    # Hitung jumlah kata pada variabel result
                    word_count = len(result.split())
                    results.append(f"Jumlah kata pada judul laporan anda: {word_count}")

                    # Berikan status sesuai jumlah kata
                    if 12 <= word_count <= 20:
                        word_count_result = "PASS"
                        print(word_count_result) # ini untuk liat hasil di terminal aja
                        note = f"Jumlah kata yang terdeteksi {word_count} kata. Penulisan judul sudah sesuai aturan"
                        print(note) # ini untuk liat hasil di terminal aja
                    elif word_count == 1:
                        word_count_result = "Perbaiki posisi penomoran halaman"
                    elif word_count > 20 or word_count < 12:
                        word_count_result = "FAIL"
                        print(word_count_result) # ini untuk liat hasil di terminal aja
                        note = f"Jumlah kata yang terdeteksi {word_count} kata. Penulisan Judul belum sesuai aturan"
                        print(note) # ini untuk liat hasil di terminal aja
                    doc.close()
                    return results, word_count_result, note  # Mengembalikan list hasil
                previous_lines = []
            else:
                previous_lines.append(line)

    doc.close()
    results.append(f"Tidak ditemukan baris baru kosong.")

def cek_identitas_kaprodi(pdf_path):
    try:
        start_keyword = "ketua" 
        pdf_document = fitz.open(pdf_path)
        match_found = False

        status_kaprodi = "FAIL"
        ket_status_kaprodi = ""
        status_nip_kaprodi = "FAIL"
        ket_status_nip_kaprodi = ""
        numbers = []

        for page_num in range(pdf_document.page_count):
            page = pdf_document[page_num]
            page_text = page.get_text()

            start_index = page_text.lower().find(start_keyword)
            if start_index != -1:
                extracted_text = page_text[start_index + len(start_keyword):].strip()
                print(f"lingkup text untuk pencarian kaprodi: {extracted_text}") 

                pattern_santi = r'Santi Sundari, S\.Si\., M\.T\.'
                pattern_ghifari = r'Ghifari Munawar, S\.Kom\., M\.T\.'

                match_santi = re.search(pattern_santi, extracted_text)
                match_ghifari = re.search(pattern_ghifari, extracted_text)

                if match_santi:
                    match_found = True
                    remaining_text = extracted_text[match_santi.end():]
                    numbers = re.findall(r'\d+', remaining_text)
                    status_kaprodi = "PASS"
                    ket_status_kaprodi = f"Nama Ketua Prodi sesuai dengan data dosen!"
                    print(f"nama yang ditemukan: {remaining_text}")
                    print(f"Nama ditemukan di halaman {page_num + 1}: Santi Sundari, S.Si., M.T.")
                    print(f"Angka setelah nama: {numbers}")

                elif match_ghifari:
                    match_found = True
                    remaining_text = extracted_text[match_ghifari.end():]
                    numbers = re.findall(r'\d+', remaining_text)
                    status_kaprodi = "PASS"
                    ket_status_kaprodi = f"Nama Ketua Prodi sesuai dengan data dosen!"
                    print(f"nama yang ditemukan: {remaining_text}")
                    print(f"Nama ditemukan di halaman {page_num + 1}: Ghifari Munawar, S.Kom., M.T.")
                    print(f"Angka setelah nama: {numbers}")

        # Mencocokkan nomor dengan nip pada tabel
        for number in numbers:
            lecturer = Lecturer.query.filter_by(nip=number).first()
            if lecturer:
                print(f"NIP {number} sudah benar. Nama: {lecturer.full_name}")
                status_nip_kaprodi = "PASS"
                ket_status_nip_kaprodi = f"NIP Ketua Prodi sudah tepat!"
            else:
                print(f"NIP {number} tidak ditemukan dalam tabel lecturer.")
                status_nip_kaprodi = "FAIL"
                ket_status_nip_kaprodi = f"NIP Ketua Prodi belum tepat!"

        if not match_found:
            print("Nama tidak ditemukan dalam file PDF.")
            status_kaprodi = "FAIL"
            ket_status_kaprodi = f"Nama Ketua Prodi belum sesuai dengan data dosen."
        
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
        # Membuat nama file PDF yang unik dengan user name
        pdf_filename = f"report_{current_user.full_name}.pdf" #inipenamaan file nya perlu diganti 
        pdf_path = os.path.join(reports_directory, pdf_filename)

        # Simpan file PDF di direktori reports_directory
        pdf_file.save(pdf_path)

        # Insert data into the Report table
        report = Report(
            path_file=f"{url_for('static', filename='reports')}/{pdf_filename}",
            tanggal=datetime.now(),
            title_report="Your Title Here",  # You need to set an appropriate title
            status="Pending",  # You may set the initial status as "Pending" or customize as needed
            user=current_user  # Assuming you have the current_user object available
        )

        db.session.add(report)
        db.session.commit()

        return jsonify({'filename': pdf_filename})
    else:
        return jsonify({'error': 'No PDF file received'}), 400

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

        # Set the start and end keywords untuk cek nama dosbing
        start_keyword = 'Pembimbing'
        end_keyword = 'NIP'

        # Lakukan pengecekan judul
        title_messages, word_count_result, note = cek_judul(pdf_path)

        # Lakukan pengecekan nama dosbing
        status_nama_dosbing, keterangan = cek_dosbing(pdf_path, start_keyword, end_keyword, database_url)

        # Lakukan pengecekan nip dosbing
        status_nip_dosbing, ket_nip_dosbing = cek_nip_dosbing(pdf_path, start_keyword, end_keyword, database_url)
       

        #Lakukan pengecekan kaprodi
        status_kaprodi, ket_status_kaprodi, status_nip_kaprodi, ket_status_nip_kaprodi = cek_identitas_kaprodi(pdf_path)

        # Lakukan pengecekan kaprodi
        # deteksi_nama(pdf_path)
     
        os.remove(pdf_path)  # Hapus file setelah digunakan

    return render_template('report.html', title_messages=title_messages, user_name=user_name, user_nim=user_nim, word_count_result=word_count_result, note=note, status_nama_dosbing=status_nama_dosbing, keterangan=keterangan, status_nip_dosbing=status_nip_dosbing, ket_nip_dosbing=ket_nip_dosbing, status_kaprodi=status_kaprodi, ket_status_kaprodi=ket_status_kaprodi, status_nip_kaprodi=status_nip_kaprodi, ket_status_nip_kaprodi=ket_status_nip_kaprodi)

if __name__ == '__main__':
    app.run()


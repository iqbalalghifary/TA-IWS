from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from passlib.hash import bcrypt
import os
import fitz
import re

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from flask import make_response
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Ganti dengan kunci rahasia yang kuat
app.config['SESSION_TYPE'] = 'filesystem'

# Konfigurasi database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost/lemper'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
uploads_directory = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/uploads')

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

@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

def count_words_in_pdf_before_keyword(pdf_path, keyword):
    # algoritma pengecekan
    try:
            # Buka file PDF
            pdf_document = fitz.open(pdf_path)

            # Inisialisasi variabel untuk menyimpan teks dari PDF
            pdf_text = ""

            # Ekstrak teks dari semua halaman PDF
            for page_num in range(len(pdf_document)):
                page = pdf_document[page_num]
                page_text = page.get_text()
                pdf_text += page_text

                # Hentikan ekstraksi setelah menemukan kata kunci
                if keyword in page_text:
                    break

            # Tutup file PDF
            pdf_document.close()

            # Pemotongan teks hingga sebelum kata kunci
            index = pdf_text.find(keyword)
            if index != -1:
                pdf_text = pdf_text[:index]

             # Menghitung jumlah kata dalam teks PDF
            words = pdf_text.split()
            word_count = len(words)

            # Menentukan pesan berdasarkan jumlah kata
            if 12 <= word_count <= 20:
                return "Pass"
            else:
               return f"Fail.Penulisan judul tidak sesuai aturan, tolong perbaiki kembali! Jumlah kata: {word_count}, seharusnya di antara 12-20 kata."

    except Exception as e:
        return str(e)

def get_dosbing(pdf_path):
    try:
        # Buka file PDF
        doc = fitz.open(pdf_path)

        # Ambil teks dari halaman pertama
        page = doc[0]
        text = page.get_text("text")

        # Cari teks "Pembimbing JTK Polban" dan "Pembimbing Industri"
        pembimbing_jtk_index = text.find("Pembimbing JTK Polban")
        pembimbing_industri_index = text.find("Pembimbing Industri")

        if pembimbing_jtk_index != -1 and pembimbing_industri_index != -1:
            # Ambil teks di antara "Pembimbing JTK Polban" dan "Pembimbing Industri" sebagai nama pembimbing JTK
            nama_pembimbing_jtk = text[pembimbing_jtk_index + len("Pembimbing JTK Polban"): pembimbing_industri_index].strip()
            # Hapus NIP dari teks nama pembimbing JTK
            nama_pembimbing_jtk_clean = nama_pembimbing_jtk.split('NIP')[0].strip()

            # Cocokkan pola regex
            match = re.match(r'^[A-Za-z]+(?:\s[A-Za-z]+){1,}\s(?:[A-Za-z]+\.\s?){2}$', nama_pembimbing_jtk_clean)
            
            if match:
                return match.group()
            else:
                return match.group()

        elif pembimbing_industri_index != -1:
            # Ambil teks di antara "Pembimbing Industri" dan "NIP" jika tidak ada teks di antara "Pembimbing JTK Polban" dan "Pembimbing Industri"
            nama_pembimbing_industri_index = text.find("Pembimbing Industri")
            nip_index = text.find("NIP")
            nama_pembimbing_industri = text[nama_pembimbing_industri_index + len("Pembimbing Industri"): nip_index].strip()

            # Cocokkan pola regex
            match = re.match(r'^[A-Za-z]+(?:\s[A-Za-z]+){1,}\s(?:[A-Za-z]+\.\s?){2}$', nama_pembimbing_industri)
            
            if match:
                return match.group()
            else:
                return match.group()

        else:
            return "Tidak ada informasi pembimbing"

    except Exception as e:
        return str(e)

def cek_nip(numbers):
    try:
        # Mencocokkan nomor dengan nip pada tabel
        for number in numbers:
            lecturer = Lecturer.query.filter_by(nip=number).first()
            if lecturer:
                print(f"NIP {number} sudah benar. Nama: {lecturer.full_name}")
            else:
                print(f"NIP {number} tidak ditemukan dalam tabel lecturer.")

    except Exception as e:
        print(f"Error: {e}")

def deteksi_nama(pdf_path):
    try:
        pdf_document = fitz.open(pdf_path)

        pattern_santi = r'Santi Sundari, S\.Si\., M\.T\.'
        pattern_ghifari = r'Ghifari Munawar, S\.Kom\., M\.T\.'

        match_found = False

        for page_num in range(pdf_document.page_count):
            page = pdf_document[page_num]
            text = page.get_text()

            match_santi = re.search(pattern_santi, text)
            match_ghifari = re.search(pattern_ghifari, text)

            if match_santi:
                match_found = True
                # Extract text after the matched pattern
                remaining_text = text[match_santi.end():]
                # Extract only numerical values using regular expression
                numbers = re.findall(r'\d+', remaining_text)
                print(f"Nama ditemukan di halaman {page_num + 1}: Santi Sundari, S.Si., M.T.")
                print(f"Angka setelah nama: {numbers}")
                cek_nip(numbers)
            if match_ghifari:
                match_found = True
                remaining_text = text[match_ghifari.end():]
                numbers = re.findall(r'\d+', remaining_text)
                print(f"Nama ditemukan di halaman {page_num + 1}: Ghifari Munawar, S.Kom., M.T.")
                print(f"Angka setelah nama: {numbers}")
                cek_nip(numbers)

        pdf_document.close()

        if not match_found:
            print("Nama tidak ditemukan dalam file PDF.")

    except Exception as e:
        return str(e)

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files['pdf_file']

    if uploaded_file.filename != '':
        # Simpan file PDF yang diunggah di server
        pdf_path = os.path.join(uploads_directory, uploaded_file.filename)
        uploaded_file.save(pdf_path)

        deteksi_nama(pdf_path)

        # Lakukan perhitungan
        # keyword = 'Disusun oleh'
        # title_message = count_words_in_pdf_before_keyword(pdf_path, keyword)
     
        os.remove(pdf_path)  # Hapus file setelah digunakan
            
        # Create a PDF receipt with the message and user's name
        # output = io.BytesIO()

        # Create a SimpleDocTemplate with custom margins
        # doc = SimpleDocTemplate(output, pagesize=letter, leftMargin=1 * inch, rightMargin=1 * inch, topMargin=1 * inch, bottomMargin=1 * inch)

         # Assuming the user's name is stored in 'current_user.full_name' (modify as needed)
        # user_name = current_user.full_name
        # user_nim = current_user.student_id

        # Create a list of flowables (content elements)
        # styles = getSampleStyleSheet()
        # elements = []

        # Add the user's name and the analysis result to the elements list
        # elements.append(Paragraph("Report Hasil Pengecekan", styles['Title']))
        # elements.append(Spacer(1, 0.2 * inch))
        # elements.append(Paragraph(f"Nama Mahasiswa: {user_name}", styles['Normal']))
        # elements.append(Paragraph(f"NIM: {user_nim}", styles['Normal']))
        # elements.append(Spacer(1, 0.2 * inch))

        # status 1
        # elements.append(Paragraph("Status Judul:", styles['Normal']))
        # Create a custom paragraph style for the analysis result with word wrapping
        # analysis_style = ParagraphStyle(name='AnalysisStyle', parent=styles['Normal'])
        # analysis_style.wordWrap = 'CJK'
        # Add the analysis result with word wrapping to the elements list
        # analysis_result = Paragraph(title_message, analysis_style)
        # elements.append(analysis_result)

        # status 2
        # elements.append(Paragraph("Status Nama lengkap dan Gelar Pembimbing Jurusan:", styles['Normal']))

        # status 3
        # elements.append(Paragraph("Status NIP Pembimbing Jurusan:", styles['Normal']))

        # status 4
        # elements.append(Paragraph("Status Nama lengkap dan Gelar Ketua Prodi:", styles['Normal']))

        # status 5
        # elements.append(Paragraph("Status NIP Ketua Prodi:", styles['Normal']))


        # Build the PDF document
        # doc.build(elements)

        # output.seek(0)

        # response = make_response(output.read())
        # response.headers['Content-Type'] = 'application/pdf'
        # response.headers['Content-Disposition'] = f'inline; filename=analysis_receipt.pdf'

        # return response

    return render_template('report.html')

if __name__ == '__main__':
    app.run()

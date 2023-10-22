from flask import Flask, render_template, request, redirect, url_for
import psycopg2

app = Flask(__name)

# Konfigurasi PostgreSQL
db_config = {
    'host': 'localhost',
    'user': 'postgres',
    'password': 'iqbal',
    'dbname': 'lemper_checker'
}

def is_valid_registration_data(name, student_id, email, password, confirm_password):
    # Lakukan validasi data di sini
    if password != confirm_password:
        return False
    # Tambahkan validasi lain jika diperlukan

    return True

def save_registration_data(name, student_id, email, password):
    try:
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, student_id, email, password) VALUES (%s, %s, %s, %s)", (name, student_id, email, password))
        conn.commit()
    except psycopg2.Error as e:
        conn.rollback()
        print("Error: ", e)
    finally:
        conn.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        student_id = request.form['student_id']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Lakukan validasi data di sini, misalnya, pastikan password dan konfirmasi password sama

        # Simpan data registrasi ke database (gunakan SQLAlchemy atau psycopg2)

        # Redirect ke halaman login atau halaman terima kasih setelah registrasi berhasil
        return redirect(url_for('login'))

    return render_template('register.html')

if __name__ == '__main__':
    app.run()

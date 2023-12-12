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

        # Print the total count
        print(f"Total 'FAIL' occurrences: {fail_count}")

        # Check if there are no errors
        if fail_count == 0:
            print("Tidak ada kesalahan")

        # Simpan 'Title' bersama dengan file ke dalam tabel Report
        new_report = Report(
            path_file=f"{url_for('static', filename='reports')}/{uploaded_file.filename}",
            tanggal=datetime.now(),
            title_report=title,  # Simpan 'Title'
            status=ket_fail_count,  # Set status sesuai kebutuhan
            user=current_user
        )

        db.session.add(new_report)
        db.session.commit()

        os.remove(pdf_path)  # Hapus file setelah digunakan

    return render_template('report.html', title_messages=title_messages, user_name=user_name, user_nim=user_nim, word_count_result=word_count_result, ket_status_judul=ket_status_judul, status_nama_dosbing=status_nama_dosbing, keterangan=keterangan, status_nip_dosbing=status_nip_dosbing, ket_nip_dosbing=ket_nip_dosbing, status_kaprodi=status_kaprodi, ket_status_kaprodi=ket_status_kaprodi, status_nip_kaprodi=status_nip_kaprodi, ket_status_nip_kaprodi=ket_status_nip_kaprodi, fail_count=fail_count)

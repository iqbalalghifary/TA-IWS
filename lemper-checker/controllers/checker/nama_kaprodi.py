import fitz

def cek_identitas_kaprodi(pdf_path):
    try:
        start_keyword = "ketua" 
        pdf_document = fitz.open(pdf_path)

        # default
        match_found = False
        status_kaprodi = "FAIL"
        ket_status_kaprodi = ""
        status_nip_kaprodi = "FAIL"
        ket_status_nip_kaprodi = "NIP tidak sesuai"
        numbers = []

        for page_num in range(pdf_document.page_count):
            page = pdf_document[page_num]
            page_text = page.get_text()

            start_index = page_text.lower().find(start_keyword)
            if start_index != -1:
                extracted_text = page_text[start_index + len(start_keyword):].strip() #Jika kata kunci ditemukan, teks setelahnya diekstrak untuk pencarian lebih lanjut.
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
                ket_status_nip_kaprodi = f"NIP Ketua Prodi belum tepat!Seharusnya NIP Ketua Prodi D4 : NIP Ketua Prodi D3 : "

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
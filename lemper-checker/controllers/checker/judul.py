import fitz

def cek_judul(pdf_path):
    doc = fitz.open(pdf_path)  # membuka file pdf

    results = []  # Inisialisasi list untuk menyimpan hasil pengecekan judul
    word_count_result = "FAIL"  # Inisialisasi hasil default
    ket_status_judul = ""
    get_judul = ""

    for page_num in range(doc.page_count):
        page = doc[page_num]
        text = page.get_text() #ekstraksi atau pengambilan teks dari setiap halaman pdf

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
    print(f"Judul :\n{get_judul}")

    # Berikan status sesuai jumlah kata
    if 12 <= jumlah_kata <= 20:
        word_count_result = "PASS"
        ket_status_judul = f"Jumlah kata yang terdeteksi {jumlah_kata} kata. Jumlah kata pada judul sudah sesuai aturan."
        print(f"Status judul : {word_count_result}") #terminal
        print(f"Jumlah kata yang terdeteksi {jumlah_kata} kata. Jumlah kata pada judul sudah sesuai aturan.\n") #terminal
    elif jumlah_kata > 20 or jumlah_kata < 12: #kalau tidak ada judul masuk ke sini
        word_count_result = "FAIL" 
        ket_status_judul = f"Jumlah kata yang terdeteksi {jumlah_kata} kata. Jumlah kata pada judul belum sesuai aturan."
        print(f"Status judul : {word_count_result}") #terminal
        print(f"Jumlah kata yang terdeteksi {jumlah_kata} kata. Jumlah kata pada judul sudah sesuai aturan.\n") #terminal

    doc.close()
    return results, word_count_result, ket_status_judul if 'ket_status_judul' in locals() else "Kalimat 'Disusun oleh' tidak ditemukan"

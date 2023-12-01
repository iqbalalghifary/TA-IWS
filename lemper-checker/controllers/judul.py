import fitz

def cek_judul(pdf_path):
    doc = fitz.open(pdf_path)

    for page_num in range(doc.page_count):
        page = doc[page_num]
        text = page.get_text()

        lines = text.split('\n')
        previous_lines = []

        for line in lines:
            if not line.strip():
                # Jika menemukan baris baru kosong, cetak bagian sebelumnya dan keluar dari loop
                if previous_lines:
                    result = ' '.join(previous_lines)
                    print(result)

                    # Hitung jumlah kata pada variabel result
                    word_count = len(result.split())
                    print(f"Jumlah kata pada judul laporan anda: {word_count}")

                    # Berikan status sesuai jumlah kata
                    if 12 <= word_count <= 20:
                        print("Penulisan Judul Sudah Sesuai Aturan")
                    elif word_count == 1:
                        print("Perbaiki posisi penomoran halaman")
                    elif word_count > 20 or word_count < 12:
                        print("Penulisan Judul Belum Sesuai Aturan")

                    doc.close()
                    return result
                previous_lines = []
            else:
                previous_lines.append(line)

    doc.close()
    print("Tidak ditemukan baris baru kosong.")

# Gantilah 'nama_dokumen.pdf' dengan nama dokumen PDF yang ingin Anda proses
pdf_path = 'wildan.pdf'
result = cek_judul(pdf_path)
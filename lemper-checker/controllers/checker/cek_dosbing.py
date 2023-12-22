import fitz
from sqlalchemy import create_engine, text

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
        print("Penulisan pembimbing sudah jurusan sesuai data dosen:")
        for keyword in similar_keywords:
            print(keyword)
            print('PASS')
    else:
        print("Penulisan pembimbing belum sesuai, seharusnya sesuai dengan data dosen!")
        print('FAIL')

# Set the start and end keywords
start_keyword = 'Pembimbing'
end_keyword = 'NIP'

# Set the database URL
database_url = 'postgresql://postgres:iqbal@localhost/lemper'

# Call the extraction and comparison function
cek_dosbing(pdf_file_path, start_keyword, end_keyword, database_url)

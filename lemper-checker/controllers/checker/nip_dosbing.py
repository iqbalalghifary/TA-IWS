from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import fitz
import re

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
                                print("Status: PASS")
                            else:
                                print("Status: FAIL")
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

start_keyword = "Pembimbing"
end_keyword = "NIP"

# Konfigurasi database
database_url = "postgresql+psycopg2://postgres:iqbal@localhost:5432/lemper"

# Panggil fungsi cek_nip
cek_nip_dosbing(pdf_path, start_keyword, end_keyword, database_url)

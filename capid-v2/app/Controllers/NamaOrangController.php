<?php

namespace App\Controllers;

use CodeIgniter\Controller;
use App\Models\NamaOrangModel;

class NamaOrangController extends Controller
{
    public function index()
    {
        return view('nama_orang/form');
    }

    public function cekNama()
    {
        // Validasi file PDF yang diunggah
        $validationRules = [
            'pdf' => 'uploaded[pdf]|ext_in[pdf,pdf]',
        ];

        if (!$this->validate($validationRules)) {
            return redirect()->to('/')->withInput()->with('validation', $this->validator);
        }

        $pdfFile = $this->request->getFile('pdf');

        // Ekstrak teks dari PDF (gunakan pustaka pihak ketiga jika diperlukan)
        $pdfText = $this->extractTextFromPDF($pdfFile);

        // Pisahkan teks menjadi array kata-kata
        $words = explode(' ', $pdfText);

        // Query nama-nama dari database
        $namaModel = new NamaOrangModel();
        $namaOrang = $namaModel->findAll();

        // Periksa apakah nama-nama ada dalam teks PDF
        $hasil = [];
        foreach ($namaOrang as $orang) {
            if (in_array($orang['nama'], $words)) {
                $hasil[$orang['nama']] = 'Sesuai';
            } else {
                $hasil[$orang['nama']] = 'Tidak Sesuai';
            }
        }

        // Tampilkan hasil ke view
        return view('nama_orang/hasil', ['hasil' => $hasil]);
    }

    private function extractTextFromPDF($file)
    {
        // Kode untuk mengekstrak teks dari PDF
        // Anda dapat menggunakan pustaka pihak ketiga seperti `pdf2text` atau `FPDF` untuk melakukan ini.
        // Pastikan Anda telah menginstal pustaka yang sesuai dan mengonfigurasi ini dengan benar.
    }
}

# 🕸️ BPW Stealer
> **[ STATUS: ARCHIVED / RETIRED ]**

---

## ⚠️ OPERATIONAL STATUS: K.I.A (Killed In Action)
**Tanggal Diskontinu:** 12 Desember 2025  
**Penyebab:** Windows Security Update (DPAPI Encryption Overhaul)

> *Catatan Forensik:*  
> Script ini sudah **TIDAK BERFUNGSI** pada versi Windows terbaru pasca-update Desember 2025.  
> Perubahan pada mekanisme enkripsi lokal (DPAPI) membuat ekstraksi master key tidak lagi memungkinkan dengan metode ini.  
> Repository ini dipertahankan hanya sebagai artefak pembelajaran (Proof of Concept).

---

## 📜 DESKRIPSI SINGKAT
`BPW Stealer` adalah sebuah arsenal otomatisasi yang dirancang untuk memanen kredensial dan data sensitif dari puluhan browser berbasis Chromium (Chrome, Edge, Brave, dll) serta Opera. 

Tool ini bekerja secara senyap untuk mendekripsi password, mengumpulkan riwayat selancar, dan mengirimkan hasilnya langsung ke markas komando melalui Telegram API.

---

## 🛠️ AMUNISI (FEATURES)
* **Deep Scrape**  
  Mengekstrak *Login Data* (Email/Password), *History*, *Downloads*, dan *Autofill*.

* **Multi-Browser Support**  
  Mendukung Chrome, Edge (Beta/Dev/Canary), Brave, Vivaldi, Opera GX, Yandex, dan banyak lagi.

* **Stealth Exfiltration**  
  Mengompres semua data menjadi satu file `.zip` dan mengirimkannya via Bot Telegram.

* **Ghost Execution**  
  Dilengkapi dengan `ss.bat` yang menjalankan operasi melalui PowerShell *Hidden Mode* untuk meminimalisir deteksi visual.

---

## ⚙️ KONFIGURASI (SETUP)
*Hanya untuk analisis edukasi.*

Buka `s.py` dan sesuaikan koordinat Telegram pada baris berikut:

---

## 🚀 PROSEDUR EKSEKUSI
Cukup jalankan pelatuknya melalui:  
`ss.bat`

---

### 🔍 Apa yang terjadi di balik layar?

**Infiltrasi**  
Membuka PowerShell dalam mode tersembunyi.

**Deployment**  
Otomatis menginstal library yang dibutuhkan (pycryptodome, requests, pypiwin32).

**Extraction**  
Menjalankan s.py untuk mulai mengais data dari AppData.

**Exfiltration**  
Mengirimkan paket browser_data_report.zip ke Telegram.

---

## 📂 STRUKTUR HASIL PANEN (LOOT)
Jika dijalankan pada sistem yang rentan (Pre-December 2025), data akan tersusun rapi:

Plaintext
```
Browser_Extracted_Data/
├── 🌐 chrome/
│   ├── 👤 Default/
│   │   ├── 🔑 Login Data.txt
│   │   ├── 🕒 History.txt
│   │   └── 📝 Web Data.txt
├── 🌐 msedge/
│   └── 👤 Profile 1/
└── ...
```

---

## ⚖️ DISCLAIMER
Project ini dibuat murni untuk tujuan edukasi dan analisis keamanan (Cybersecurity Research). Penyalahgunaan tool ini untuk kegiatan ilegal di luar tanggung jawab pengembang. Ingat, pertahanan terbaik dimulai dari memahami cara kerja serangan.

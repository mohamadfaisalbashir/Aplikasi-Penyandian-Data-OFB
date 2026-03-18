import os
import sys
import tkinter as tk
from tkinter import filedialog

BLOCK_SIZE = 8

def buat_kunci(kunci_teks):
    kunci_bytes = kunci_teks.encode('utf-8')
    if len(kunci_bytes) == 0:
        kunci_bytes = b'\x00'
    
    while len(kunci_bytes) < BLOCK_SIZE:
        kunci_bytes += kunci_bytes
        
    return kunci_bytes[:BLOCK_SIZE]

def enkripsi(blok, kunci):
    assert len(blok) == BLOCK_SIZE, "Blok harus berukuran 8 byte"
    assert len(kunci) == BLOCK_SIZE, "Kunci harus berukuran 8 byte"
    
    blok_sementara = bytearray(BLOCK_SIZE)
    
    # Substitusi
    for i in range(BLOCK_SIZE):
        blok_sementara[i] = (blok[i] + kunci[i]) % 256
        
    # Transposisi
    blok_sementara = blok_sementara[1:] + blok_sementara[:1]
    
    # Rotasi Bit
    nilai_64bit = int.from_bytes(blok_sementara, byteorder='big')
    nilai_64bit = ((nilai_64bit << 3) & 0xFFFFFFFFFFFFFFFF) | (nilai_64bit >> (64 - 3))
    blok_sementara = bytearray(nilai_64bit.to_bytes(BLOCK_SIZE, byteorder='big'))
    
    # XOR
    for i in range(BLOCK_SIZE):
        blok_sementara[i] = blok_sementara[i] ^ kunci[i]
        
    return bytes(blok_sementara)

def ofb(data, kunci_bytes, iv=None):
    if iv is None:
        iv = os.urandom(BLOCK_SIZE)
        
    feedback = iv
    keystream = bytearray()
    
    for _ in range(0, len(data), BLOCK_SIZE):
        feedback = enkripsi(feedback, kunci_bytes)
        keystream.extend(feedback)
        
    keystream = keystream[:len(data)]
    
    hasil = bytearray(len(data))
    for i in range(len(data)):
        hasil[i] = data[i] ^ keystream[i]
        
    return iv, bytes(hasil)

def pilih_file(judul):
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    filepath = filedialog.askopenfilename(title=judul)
    return filepath

def enkripsi_teks():
    print("\n--- ENKRIPSI TEKS ---")
    teks = input("Masukkan teks yang ingin dienkripsi: ")
    kunci = input("Masukkan kunci: ")
    
    if not teks or not kunci:
        print("Tidak boleh kosong")
        return
        
    data_bytes = teks.encode('utf-8')
    kunci_bytes = buat_kunci(kunci)
    
    iv, ciphertext = ofb(data_bytes, kunci_bytes)
    
    hasil_akhir = iv + ciphertext
    hasil_hex = hasil_akhir.hex()
    
    print("\nBerhasil Dienkripsi")
    print(f"Hasil (Hex): {hasil_hex}")

def dekripsi_teks():
    print("\n--- DEKRIPSI TEKS ---")
    teks_hex = input("Masukkan teks yang terenkripsi (Hex): ")
    kunci = input("Masukkan kunci: ")
    
    if not teks_hex or not kunci:
        print("Tidak boleh kosong")
        return

    try:
        data_mentah = bytes.fromhex(teks_hex)
    except ValueError:
        print("\nFormat Hex tidak valid.")
        return
        
    if len(data_mentah) < BLOCK_SIZE:
        print("Data terlalu pendek.")
        return
   
    kunci_bytes = buat_kunci(kunci)
    
    iv = data_mentah[:BLOCK_SIZE]
    ciphertext = data_mentah[BLOCK_SIZE:]
    
    _, plaintext_bytes = ofb(ciphertext, kunci_bytes, iv)
    
    try:
        hasil_teks = plaintext_bytes.decode('utf-8')
        print("\nBerhasil Didekripsi")
        print(f"Hasil Teks : {hasil_teks}")
    except UnicodeDecodeError:
        print("\nError: Kunci salah atau data rusak.")


def enkripsi_file():
    print("\n--- ENKRIPSI FILE/GAMBAR ---")
    print("Pilih file yang ingin dienkripsi...")
    
    filepath = pilih_file("Pilih file yang ingin dienkripsi")
    
    if not filepath:
        print("Batal memilih file.")
        return
        
    print(f"File terpilih: {filepath}")
    kunci = input("Masukkan kunci (password): ")
    
    if not kunci:
        print("Tidak boleh kosong")
        return
        
    kunci_bytes = buat_kunci(kunci)
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
            
        iv, ciphertext = ofb(data, kunci_bytes)
        
        dir_name, file_name = os.path.split(filepath)
        nama_baru = f"enkripsi_{file_name}"
        path_baru = os.path.join(dir_name, nama_baru)
        
        with open(path_baru, 'wb') as f:
            f.write(iv + ciphertext)
            
        print(f"\nFile dienkripsi dan disimpan sebagai: \n    {path_baru}")
    except Exception as e:
        print(f"Terjadi kesalahan saat memproses file: {e}")

def dekripsi_file():
    print("\n--- DEKRIPSI FILE/GAMBAR ---")
    print("Pilih file yang ingin didekripsi...")
    
    filepath = pilih_file("Pilih File Terenkripsi")
    
    if not filepath:
        print("Batal memilih file.")
        return
        
    print(f"File terpilih: {filepath}")
    kunci = input("Masukkan kunci (password): ")
    
    if not kunci:
        print("Tidak boleh kosong")
        return
        
    kunci_bytes = buat_kunci(kunci)
    
    try:
        with open(filepath, 'rb') as f:
            data_mentah = f.read()
            
        if len(data_mentah) < BLOCK_SIZE:
            print("File terlalu kecil / rusak.")
            return
            
        iv = data_mentah[:BLOCK_SIZE]
        ciphertext = data_mentah[BLOCK_SIZE:]
        
        _, plaintext = ofb(ciphertext, kunci_bytes, iv)
        
        dir_name, file_name = os.path.split(filepath)
        if file_name.startswith("enkripsi_"):
            nama_baru = file_name.replace("enkripsi_", "dekripsi_", 1)
        else:
            nama_baru = f"terdekripsi_{file_name}"
            
        path_baru = os.path.join(dir_name, nama_baru)
        
        with open(path_baru, 'wb') as f:
            f.write(plaintext)
            
        print(f"\nFile didekripsi dan disimpan sebagai: \n    {path_baru}")
    except Exception as e:
         print(f"Terjadi kesalahan saat memproses file: {e}")

def main():
    while True:
        print("\n==============================================")
        print("Penyandian dengan Block Cipher Mode OFB")
        print("==============================================")
        print("1. Enkripsi Teks")
        print("2. Dekripsi Teks")
        print("3. Enkripsi File/Gambar")
        print("4. Dekripsi File/Gambar")
        print("5. Keluar")
        
        pilihan = input("Pilih menu (1-5): ")
        
        if pilihan == '1': enkripsi_teks()
        elif pilihan == '2': dekripsi_teks()
        elif pilihan == '3': enkripsi_file()
        elif pilihan == '4': dekripsi_file()
        elif pilihan == '5':
            print("Terima kasih telah menggunakan aplikasi ini.")
            sys.exit(0)
        else:
            print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
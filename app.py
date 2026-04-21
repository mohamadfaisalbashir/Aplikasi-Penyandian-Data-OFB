BLOCK_SIZE = 8

def buat_kunci(kunci_teks):
    kunci_bytes = kunci_teks.encode("utf-8")
    if len(kunci_bytes) == 0:
        kunci_bytes = b"\x00"

    while len(kunci_bytes) < BLOCK_SIZE:
        kunci_bytes += kunci_bytes

    return kunci_bytes[:BLOCK_SIZE]


SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
)

def enkripsi(blok, kunci):
    assert len(blok) == BLOCK_SIZE, "Blok harus berukuran 8 byte"
    assert len(kunci) == BLOCK_SIZE, "Kunci harus berukuran 8 byte"

    blok_sementara = bytearray(BLOCK_SIZE)

    # Substitusi
    for i in range(BLOCK_SIZE):
        nilai_xor = blok[i] ^ kunci[i]
        
        blok_sementara[i] = SBOX[nilai_xor]

    # Transposisi
    blok_sementara = blok_sementara[1:] + blok_sementara[:1]

    # Rotasi Bit
    nilai_64bit = int.from_bytes(blok_sementara, byteorder="big")
    nilai_64bit = ((nilai_64bit << 3) & 0xFFFFFFFFFFFFFFFF) | (nilai_64bit >> (64 - 3))
    blok_sementara = bytearray(nilai_64bit.to_bytes(BLOCK_SIZE, byteorder="big"))

    # XOR
    for i in range(BLOCK_SIZE):
        blok_sementara[i] = blok_sementara[i] ^ kunci[i]

    return bytes(blok_sementara)


def ofb(data, kunci_bytes, iv=None):
    if iv is None:
        iv_sementara = bytearray(BLOCK_SIZE)
        seed = id(iv_sementara)
        for i in range(BLOCK_SIZE):
            seed = (seed * 1103515245 + 12345) & 0xFFFFFFFF
            iv_sementara[i] = (seed >> 16) & 0xFF
        iv = bytes(iv_sementara)

    feedback = iv
    keystream = bytearray()

    for _ in range(0, len(data), BLOCK_SIZE):
        feedback = enkripsi(feedback, kunci_bytes)
        keystream.extend(feedback)

    keystream = keystream[: len(data)]

    hasil = bytearray(len(data))
    for i in range(len(data)):
        hasil[i] = data[i] ^ keystream[i]

    return iv, bytes(hasil)


def pilih_file(judul):
    print(f"\n{judul}")
    
    while True:
        filepath = input("Masukkan path file: ").strip()
        filepath = filepath.strip('"').strip("'")

        if not filepath:
            print("Input tidak boleh kosong.")
            continue

        try:
            with open(filepath, "rb") as f:
                pass
            return filepath
        except Exception:
            print("File tidak valid atau tidak ditemukan.")
            continue


def split_path(filepath):
    if "/" in filepath:
        return filepath.rsplit("/", 1)
    elif "\\" in filepath:
        return filepath.rsplit("\\", 1)
    else:
        return "", filepath

def join_path(dir_name, file_name, referensi_path):
    if not dir_name:
        return file_name
    sep = "/" if "/" in referensi_path else "\\"
    return f"{dir_name}{sep}{file_name}"


def enkripsi_teks():
    print("\n--- ENKRIPSI TEKS ---")
    teks = input("Masukkan teks yang ingin dienkripsi: ")
    kunci = input("Masukkan kunci: ")

    if not teks or not kunci:
        print("Tidak boleh kosong")
        return

    data_bytes = teks.encode("utf-8")
    kunci_bytes = buat_kunci(kunci)

    iv, ciphertext = ofb(data_bytes, kunci_bytes)

    hasil_akhir = iv + ciphertext
    hasil_hex = hasil_akhir.hex()

    print("\nBerhasil Dienkripsi")
    print(f"Hasil (Hex): {hasil_hex}")


def dekripsi_teks():
    print("\n--- DEKRIPSI TEKS ---")
    teks_hex = input("Masukkan teks yang terenkripsi (Hex): ")
    kunci = input("Masukkan kunci (password): ")

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
        hasil_teks = plaintext_bytes.decode("utf-8")
        print("\nBerhasil Didekripsi")
        print(f"Hasil Teks : {hasil_teks}")
    except UnicodeDecodeError:
        print("\nError: Kunci salah atau data rusak.")


def enkripsi_file():
    print("\n--- ENKRIPSI FILE/GAMBAR ---")
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
        with open(filepath, "rb") as f:
            data = f.read()

        iv, ciphertext = ofb(data, kunci_bytes)

        dir_name, file_name = split_path(filepath)
        nama_baru = f"enkripsi_{file_name}"
        path_baru = join_path(dir_name, nama_baru, filepath)

        with open(path_baru, "wb") as f:
            f.write(iv + ciphertext)

        print(f"\nFile dienkripsi dan disimpan sebagai: \n    {path_baru}")
    except Exception as e:
        print(f"Terjadi kesalahan saat memproses file: {e}")


def dekripsi_file():
    print("\n--- DEKRIPSI FILE/GAMBAR ---")

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
        with open(filepath, "rb") as f:
            data_mentah = f.read()

        if len(data_mentah) < BLOCK_SIZE:
            print("File terlalu kecil / rusak.")
            return

        iv = data_mentah[:BLOCK_SIZE]
        ciphertext = data_mentah[BLOCK_SIZE:]

        _, plaintext = ofb(ciphertext, kunci_bytes, iv)

        dir_name, file_name = split_path(filepath)
        if file_name.startswith("enkripsi_"):
            nama_baru = file_name.replace("enkripsi_", "dekripsi_", 1)
        else:
            nama_baru = f"terdekripsi_{file_name}"

        path_baru = join_path(dir_name, nama_baru, filepath)

        with open(path_baru, "wb") as f:
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

        if pilihan == "1":
            enkripsi_teks()
        elif pilihan == "2":
            dekripsi_teks()
        elif pilihan == "3":
            enkripsi_file()
        elif pilihan == "4":
            dekripsi_file()
        elif pilihan == "5":
            print("Terima kasih telah menggunakan aplikasi ini.")
            break
        else:
            print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
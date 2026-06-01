#  Local Password Vault (Zero-Knowledge C++ Engine)
A mathematically secure, entirely local command-line password manager written in C++.

This project implements a Zero-Knowledge dual-key cryptographic architecture with multi-vault support. Passwords are never stored in plaintext, and the Master Data Encryption Key (DEK) is securely wrapped and locked by a Key Encryption Key (KEK) derived from a user's mental PIN.

# Core Cryptographic Architecture
Encryption Engine: AES-256 (Block Cipher in CBC Mode).

Hashing Engine: SHA-256 (via picosha2).

Key Derivation (PBKDF): The user's PIN is salted, peppered, and subjected to 100,000 rounds of SHA-256 hashing to generate a secure 32-byte Key Encryption Key (KEK).

Dual-Key Wrapping: The vault relies on a 32-byte Data Encryption Key (DEK). This master key is encrypted by the KEK and stored in the file header. If the PIN is wrong, the KEK is wrong, and the DEK decrypts into mathematical garbage.

Initialization Vectors (IV): A unique, hardware-generated 16-byte IV is created for the DEK, and a completely fresh IV is generated for every single payload entry to prevent ciphertext pattern analysis.

Zero-Knowledge Memory: Keys and plaintext passwords exist in RAM exclusively during active execution cycles and are inherently destroyed by the C++ stack upon function completion.

#  Vault File Format (.txt)
The vault utilizes a strict, custom-parsed linear structure without empty spaces to allow for seamless appending without risking header corruption. All cryptographic bytes are stored as raw hexadecimal text.

#  Plaintext
[Line 1] Salt (16 bytes, Hex)
[Line 2] KEK IV (16 bytes, Hex)
[Line 3] KEK Verification Hash (64 characters, Hex Text)
[Line 4] Encrypted DEK (Padded, Hex)
[Line 5+] Payload Entries -> WebsiteName|Unique_IV_Hex|Encrypted_Password_Hex
#Dependencies & Libraries#
tiny-AES-c: A small, portable C library for the AES ECB/CTR/CBC encryption algorithms.

picosha2: A header-only C++ library for SHA-256 hashing.

C++ Standard Library: <iostream>, <fstream>, <vector>, <string>, <sstream>.

C Standard I/O: <cstdio> (Utilized for OS-level file destruction).

OS Cryptography: Utilizes CryptGenRandom (Windows CryptoAPI) or /dev/urandom (Unix) for cryptographically secure pseudo-random number generation (CSPRNG).

#Compilation & Usage#
To Compile:

Bash:
g++ source.cpp aes.c -o local_vault.exe
System Workflow:

Creation Phase: The user provides a Site Name, Password, and a numeric PIN. The engine generates the Salt, KEK, DEK, and IVs, formats the vault header, and securely creates a new sequentially numbered vault (e.g., vault1.txt).

Appending Phase: The user selects a vault and provides their PIN. The engine reads the header, recalculates the KEK, verifies the hash, unlocks the DEK in RAM, encrypts the new payload with a fresh IV, and uses std::ios::app to safely append the entry to the bottom of the file.

Retrieval Phase: The engine unlocks the DEK, parses the file line-by-line using a stringstream cleaver, isolates the requested site's ciphertext and IV, strips the PKCS#7 padding, and outputs the plaintext to the terminal.

Destruction Phase: If a vault is compromised or no longer needed, the user can trigger the deletion protocol. The engine verifies the PIN to ensure ownership, intentionally drops the OS read-locks, and uses the C-standard remove() function to violently wipe the file from the hard drive.

#  Security Notice
This is a local storage application. If you lose your mental PIN, the vault is mathematically impossible to recover. The Data Encryption Key will remain permanently locked.

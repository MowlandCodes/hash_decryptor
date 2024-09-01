# 🔓 Python Hash Decryptor 1.0

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.x-green)

## 📜 Description

Hash Decryptor is a powerful tool designed for educational purposes to decrypt various types of hash strings. It supports SHA256, SHA1, and MD5 hash types and offers both brute-force and wordlist-based decryption methods.

## 🚀 Features

- 🔐 Supports SHA256, SHA1, and MD5 hash types
- 🔨 Brute-force decryption mode
- 📚 Wordlist-based decryption mode
- 🖥️ User-friendly command-line interface
- 🎨 Colorful output for better readability

## 🛠️ Installation

1. Clone the repository:

```bash
git clone https://github.com/MowlandCodes/hash-decryptor.git
```

2. Navigate to the project directory:

```bash
cd hash-decryptor/source/
```

## 🔧 Usage

### Arguments

- `-ht, --hash-type`: Define hash type to decrypt (sha256, sha1, md5)
- `-hv, --hash-value`: Hash string to decrypt
- `-m, --mode`: Method to decrypt the hash (brute, wordlist)
- `-w, --wordlist`: Wordlist file (required if mode is set to wordlist)

### Examples:

1. Brute-force SHA256 decryption:

```bash
python hash-decryptor.py -ht sha256 -hv <hash_value> -m brute
```

2. Wordlist-based SHA256 decryption:

```bash
python hash-decryptor.py -ht sha256 -hv <hash_value> -m wordlist -w <wordlist_file>
```


## ⚠️ Disclaimer

This tool is for educational purposes only. The author and contributors are not responsible for any misuse or damage caused by this program.

## 👨‍💻 Author

- **Mowland Production**
- GitHub: [MowlandCodes](https://github.com/MowlandCodes)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

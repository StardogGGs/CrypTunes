# CrypTunes Requirements

## Runtime

- Python 3.10+ recommended
- Windows, macOS, or Linux with a working audio output device
- Tkinter, included with most standard Python installations

## Python Packages

Install the required third-party packages with:

```bash
pip install argon2-cffi cryptography pydub sounddevice numpy
```

### Dependencies

| Package | Import | Purpose |
|---|---|---|
| `argon2-cffi` | `argon2.low_level` | Argon2 password-based key derivation |
| `cryptography` | `cryptography.hazmat.primitives.ciphers.aead` | AES-GCM encryption and decryption |
| `pydub` | `pydub` | Audio decoding and conversion |
| `sounddevice` | `sounddevice` | Audio playback |
| `numpy` | `numpy` | Audio sample processing |

## External Audio Backend

`pydub` relies on an audio decoder/backend for formats such as MP3, FLAC, AAC, and M4A. On systems where these formats cannot be decoded directly, install **FFmpeg** and make sure it is available on the system `PATH`.

## PyInstaller

To package the application as a Windows executable without opening a console window:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name Cryptunes main.py
```

The executable will be created at:

```text
dist/CrypTunes.exe
```

## Optional Icon

To package with an `.ico` application icon:

```bash
pyinstaller --onefile --windowed --icon=icon.ico --name CrypTunes main.py
```


`passwords.ead` is stored as plaintext JSON for automatic password lookup. Anyone with access to the same user account/machine can read the stored passwords.

## Supported Audio Formats

- MP3
- WAV
- FLAC
- AAC
- M4A
- EA25 encrypted audio container
- UECT tagged unencrypted audio container

## Installation

1. Install Python.
2. Install the required packages:

```bash
pip install argon2-cffi cryptography pydub sounddevice numpy
```

3. Install FFmpeg if required for your audio formats.
4. Run the application:

```bash
python main.py
```

5. For a standalone Windows executable:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name VaultPlayer main.py
```

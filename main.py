#!/usr/bin/env python3
"""
Vault Player — local encrypted audio player.

Format spec:
  EA25 = Eli's AES256 (encrypted): magic(4)+ver(1)+codec(1)+salt(16)+iv(12)+tag(16)+ciphertext
  UECT = tagged unencrypted container: magic(4)+codec(1)+raw_audio
  (no marker) = native file, codec sniffed from extension
Codec byte: 0=MP3 1=WAV 2=FLAC 3=AAC

Decrypted/decoded audio never touches disk — decrypt happens in RAM per play,
key buffers zeroized after use.

library.json v2:
{
  "tracks": [{"path","password","album","artist"}],
  "playlists": {"name": [path,...]},
  "album_art": {"album_name": "path/to/cover.png"}
}
"password" in library.json is just the most-recently-used one, kept for the
🔑 icon and quick lookups. The real credential store lives separately:

~/Documents/.ead/passwords.ead (plaintext JSON):
{ "path/to/track.mp3": ["oldpw", "currentpw"], ... }
Each item keeps every password ever entered for it, oldest first. On play,
they're tried in order against the file until one works, so a password
change or a re-shared file with a different key still opens without asking.
Stored in PLAINTEXT for auto-unlock convenience — anyone with access to this
account/machine can read them.
"""
import io, os, json, re, shutil, struct, threading, hashlib, tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from pathlib import Path

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydub import AudioSegment
import sounddevice as sd
import numpy as np

MAGIC_ENC = b"EA25"
MAGIC_PLAIN = b"UECT"
CODECS = {0: "mp3", 1: "wav", 2: "flac", 3: "aac"}
EXT_CODEC = {".mp3": 0, ".wav": 1, ".flac": 2, ".aac": 3, ".m4a": 3}
VERSION = 1
UNKNOWN_ALBUM = "Unknown Album"

CONFIG_DIR = Path.home() / ".vault_player"
LIBRARY_FILE = CONFIG_DIR / "library.json"
DESKTOP_DIR = Path.home() / "Desktop"

# EAD = Eli's AES Directory: plaintext credential store, separate from the
# library file, holding every password ever tried per track.
EAD_DIR = Path.home() / "Documents" / ".ead"
EAD_FILE = EAD_DIR / "passwords.ead"

PALETTE = ["#1DB954", "#8b1e1e", "#2b4c8c", "#7c3aed", "#c2410c", "#0f766e", "#a21caf", "#4d7c0f"]



def zero(buf: bytearray):
    for i in range(len(buf)):
        buf[i] = 0


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(secret=password.encode("utf-8"), salt=salt,
                            time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID)


def detect_format(path: Path):
    with open(path, "rb") as f:
        head = f.read(4)
    if head == MAGIC_ENC:
        return "encrypted", None
    if head == MAGIC_PLAIN:
        with open(path, "rb") as f:
            f.read(4); codec_id = f.read(1)[0]
        return "plain_tagged", CODECS.get(codec_id, "mp3")
    ext = path.suffix.lower()
    codec = {"mp3": "mp3", "wav": "wav", "flac": "flac", "aac": "aac", "m4a": "aac"}.get(ext.lstrip("."), "mp3")
    return "native", codec


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r'[<>:"/\\|?*]', "_", name).strip()
    return cleaned or "Untitled"


def _dedupe_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    i = 1
    while True:
        candidate = path.with_name(f"{stem} ({i}){suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def encrypt_file(src_path: Path, dst_path: Path, password: str):
    codec_id = EXT_CODEC.get(src_path.suffix.lower(), 0)
    salt, iv = os.urandom(16), os.urandom(12)
    key = bytearray(derive_key(password, salt))
    with open(src_path, "rb") as f:
        plaintext = f.read()
    ct = AESGCM(bytes(key)).encrypt(iv, plaintext, None)
    ciphertext, tag = ct[:-16], ct[-16:]
    with open(dst_path, "wb") as f:
        f.write(MAGIC_ENC); f.write(struct.pack("BB", VERSION, codec_id))
        f.write(salt); f.write(iv); f.write(tag); f.write(ciphertext)
    zero(key)


def decrypt_to_pcm(path: Path, password: str) -> AudioSegment:
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == MAGIC_ENC, "not an EA25 file"
    codec_id = data[5]
    salt, iv, tag = data[6:22], data[22:34], data[34:50]
    ciphertext = data[50:]
    key = bytearray(derive_key(password, salt))
    try:
        plaintext = bytearray(AESGCM(bytes(key)).decrypt(iv, ciphertext + tag, None))
    except Exception:
        zero(key)
        raise ValueError("Wrong password or corrupted file")
    zero(key)
    seg = AudioSegment.from_file(io.BytesIO(bytes(plaintext)), format=CODECS.get(codec_id, "mp3"))
    zero(plaintext)
    return seg


def load_plain_pcm(path: Path, kind: str, codec: str) -> AudioSegment:
    if kind == "plain_tagged":
        with open(path, "rb") as f:
            f.read(5); raw = f.read()
        return AudioSegment.from_file(io.BytesIO(raw), format=codec)
    return AudioSegment.from_file(str(path), format=codec)


class Player:
    def __init__(self):
        self.stream = None
        self.samples = None
        self.frame_rate = 44100
        self.channels = 2
        self.frame_idx = 0
        self.volume = 1.0
        self.playing = False
        self.on_done = None
        self._lock = threading.Lock()

    def load(self, seg: AudioSegment):
        self.stop()
        arr = np.array(seg.get_array_of_samples()).astype(np.float32)
        arr /= float(1 << (8 * seg.sample_width - 1))
        arr = arr.reshape((-1, 2)) if seg.channels == 2 else arr.reshape((-1, 1))
        with self._lock:
            self.samples = arr; self.frame_rate = seg.frame_rate
            self.channels = seg.channels; self.frame_idx = 0

    def _callback(self, outdata, frames, time_info, status):
        with self._lock:
            start = self.frame_idx; end = start + frames
            chunk = self.samples[start:end] * self.volume
            n = len(chunk)
            outdata[:n] = chunk
            if n < frames:
                outdata[n:] = 0
                self.frame_idx = len(self.samples)
                self.playing = False
                raise sd.CallbackStop()
            self.frame_idx = end

    def play(self, on_done=None):
        if self.samples is None:
            return
        self.on_done = on_done
        self._open_stream()

    def _open_stream(self):
        if self.stream:
            self.stream.stop(); self.stream.close()
        self.stream = sd.OutputStream(samplerate=self.frame_rate, channels=self.channels,
                                       callback=self._callback, finished_callback=self._finished)
        self.playing = True
        self.stream.start()

    def _finished(self):
        self.playing = False
        if self.on_done:
            self.on_done()

    def pause(self):
        if self.stream:
            self.stream.stop()
        self.playing = False

    def resume(self):
        if self.samples is None or self.frame_idx >= len(self.samples):
            return
        self._open_stream()

    def stop(self):
        self.playing = False
        if self.stream:
            self.stream.stop(); self.stream.close(); self.stream = None
        with self._lock:
            self.frame_idx = 0

    def seek(self, seconds: float):
        with self._lock:
            if self.samples is None:
                return
            self.frame_idx = max(0, min(int(seconds * self.frame_rate), len(self.samples)))

    def position_seconds(self):
        with self._lock:
            return self.frame_idx / self.frame_rate if self.frame_rate else 0

    def duration_seconds(self):
        with self._lock:
            return len(self.samples) / self.frame_rate if self.samples is not None and self.frame_rate else 0

    def set_volume(self, v: float):
        self.volume = max(0.0, min(1.0, v))


# ---------- persistence ----------

def load_library():
    if not LIBRARY_FILE.exists():
        return [], {}, {}
    try:
        raw = json.loads(LIBRARY_FILE.read_text())
        if isinstance(raw, list):  # v1 migration
            raw = {"tracks": raw, "playlists": {}, "album_art": {}}
        tracks = []
        for e in raw.get("tracks", []):
            p = Path(e["path"])
            if p.exists():
                tracks.append({"path": p, "password": e.get("password"),
                                "album": e.get("album") or UNKNOWN_ALBUM, "artist": e.get("artist") or ""})
        playlists = {name: [str(p) for p in paths] for name, paths in raw.get("playlists", {}).items()}
        album_art = raw.get("album_art", {})
        return tracks, playlists, album_art
    except Exception:
        return [], {}, {}


def save_library(tracks, playlists, album_art):
    CONFIG_DIR.mkdir(exist_ok=True)
    LIBRARY_FILE.write_text(json.dumps({
        "tracks": [{"path": str(t["path"]), "password": t.get("password"),
                     "album": t.get("album", UNKNOWN_ALBUM), "artist": t.get("artist", "")} for t in tracks],
        "playlists": playlists,
        "album_art": album_art,
    }))


def clear_library():
    if LIBRARY_FILE.exists():
        LIBRARY_FILE.unlink()


def load_password_store():
    """path (str) -> list of every password ever entered for it, oldest first."""
    if not EAD_FILE.exists():
        return {}
    try:
        return json.loads(EAD_FILE.read_text())
    except Exception:
        return {}


def save_password_store(store: dict):
    EAD_DIR.mkdir(parents=True, exist_ok=True)
    EAD_FILE.write_text(json.dumps(store, indent=2))


def clear_password_store():
    if EAD_FILE.exists():
        EAD_FILE.unlink()


AUDIO_FILETYPES = [
    ("All supported", "*.mp3 *.wav *.flac *.aac *.m4a *.ea25"),
    ("Encrypted (.ea25)", "*.ea25"),
    ("Audio", "*.mp3 *.wav *.flac *.aac *.m4a"),
    ("All files", "*.*"),
]


def _album_color(name: str) -> str:
    return PALETTE[int(hashlib.md5(name.encode()).hexdigest(), 16) % len(PALETTE)]


class App:
    def __init__(self, root):
        self.root = root
        root.title("Vault Player")
        root.geometry("980x640")
        root.configure(bg="#121212")

        self.player = Player()
        self.tracks, self.playlists, self.album_art = load_library()
        # Credential store: path (str) -> list of every password ever entered
        # for it. Lives in ~/Documents/.ead, separate from library.json.
        self._pw_store = load_password_store()
        migrated = False
        for t in self.tracks:
            legacy = t.get("password")
            if legacy:
                lst = self._pw_store.setdefault(str(t["path"]), [])
                if legacy not in lst:
                    lst.append(legacy)
                    migrated = True
        if migrated:
            save_password_store(self._pw_store)
        self.current_view = "albums"     # albums | songs | album_detail | playlist
        self.current_album = None
        self.current_playlist = None
        self.view_tracks = []            # index -> track dict, for whatever list is on screen
        self._dragging_seek = False
        self._art_cache = {}

        self._build_sidebar()
        self._build_main()
        self._build_transport()
        self._build_context_menu()

        self.show_albums()
        self._tick()

    # ---------- layout ----------
    def _build_sidebar(self):
        sb = tk.Frame(self.root, bg="#000000", width=190)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        tk.Button(sb, text="⚠ Clear Library", command=self.emergency_clear, bg="#8b1e1e", fg="white",
                  bd=0, padx=6, pady=6).pack(fill="x", padx=10, pady=(10, 14))

        tk.Label(sb, text="LIBRARY", bg="#000000", fg="#666", font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x", padx=14, pady=(4, 2))
        for label, cmd in [("Albums", self.show_albums), ("Songs", self.show_songs)]:
            tk.Button(sb, text=label, command=cmd, bg="#000000", fg="white", bd=0, anchor="w",
                      activebackground="#282828", activeforeground="white", padx=14, pady=6).pack(fill="x")

        tk.Label(sb, text="PLAYLISTS", bg="#000000", fg="#666", font=("Segoe UI", 9, "bold"), anchor="w").pack(fill="x", padx=14, pady=(16, 2))
        self.playlist_frame = tk.Frame(sb, bg="#000000")
        self.playlist_frame.pack(fill="x")
        tk.Button(sb, text="+ New Playlist", command=self.new_playlist, bg="#000000", fg="#1DB954", bd=0,
                  anchor="w", padx=14, pady=6).pack(fill="x")

        add_frame = tk.Frame(sb, bg="#000000")
        add_frame.pack(side="bottom", fill="x", pady=10)
        tk.Button(add_frame, text="+ Add to Library", command=self.add_files, bg="#1DB954", fg="white",
                  bd=0, padx=6, pady=8).pack(fill="x", padx=10, pady=2)
        tk.Button(add_frame, text="Encrypt a File...", command=self.encrypt_dialog, bg="#333", fg="white",
                  bd=0, padx=6, pady=8).pack(fill="x", padx=10, pady=2)

        self._refresh_playlist_buttons()

    def _refresh_playlist_buttons(self):
        for w in self.playlist_frame.winfo_children():
            w.destroy()
        for name in sorted(self.playlists.keys()):
            btn = tk.Button(self.playlist_frame, text=name, command=lambda n=name: self.show_playlist(n),
                      bg="#000000", fg="white", bd=0, anchor="w", activebackground="#282828",
                      activeforeground="white", padx=14, pady=5)
            btn.pack(fill="x")
            btn.bind("<Button-3>", lambda e, n=name: self._show_playlist_menu(e, n))

    def _show_playlist_menu(self, event, playlist_name):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Encrypt && Send to Desktop (.ea25)", command=lambda: self._export_playlist_encrypted(playlist_name))
        menu.tk_popup(event.x_root, event.y_root)

    def _build_main(self):
        container = tk.Frame(self.root, bg="#121212")
        container.pack(side="left", fill="both", expand=True)

        self.header = tk.Label(container, text="Albums", bg="#121212", fg="white", font=("Segoe UI", 18, "bold"), anchor="w")
        self.header.pack(fill="x", padx=16, pady=(14, 6))

        # album grid (scrollable canvas)
        self.grid_canvas = tk.Canvas(container, bg="#121212", bd=0, highlightthickness=0)
        self.grid_scroll = ttk.Scrollbar(container, orient="vertical", command=self.grid_canvas.yview)
        self.grid_inner = tk.Frame(self.grid_canvas, bg="#121212")
        self.grid_inner.bind("<Configure>", lambda e: self.grid_canvas.configure(scrollregion=self.grid_canvas.bbox("all")))
        self.grid_canvas.create_window((0, 0), window=self.grid_inner, anchor="nw")
        self.grid_canvas.configure(yscrollcommand=self.grid_scroll.set)

        # song list (used for songs/album_detail/playlist views)
        self.listbox = tk.Listbox(container, bg="#181818", fg="white", selectbackground="#1DB954",
                                   bd=0, highlightthickness=0, font=("Segoe UI", 11))
        self.listbox.bind("<Double-Button-1>", lambda e: self.play_selected())
        self.listbox.bind("<Button-3>", self._show_context_menu)

        self._container = container  # for packing swaps

    def _show_grid(self):
        self.listbox.pack_forget()
        self.grid_canvas.pack(side="left", fill="both", expand=True, padx=(16, 0), pady=(0, 10))
        self.grid_scroll.pack(side="right", fill="y")

    def _show_list(self):
        self.grid_canvas.pack_forget()
        self.grid_scroll.pack_forget()
        self.listbox.pack(fill="both", expand=True, padx=16, pady=(0, 10))

    def _build_transport(self):
        seek_frame = tk.Frame(self.root, bg="#121212")
        seek_frame.place_forget()  # placed via pack below on a bottom bar instead

        bottom = tk.Frame(self.root, bg="#181818")
        # pack bottom bar across full width beneath everything — repack root children instead
        self.root.update_idletasks()

        bar = tk.Frame(self.root, bg="#121212")
        bar.pack(side="bottom", fill="x")

        seek_row = tk.Frame(bar, bg="#121212")
        seek_row.pack(fill="x", padx=10, pady=(6, 0))
        self.time_label = tk.Label(seek_row, text="0:00 / 0:00", bg="#121212", fg="#aaa", width=12)
        self.time_label.pack(side="right")
        self.seek_var = tk.DoubleVar(value=0)
        self.seek_scale = ttk.Scale(seek_row, from_=0, to=100, orient="horizontal", variable=self.seek_var)
        self.seek_scale.pack(fill="x", side="left", expand=True, padx=(0, 10))
        self.seek_scale.bind("<ButtonPress-1>", lambda e: setattr(self, "_dragging_seek", True))
        self.seek_scale.bind("<ButtonRelease-1>", self._on_seek_release)

        self.status = tk.Label(bar, text="Ready", bg="#181818", fg="#aaa", anchor="w", padx=10, pady=6)
        self.status.pack(fill="x", pady=(6, 0))

        ctrl = tk.Frame(bar, bg="#121212")
        ctrl.pack(pady=8)
        tk.Button(ctrl, text="▶ Play", command=self.play_selected, bg="#1DB954", fg="white", bd=0, padx=14, pady=6).pack(side="left", padx=4)
        tk.Button(ctrl, text="⏸ Pause", command=self.pause_track, bg="#333", fg="white", bd=0, padx=14, pady=6).pack(side="left", padx=4)
        tk.Button(ctrl, text="▶ Resume", command=self.resume_track, bg="#333", fg="white", bd=0, padx=14, pady=6).pack(side="left", padx=4)
        tk.Button(ctrl, text="■ Stop", command=self.stop_track, bg="#333", fg="white", bd=0, padx=14, pady=6).pack(side="left", padx=4)
        vol_frame = tk.Frame(ctrl, bg="#121212")
        vol_frame.pack(side="left", padx=16)
        tk.Label(vol_frame, text="Vol", bg="#121212", fg="#aaa").pack(side="left")
        self.vol_var = tk.DoubleVar(value=100)
        ttk.Scale(vol_frame, from_=0, to=100, orient="horizontal", length=120,
                  variable=self.vol_var, command=self._on_volume_change).pack(side="left", padx=6)

    def _build_context_menu(self):
        self.ctx_menu = tk.Menu(self.root, tearoff=0)
        self.ctx_menu.add_command(label="Set Password", command=self._ctx_set_password)
        self.ctx_menu.add_command(label="Input Password", command=self._ctx_input_password)
        self.ctx_menu.add_separator()
        self.album_menu = tk.Menu(self.ctx_menu, tearoff=0)
        self.ctx_menu.add_cascade(label="Add to Album", menu=self.album_menu)
        self.playlist_menu = tk.Menu(self.ctx_menu, tearoff=0)
        self.ctx_menu.add_cascade(label="Add to Playlist", menu=self.playlist_menu)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Encrypt && Send to Desktop (.ea25)", command=self._ctx_export_encrypted)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Remove from Library", command=self._ctx_remove)

    # ---------- views ----------
    def show_albums(self):
        self.current_view = "albums"
        self.header.config(text="Albums")
        self._show_grid()
        for w in self.grid_inner.winfo_children():
            w.destroy()
        albums = sorted({t["album"] for t in self.tracks})
        cols = 5
        for i, name in enumerate(albums):
            r, c = divmod(i, cols)
            cell = tk.Frame(self.grid_inner, bg="#121212")
            cell.grid(row=r, column=c, padx=12, pady=12)
            cover = self._make_cover(cell, name, size=140)
            cover.pack()
            cover.bind("<Button-1>", lambda e, n=name: self.show_album(n))
            cover.bind("<Button-3>", lambda e, n=name: self._show_album_cover_menu(e, n))
            count = sum(1 for t in self.tracks if t["album"] == name)
            tk.Label(cell, text=name, bg="#121212", fg="white", font=("Segoe UI", 10, "bold"), wraplength=140, justify="left").pack(anchor="w", pady=(6, 0))
            tk.Label(cell, text=f"{count} track{'s' if count != 1 else ''}", bg="#121212", fg="#999", font=("Segoe UI", 9)).pack(anchor="w")

    def _make_cover(self, parent, album_name, size=140):
        img = self.album_art.get(album_name)
        canvas = tk.Canvas(parent, width=size, height=size, bd=0, highlightthickness=0, bg=_album_color(album_name))
        if img and Path(img).exists():
            try:
                key = (img, size)
                if key not in self._art_cache:
                    photo = tk.PhotoImage(file=img)
                    factor = max(1, photo.width() // size)
                    photo = photo.subsample(factor, factor)
                    self._art_cache[key] = photo
                canvas.create_image(size // 2, size // 2, image=self._art_cache[key])
                return canvas
            except Exception:
                pass
        canvas.create_text(size // 2, size // 2, text="♪", fill="white", font=("Segoe UI", int(size * 0.4), "bold"))
        return canvas

    def show_songs(self):
        self.current_view = "songs"
        self.current_album = None
        self.current_playlist = None
        self.header.config(text="Songs")
        self._show_list()
        self._populate_listbox(self.tracks)

    def show_album(self, name):
        self.current_view = "album_detail"
        self.current_album = name
        self.header.config(text=name)
        self._show_list()
        self._populate_listbox([t for t in self.tracks if t["album"] == name])

    def show_playlist(self, name):
        self.current_view = "playlist"
        self.current_playlist = name
        self.header.config(text=f"Playlist: {name}")
        self._show_list()
        paths = set(self.playlists.get(name, []))
        self._populate_listbox([t for t in self.tracks if str(t["path"]) in paths])

    def _populate_listbox(self, tracks):
        self.view_tracks = tracks
        self.listbox.delete(0, "end")
        for t in tracks:
            kind, _ = detect_format(t["path"])
            lock = "🔒 " if kind == "encrypted" else ("🔑 " if t.get("password") else "")
            self.listbox.insert("end", f"{lock}{t['path'].name}")

    def _refresh_current_view(self):
        if self.current_view == "albums":
            self.show_albums()
        elif self.current_view == "songs":
            self.show_songs()
        elif self.current_view == "album_detail":
            self.show_album(self.current_album)
        elif self.current_view == "playlist":
            self.show_playlist(self.current_playlist)

    def _candidate_passwords(self, path):
        """Every password ever entered for this track, oldest first."""
        return self._pw_store.get(str(path), [])

    def _remember_password(self, track, pw):
        """Add a password to this track's candidate list and persist it."""
        lst = self._pw_store.setdefault(str(track["path"]), [])
        if pw in lst:
            lst.remove(pw)
        lst.append(pw)  # keep most-recently-used last
        save_password_store(self._pw_store)
        track["password"] = pw  # mirror for the 🔑 icon / quick lookups
        save_library(self.tracks, self.playlists, self.album_art)

    def _forget_password(self, track):
        self._pw_store.pop(str(track["path"]), None)
        save_password_store(self._pw_store)
        track["password"] = None
        save_library(self.tracks, self.playlists, self.album_art)

    # ---------- library management ----------
    def add_files(self):
        paths = filedialog.askopenfilenames(title="Add audio files", filetypes=AUDIO_FILETYPES)
        for p in paths:
            path = Path(p)
            if any(t["path"] == path for t in self.tracks):
                continue
            pw = simpledialog.askstring("Set Password", f"Set a password for '{path.name}'?\n(Cancel to skip)", show="*", parent=self.root)
            self.tracks.append({"path": path, "password": pw or None, "album": UNKNOWN_ALBUM, "artist": ""})
            if pw:
                self._pw_store.setdefault(str(path), [])
                if pw not in self._pw_store[str(path)]:
                    self._pw_store[str(path)].append(pw)
        save_password_store(self._pw_store)
        save_library(self.tracks, self.playlists, self.album_art)
        self._refresh_current_view()

    def emergency_clear(self):
        if not messagebox.askyesno("Clear Library",
                "This removes ALL tracks, playlists, and stored passwords\n"
                "(including the .ead credential file in Documents).\n"
                "Original files on disk are NOT deleted. This cannot be undone.\n\nContinue?"):
            return
        self.player.stop()
        self.tracks, self.playlists, self.album_art = [], {}, {}
        self._pw_store.clear()
        clear_library()
        clear_password_store()
        self._refresh_playlist_buttons()
        self._refresh_current_view()
        self.status.config(text="Library cleared")

    def new_playlist(self):
        name = simpledialog.askstring("New Playlist", "Playlist name:", parent=self.root)
        if not name or name in self.playlists:
            return
        self.playlists[name] = []
        save_library(self.tracks, self.playlists, self.album_art)
        self._refresh_playlist_buttons()

    # ---------- context menu ----------
    def _selected_track(self):
        sel = self.listbox.curselection()
        if not sel or sel[0] >= len(self.view_tracks):
            return None
        return self.view_tracks[sel[0]]

    def _show_context_menu(self, event):
        idx = self.listbox.nearest(event.y)
        if idx < 0 or idx >= len(self.view_tracks):
            return
        self.listbox.selection_clear(0, "end")
        self.listbox.selection_set(idx)
        track = self.view_tracks[idx]

        self.album_menu.delete(0, "end")
        self.album_menu.add_command(label="＋ Create New...", command=lambda: self._assign_album(track, new=True))
        for name in sorted({t["album"] for t in self.tracks}):
            self.album_menu.add_command(label=name, command=lambda n=name: self._assign_album(track, name=n))

        self.playlist_menu.delete(0, "end")
        self.playlist_menu.add_command(label="＋ Create New...", command=lambda: self._assign_playlist(track, new=True))
        for name in sorted(self.playlists.keys()):
            self.playlist_menu.add_command(label=name, command=lambda n=name: self._assign_playlist(track, name=n))

        self.ctx_menu.tk_popup(event.x_root, event.y_root)

    def _assign_album(self, track, name=None, new=False):
        if new:
            name = simpledialog.askstring("Create Album", "New album name:", parent=self.root)
            if not name:
                return
        track["album"] = name
        save_library(self.tracks, self.playlists, self.album_art)
        self._refresh_current_view()

    def _assign_playlist(self, track, name=None, new=False):
        if new:
            name = simpledialog.askstring("Create Playlist", "New playlist name:", parent=self.root)
            if not name:
                return
            self.playlists.setdefault(name, [])
        p = str(track["path"])
        if p not in self.playlists[name]:
            self.playlists[name].append(p)
        save_library(self.tracks, self.playlists, self.album_art)
        self._refresh_playlist_buttons()

    def _ctx_set_password(self):
        track = self._selected_track()
        if not track:
            return
        pw = simpledialog.askstring("Set Password", f"New password for '{track['path'].name}':", show="*", parent=self.root)
        if pw is None:
            return
        if pw:
            self._remember_password(track, pw)
        else:
            self._forget_password(track)
        self._refresh_current_view()

    def _ctx_input_password(self):
        track = self._selected_track()
        if not track:
            return
        pw = simpledialog.askstring("Input Password", f"Re-enter password for '{track['path'].name}':", show="*", parent=self.root)
        if pw is None:
            return
        kind, _ = detect_format(track["path"])
        if kind == "encrypted":
            try:
                decrypt_to_pcm(track["path"], pw)
            except ValueError as e:
                messagebox.showerror("Incorrect", str(e))
                return
        self._remember_password(track, pw)
        self.status.config(text="Password updated")

    def _ctx_remove(self):
        track = self._selected_track()
        if not track:
            return
        if not messagebox.askyesno("Remove", f"Remove '{track['path'].name}' from the library?\n(File on disk is untouched.)"):
            return
        self.tracks.remove(track)
        for pl in self.playlists.values():
            if str(track["path"]) in pl:
                pl.remove(str(track["path"]))
        save_library(self.tracks, self.playlists, self.album_art)
        self._refresh_current_view()

    def _show_album_cover_menu(self, event, album_name):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Set Custom Cover...", command=lambda: self._set_album_cover(album_name))
        menu.add_command(label="Reset to Default", command=lambda: self._reset_album_cover(album_name))
        menu.add_separator()
        menu.add_command(label="Encrypt && Send to Desktop (.ea25)", command=lambda: self._export_album_encrypted(album_name))
        menu.tk_popup(event.x_root, event.y_root)

    def _set_album_cover(self, album_name):
        path = filedialog.askopenfilename(title="Choose cover image", filetypes=[("Images", "*.png *.gif *.ppm *.pgm")])
        if not path:
            return
        self.album_art[album_name] = path
        save_library(self.tracks, self.playlists, self.album_art)
        self.show_albums()

    def _reset_album_cover(self, album_name):
        self.album_art.pop(album_name, None)
        save_library(self.tracks, self.playlists, self.album_art)
        self.show_albums()

    # ---------- encryption ----------
    def encrypt_dialog(self):
        src = filedialog.askopenfilename(title="Select file to encrypt",
                                          filetypes=[("Audio", "*.mp3 *.wav *.flac *.aac *.m4a"), ("All files", "*.*")])
        if not src:
            return
        pw = simpledialog.askstring("Password", "Set a password for this file:", show="*", parent=self.root)
        if not pw:
            return
        dst = filedialog.asksaveasfilename(defaultextension=".ea25", initialfile=Path(src).stem + ".ea25",
                                            filetypes=[("Encrypted", "*.ea25")])
        if not dst:
            return
        try:
            encrypt_file(Path(src), Path(dst), pw)
            messagebox.showinfo("Done", f"Encrypted file saved:\n{dst}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------- encrypt & send to desktop ----------
    def _ctx_export_encrypted(self):
        track = self._selected_track()
        if not track:
            return
        self._export_tracks_as_ea25([track])

    def _export_album_encrypted(self, album_name):
        tracks = [t for t in self.tracks if t["album"] == album_name]
        self._export_tracks_as_ea25(tracks, folder_name=album_name)

    def _export_playlist_encrypted(self, playlist_name):
        paths = set(self.playlists.get(playlist_name, []))
        tracks = [t for t in self.tracks if str(t["path"]) in paths]
        self._export_tracks_as_ea25(tracks, folder_name=playlist_name)

    def _export_tracks_as_ea25(self, tracks, folder_name=None):
        """Encrypt (or copy, if already EA25) the given tracks out to the Desktop.

        A single track goes straight to the Desktop. Multiple tracks (album or
        playlist) go into a subfolder named after the album/playlist, each
        track inside it becoming its own .ea25 file.

        Tracks that already have a saved password (from a prior export, play,
        or "Set Password") reuse it automatically — no re-prompting. Only
        tracks with no known password trigger a single prompt, and that
        password is then remembered for next time.
        """
        if not tracks:
            messagebox.showinfo("Nothing to export", "There are no tracks to export.")
            return

        def needs_new_pw(t):
            kind, _ = detect_format(t["path"])
            return kind != "encrypted" and not self._candidate_passwords(t["path"])

        unpassworded = [t for t in tracks if needs_new_pw(t)]
        batch_pw = None
        if unpassworded:
            batch_pw = simpledialog.askstring(
                "Encryption Password",
                "Set a password to encrypt the file(s) that don't have one saved yet:",
                show="*", parent=self.root)
            if not batch_pw:
                return

        try:
            DESKTOP_DIR.mkdir(exist_ok=True)
            if folder_name:
                out_dir = DESKTOP_DIR / _safe_filename(folder_name)
                out_dir.mkdir(exist_ok=True)
            else:
                out_dir = DESKTOP_DIR

            exported = 0
            for t in tracks:
                src = t["path"]
                kind, _ = detect_format(src)
                dst = _dedupe_path(out_dir / f"{src.stem}.ea25")
                if kind == "encrypted":
                    shutil.copyfile(src, dst)   # already EA25 — pass through untouched
                else:
                    candidates = self._candidate_passwords(src)
                    pw = candidates[-1] if candidates else batch_pw  # most recently used
                    encrypt_file(src, dst, pw)
                    if not candidates:
                        self._remember_password(t, pw)
                exported += 1

            messagebox.showinfo(
                "Exported",
                f"{exported} file{'s' if exported != 1 else ''} sent to:\n{out_dir}")
            self.status.config(text=f"Exported {exported} file(s) to Desktop")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    # ---------- playback ----------
    def play_selected(self):
        # NOTE: runs on the main thread deliberately. Tk dialogs (simpledialog/
        # messagebox) are not thread-safe — calling them from a worker thread
        # causes errors like 'window "!querystring" was deleted before its
        # visibility changed'. Argon2 decrypt is fast enough (~100-300ms) that
        # a brief main-thread block here is preferable to that bug.
        track = self._selected_track()
        if not track:
            return
        path = track["path"]
        kind, codec = detect_format(path)
        self.status.config(text=f"Loading {path.name}...")
        self.root.update_idletasks()

        try:
            if kind == "encrypted":
                seg = None
                tried_pw = None
                for candidate in reversed(self._candidate_passwords(path)):  # newest first
                    try:
                        seg = decrypt_to_pcm(path, candidate)
                        tried_pw = candidate
                        break
                    except ValueError:
                        continue
                if seg is None:
                    pw = simpledialog.askstring("Password", f"Password for {path.name}:", show="*", parent=self.root)
                    if not pw:
                        self.status.config(text="Cancelled")
                        return
                    try:
                        seg = decrypt_to_pcm(path, pw)
                    except ValueError:
                        pw2 = simpledialog.askstring("Wrong Password", f"Incorrect. Retry password for {path.name}:", show="*", parent=self.root)
                        if not pw2:
                            self.status.config(text="Cancelled")
                            return
                        seg = decrypt_to_pcm(path, pw2)
                        pw = pw2
                    tried_pw = pw
                self._remember_password(track, tried_pw)
            else:
                seg = load_plain_pcm(path, kind, codec)
            self.player.load(seg)
            self.seek_scale.config(to=max(self.player.duration_seconds(), 0.01))
            self.player.play(on_done=lambda: self.status.config(text="Ready"))
            self.status.config(text=f"Playing {path.name}")
        except Exception as e:
            messagebox.showerror("Playback error", str(e))
            self.status.config(text="Ready")

    def pause_track(self):
        self.player.pause(); self.status.config(text="Paused")

    def resume_track(self):
        self.player.resume(); self.status.config(text="Playing")

    def stop_track(self):
        self.player.stop(); self.status.config(text="Ready")

    def _on_volume_change(self, val):
        self.player.set_volume(float(val) / 100.0)

    def _on_seek_release(self, event):
        self._dragging_seek = False
        self.player.seek(self.seek_var.get())

    def _tick(self):
        if not self._dragging_seek and self.player.samples is not None:
            pos, dur = self.player.position_seconds(), self.player.duration_seconds()
            self.seek_var.set(pos)
            self.time_label.config(text=f"{_fmt(pos)} / {_fmt(dur)}")
        self.root.after(250, self._tick)


def _fmt(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60}:{seconds % 60:02d}"


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()

#!/usr/bin/env python3
"""
Jelly Renamer GUI — improved preview + automatic movie/show detection

Changes:
- New mode "auto": automatically decides per-file whether it's a TV episode or a movie.
- Heuristics: SxxEyy in filename, parent-folder hints (season/episode, 'Season', 'S01', bracketed imdb), and optional OMDb type lookup when API key provided.
- Preview now includes detected_type and detect_reason for each file.
"""
import os
import re
import json
import urllib.request
import urllib.parse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

ILLEGAL_CHARS = '<>:\\\"/|?*'
ILLEGAL_RE = re.compile(r'[<>:\\\"/|?*]')

TT_RE = re.compile(r'(tt\d{6,8})', re.IGNORECASE)  # find tt1234567 patterns


def sanitize_filename(name: str) -> str:
    name = ILLEGAL_RE.sub("_", name)
    name = re.sub(r'\s+', ' ', name).strip()
    return name


def normalize_imdb(imdb: str) -> str:
    if not imdb:
        return ""
    s = imdb.strip()
    s = s.replace("[", "").replace("]", "")
    s = s.replace("imdbid-", "").replace("IMDBID-", "").replace("imdid-", "").replace("IMDID-", "")
    m = TT_RE.search(s)
    if m:
        s = m.group(1)
    if not s.startswith("tt"):
        if s.isdigit():
            s = "tt" + s
    return s


def find_imdb_in_path(path: str) -> str:
    base = os.path.basename(path)
    m = TT_RE.search(base)
    if m:
        return normalize_imdb(m.group(1))
    cur = os.path.abspath(path)
    for _ in range(0, 6):
        cur = os.path.dirname(cur)
        if not cur:
            break
        name = os.path.basename(cur)
        if not name:
            continue
        m = TT_RE.search(name)
        if m:
            return normalize_imdb(m.group(1))
        br = re.search(r'imdbid-tt\d{6,8}', name, re.IGNORECASE)
        if br:
            return normalize_imdb(br.group(0))
        br2 = re.search(r'imdid-tt\d{6,8}', name, re.IGNORECASE)
        if br2:
            return normalize_imdb(br2.group(0))
    return ""


def parse_filename_for_movie(base: str):
    m = re.match(r'^(?P<title>.+?)\s*\((?P<year>\d{4})\)\s*$', base)
    if m:
        return m.group('title').replace('.', ' ').strip(), m.group('year')
    m = re.search(r'(?P<year>\d{4})', base)
    if m:
        year = m.group('year')
        title = base[:m.start()].replace('.', ' ').replace('_', ' ').replace('-', ' ').strip()
        if title:
            return title, year
    return base.replace('.', ' ').replace('_', ' ').replace('-', ' ').strip(), None


def parse_filename_for_tv(base: str):
    m = re.search(r'(?i)(?:^|\b)(S(?P<season>\d{1,2})E(?P<episode>\d{1,2}))(?:\b|$)', base)
    if m:
        season = int(m.group('season'))
        episode = int(m.group('episode'))
        show = base[:m.start()].replace('.', ' ').replace('_', ' ').replace('-', ' ').strip()
        return show or base.replace('.', ' ').strip(), season, episode
    m2 = re.search(r'(?i)(?:^|\b)(?P<season>\d{1,2})x(?P<episode>\d{1,2})(?:\b|$)', base)
    if m2:
        season = int(m2.group('season'))
        episode = int(m2.group('episode'))
        show = base[:m2.start()].replace('.', ' ').replace('_', ' ').replace('-', ' ').strip()
        return show or base.replace('.', ' ').strip(), season, episode
    return base.replace('.', ' ').replace('_', ' ').replace('-', ' ').strip(), None, None


def omdb_query(params: dict, apikey: str):
    if not apikey:
        return None
    base = "http://www.omdbapi.com/"
    params = dict(params)
    params['apikey'] = apikey
    url = base + "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            raw = resp.read().decode('utf-8', errors='replace')
            data = json.loads(raw)
            return data
    except Exception:
        return None


def determine_media_type(path: str, meta: dict, apikey: str = ""):
    """
    Decide 'tv' or 'movie' for a file and return (type, reason).
    Heuristics (in order):
      1) If filename contains SxxEyy or 1x01 style -> tv
      2) If parent folder name looks like 'Season' or contains S01 or 'Episode' -> tv
      3) If parent folder contains imdb/tt and OMDb type is 'series' or 'movie', prefer OMDb when available.
      4) If filename contains a 4-digit year and no SxxEyy, lean movie (but low confidence).
      5) Default to 'movie' (safer for single-file renames) but mark low confidence.
    """
    # 1) filename SxxEyy detection
    base = os.path.splitext(os.path.basename(path))[0]
    show, s, e = parse_filename_for_tv(base)
    if s is not None and e is not None:
        return "tv", "SxxEyy found in filename"
    # 2) parent-folder hints
    cur = os.path.abspath(path)
    for _ in range(0, 4):  # check a few folder levels
        cur = os.path.dirname(cur)
        if not cur:
            break
        name = os.path.basename(cur).lower()
        if not name:
            continue
        if re.search(r'\bseason\b|\bs\d{1,2}\b|\bseries\b', name):
            return "tv", f"parent folder hint: '{os.path.basename(cur)}'"
        # if folder looks like "Show Name - S01" or contains S01
        if re.search(r'\bs\d{1,2}\b', name):
            return "tv", f"parent folder hint: '{os.path.basename(cur)}'"
    # 3) check for imdb/tt in path - if present and OMDb available, query OMDb to disambiguate
    imdb_from_path = find_imdb_in_path(path)
    if apikey and imdb_from_path:
        # query OMDb by id
        data = omdb_query({'i': imdb_from_path}, apikey)
        if data and data.get('Response') == 'True':
            typ = data.get('Type', '').lower()
            if typ == 'series':
                return "tv", f"OMDb: type=series (by imdb {imdb_from_path})"
            if typ == 'movie':
                return "movie", f"OMDb: type=movie (by imdb {imdb_from_path})"
    # 4) filename year presence -> lean movie
    if re.search(r'\b(19|20)\d{2}\b', base):
        return "movie", "year found in filename (heuristic)"
    # 5) fallback: try OMDb by title if apikey present
    if apikey:
        # best-effort: if meta has title or show, try those
        title = meta.get('title') or meta.get('show') or re.sub(r'[._\-]+', ' ', base).strip()
        if title:
            # first try movie
            mdata = omdb_query({'t': title, 'type': 'movie'}, apikey)
            if mdata and mdata.get('Response') == 'True':
                return "movie", "OMDb: matched movie by title"
            sdata = omdb_query({'t': title, 'type': 'series'}, apikey)
            if sdata and sdata.get('Response') == 'True':
                return "tv", "OMDb: matched series by title"
    # default
    return "movie", "default fallback (no strong signal)"


class JellyRenamer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Jelly Renamer — compact names (auto-detect)")
        self.geometry("960x600")
        self.minsize(860, 480)

        self.files = []
        self.file_meta = {}

        self.mode_var = tk.StringVar(value="auto")  # default to auto
        self.omdb_key_var = tk.StringVar()
        self.auto_find_on_add = tk.BooleanVar(value=True)
        self.auto_apply = tk.BooleanVar(value=False)

        # manual override fields
        self.imdb_var = tk.StringVar()
        self.title_var = tk.StringVar()
        self.year_var = tk.StringVar()
        self.show_var = tk.StringVar()
        self.season_var = tk.StringVar()
        self.episode_var = tk.StringVar()
        self.ep_title_var = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        frm_top = ttk.Frame(self, padding=8)
        frm_top.pack(fill=tk.X)
        frm_files = ttk.Frame(self, padding=(0, 4))
        frm_files.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(frm_files)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        btns = ttk.Frame(left)
        btns.pack(fill=tk.X, pady=(0, 6))

        ttk.Button(btns, text="Add Files", command=self.add_files).pack(side=tk.LEFT)
        ttk.Button(btns, text="Remove Selected", command=self.remove_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Clear", command=self.clear_files).pack(side=tk.LEFT)
        ttk.Button(btns, text="Auto-Find IMDBs", command=self.auto_find_imdbs).pack(side=tk.LEFT, padx=6)

        self.files_listbox = tk.Listbox(left, selectmode=tk.EXTENDED)
        self.files_listbox.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        scrollbar = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.files_listbox.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self.files_listbox.config(yscrollcommand=scrollbar.set)

        right = ttk.Frame(frm_files, width=360)
        right.pack(side=tk.LEFT, fill=tk.Y, padx=(8, 0))

        ttk.Label(right, text="Mode:").pack(anchor=tk.W)
        mode_opts = ("auto", "movie", "tv", "append")
        ttk.OptionMenu(right, self.mode_var, self.mode_var.get(), *mode_opts, command=lambda _: self.update_fields()).pack(fill=tk.X)

        ttk.Separator(right).pack(fill=tk.X, pady=6)

        ttk.Label(right, text="OMDb API Key (optional):").pack(anchor=tk.W)
        ttk.Entry(right, textvariable=self.omdb_key_var).pack(fill=tk.X)
        ttk.Checkbutton(right, text="Auto-find on add", variable=self.auto_find_on_add).pack(anchor=tk.W, pady=(4, 0))
        ttk.Checkbutton(right, text="Auto-apply renames (no confirm)", variable=self.auto_apply).pack(anchor=tk.W, pady=(0, 6))

        ttk.Separator(right).pack(fill=tk.X, pady=6)

        ttk.Label(right, text="IMDB ID (manual override):").pack(anchor=tk.W)
        ttk.Entry(right, textvariable=self.imdb_var).pack(fill=tk.X)

        self.movie_frame = ttk.Frame(right)
        self.movie_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(self.movie_frame, text="Movie Title (manual):").pack(anchor=tk.W)
        ttk.Entry(self.movie_frame, textvariable=self.title_var).pack(fill=tk.X)
        ttk.Label(self.movie_frame, text="Year (manual):").pack(anchor=tk.W, pady=(6, 0))
        ttk.Entry(self.movie_frame, textvariable=self.year_var).pack(fill=tk.X)

        self.tv_frame = ttk.Frame(right)
        self.tv_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(self.tv_frame, text="Show Name (manual):").pack(anchor=tk.W)
        ttk.Entry(self.tv_frame, textvariable=self.show_var).pack(fill=tk.X)
        row = ttk.Frame(self.tv_frame)
        row.pack(fill=tk.X, pady=(6, 0))
        ttk.Label(row, text="Season:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.season_var, width=6).pack(side=tk.LEFT, padx=(6, 10))
        ttk.Label(row, text="Episode:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.episode_var, width=6).pack(side=tk.LEFT, padx=(6, 10))
        ttk.Label(self.tv_frame, text="Episode Title (optional):").pack(anchor=tk.W, pady=(6, 0))
        ttk.Entry(self.tv_frame, textvariable=self.ep_title_var).pack(fill=tk.X)

        ttk.Separator(right).pack(fill=tk.X, pady=8)
        ttk.Button(right, text="Preview Rename", command=self.preview_rename).pack(fill=tk.X)
        ttk.Button(right, text="Rename Files", command=self.rename_files).pack(fill=tk.X, pady=(6, 0))

        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill=tk.BOTH, expand=True)
        ttk.Label(bottom, text="Preview (original -> new) — shows detected type & reason:").pack(anchor=tk.W)
        self.preview_box = ScrolledText(bottom, height=14)
        self.preview_box.pack(fill=tk.BOTH, expand=True)

        self.update_fields()
        self.files_listbox.bind('<<ListboxSelect>>', self.on_select_file)

    def add_files(self):
        paths = filedialog.askopenfilenames(title="Select video file(s)", filetypes=[("Video files", "*.mp4 *.mkv *.avi *.mov *.wmv *.flv *.webm"), ("All files", "*")])
        if not paths:
            return
        for p in paths:
            if p not in self.files:
                self.files.append(p)
                self.files_listbox.insert(tk.END, p)
                base = os.path.splitext(os.path.basename(p))[0]
                imdb_from_path = find_imdb_in_path(p)
                # initialize meta from filename heuristics
                show, season, episode = parse_filename_for_tv(base)
                title, year = parse_filename_for_movie(base)
                # prefer tv detection for initial meta if SxxEyy present
                if season is not None and episode is not None:
                    meta = {'title': None, 'year': None, 'show': sanitize_filename(show), 'season': season, 'episode': episode, 'imdb': imdb_from_path or None}
                else:
                    meta = {'title': sanitize_filename(title), 'year': year, 'show': None, 'season': None, 'episode': None, 'imdb': imdb_from_path or None}
                # determine detected type and reason now (may use OMDb if API key is present)
                detected, reason = determine_media_type(p, meta, self.omdb_key_var.get().strip())
                meta['detected_type'] = detected
                meta['detect_reason'] = reason
                self.file_meta[p] = meta
                if self.auto_find_on_add.get() and not meta.get('imdb'):
                    self._try_find_imdb_for_file(p)
                    # redo detection if imdb found by lookup
                    detected, reason = determine_media_type(p, self.file_meta[p], self.omdb_key_var.get().strip())
                    self.file_meta[p]['detected_type'] = detected
                    self.file_meta[p]['detect_reason'] = reason

    def remove_selected(self):
        sel = list(self.files_listbox.curselection())
        for index in reversed(sel):
            path = self.files[index]
            self.files_listbox.delete(index)
            self.files.pop(index)
            if path in self.file_meta:
                del self.file_meta[path]

    def clear_files(self):
        self.files_listbox.delete(0, tk.END)
        self.files.clear()
        self.file_meta.clear()

    def update_fields(self):
        mode = self.mode_var.get()
        if mode == "movie":
            self.movie_frame.pack(fill=tk.X, pady=(8, 0))
            self.tv_frame.forget()
        elif mode == "tv":
            self.tv_frame.pack(fill=tk.X, pady=(8, 0))
            self.movie_frame.forget()
        else:
            # auto or append: show both manual frames for override convenience
            self.movie_frame.pack(fill=tk.X, pady=(8, 0))
            self.tv_frame.pack(fill=tk.X, pady=(8, 0))

    def on_select_file(self, event):
        sel = self.files_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        path = self.files[idx]
        meta = self.file_meta.get(path, {})
        self.imdb_var.set(meta.get('imdb') or '')
        self.title_var.set(meta.get('title') or '')
        self.year_var.set(meta.get('year') or '')
        self.show_var.set(meta.get('show') or '')
        self.season_var.set(str(meta.get('season')) if meta.get('season') is not None else '')
        self.episode_var.set(str(meta.get('episode')) if meta.get('episode') is not None else '')
        self.ep_title_var.set('')

    def _try_find_imdb_for_file(self, path: str):
        meta = self.file_meta.get(path, {})
        apikey = self.omdb_key_var.get().strip()
        if meta.get('imdb'):
            return True
        imdb_from_path = find_imdb_in_path(path)
        if imdb_from_path:
            meta['imdb'] = imdb_from_path
            self.file_meta[path] = meta
            return True
        if not apikey:
            return False
        # attempt lookup depending on current detection or heuristics
        if meta.get('detected_type') == 'tv' or (meta.get('season') is not None and meta.get('episode') is not None):
            show = meta.get('show') or ''
            if not show:
                return False
            data = omdb_query({'s': show, 'type': 'series'}, apikey)
            if data and data.get('Response') == 'True':
                items = data.get('Search', [])
                if items:
                    best = items[0]
                    imdbid = normalize_imdb(best.get('imdbID', ''))
                    meta['imdb'] = imdbid
                    meta['show'] = best.get('Title') or meta.get('show')
                    self.file_meta[path] = meta
                    return True
            data = omdb_query({'t': show, 'type': 'series'}, apikey)
            if data and data.get('Response') == 'True':
                imdbid = normalize_imdb(data.get('imdbID', ''))
                meta['imdb'] = imdbid
                meta['show'] = data.get('Title') or meta.get('show')
                self.file_meta[path] = meta
                return True
            return False
        else:
            title = meta.get('title') or ''
            year = meta.get('year')
            if not title:
                return False
            q = {'t': title, 'type': 'movie'}
            if year:
                q['y'] = year
            data = omdb_query(q, apikey)
            if data and data.get('Response') == 'True':
                imdbid = normalize_imdb(data.get('imdbID', ''))
                meta['imdb'] = imdbid
                meta['title'] = data.get('Title') or meta.get('title')
                meta['year'] = data.get('Year') or meta.get('year')
                self.file_meta[path] = meta
                return True
            data = omdb_query({'s': title, 'type': 'movie'}, apikey)
            if data and data.get('Response') == 'True':
                items = data.get('Search', [])
                if items:
                    best = items[0]
                    imdbid = normalize_imdb(best.get('imdbID', ''))
                    meta['imdb'] = imdbid
                    meta['title'] = best.get('Title') or meta.get('title')
                    meta['year'] = best.get('Year') or meta.get('year')
                    self.file_meta[path] = meta
                    return True
            return False

    def auto_find_imdbs(self):
        if not self.files:
            messagebox.showinfo("No files", "Please add files first.")
            return
        apikey = self.omdb_key_var.get().strip()
        if not apikey:
            if not messagebox.askyesno("No API key", "No OMDb API key provided. The app will try only local filename/folder parsing. Continue?"):
                return
        self.preview_box.delete(1.0, tk.END)
        found = 0
        for p in self.files:
            ok = self._try_find_imdb_for_file(p)
            # if we found one, re-evaluate detection with new imdb info
            if ok:
                self.file_meta[p].setdefault('detected_type', None)
                detected, reason = determine_media_type(p, self.file_meta[p], apikey)
                self.file_meta[p]['detected_type'] = detected
                self.file_meta[p]['detect_reason'] = reason
            meta = self.file_meta.get(p, {})
            line = f"{p} -> detected: title={meta.get('title')} show={meta.get('show')} season={meta.get('season')} episode={meta.get('episode')} imdb={meta.get('imdb')} type={meta.get('detected_type')} reason={meta.get('detect_reason')}\n"
            self.preview_box.insert(tk.END, line)
            if ok:
                found += 1
        messagebox.showinfo("Lookup complete", f"Finished lookups. Found imdb IDs for {found}/{len(self.files)} files.")

    def build_new_name(self, old_path: str, index: int = 1) -> str:
        dirname, oldname = os.path.split(old_path)
        base, ext = os.path.splitext(oldname)
        meta = self.file_meta.get(old_path, {}) or {}
        imdb = normalize_imdb(meta.get('imdb') or self.imdb_var.get())
        # choose effective mode: user selection unless 'auto'
        effective_mode = self.mode_var.get()
        if effective_mode == 'auto':
            effective_mode = meta.get('detected_type') or 'movie'
        def tag():
            return f"[imdbid-{imdb}]" if imdb else ""
        if effective_mode == "movie":
            title = (meta.get('title') or self.title_var.get().strip() or base)
            title = sanitize_filename(title)
            year = meta.get('year') or self.year_var.get().strip()
            if year:
                newbase = f"{title} ({year})"
            else:
                newbase = f"{title}"
            newbase = f"{newbase} {tag()}" if tag() else newbase
            return os.path.join(dirname, newbase + ext)
        elif effective_mode == "tv":
            show = (meta.get('show') or self.show_var.get().strip() or base)
            show = sanitize_filename(show)
            s = meta.get('season') if meta.get('season') is not None else (int(self.season_var.get()) if self.season_var.get().strip() else None)
            e = meta.get('episode') if meta.get('episode') is not None else (int(self.episode_var.get()) if self.episode_var.get().strip() else None)
            if s is None or e is None:
                newbase = f"{show}"
            else:
                newbase = f"{show} - S{int(s):02d}E{int(e):02d}"
            newbase = f"{newbase} {tag()}" if tag() else newbase
            return os.path.join(dirname, newbase + ext)
        else:
            newbase = f"{base} {tag()}" if tag() else base
            return os.path.join(dirname, newbase + ext)

    def preview_rename(self):
        if not self.files:
            messagebox.showinfo("No files", "Please add one or more files to rename.")
            return
        self.preview_box.delete(1.0, tk.END)
        for i, p in enumerate(self.files, start=1):
            new = self.build_new_name(p, index=i)
            meta = self.file_meta.get(p, {})
            det = meta.get('detected_type') or 'unknown'
            reason = meta.get('detect_reason') or ''
            self.preview_box.insert(tk.END, f"{p} -> {new}\n    [detected: type={det} reason={reason} title={meta.get('title')} show={meta.get('show')} season={meta.get('season')} episode={meta.get('episode')} imdb={meta.get('imdb')}]\n\n")

    def rename_files(self):
        if not self.files:
            messagebox.showinfo("No files", "Please add files first.")
            return
        apikey = self.omdb_key_var.get().strip()
        # if in auto and no files have detection or imdbs, offer to auto-find
        if apikey and not any(self.file_meta.get(p, {}).get('imdb') for p in self.files):
            if messagebox.askyesno("Run lookups?", "No imdb IDs found for your files. Run OMDb lookups now?"):
                self.auto_find_imdbs()
        self.preview_rename()
        if not self.auto_apply.get():
            if not messagebox.askyesno("Confirm rename", "Rename the files shown in the preview? This will change files immediately."):
                return
        errors = []
        moved = []
        for i, p in enumerate(self.files, start=1):
            new = self.build_new_name(p, index=i)
            if os.path.abspath(p) == os.path.abspath(new):
                moved.append((p, new, "skipped - same name"))
                continue
            try:
                final = new
                count = 1
                while os.path.exists(final):
                    base, ext = os.path.splitext(new)
                    final = f"{base} ({count}){ext}"
                    count += 1
                os.rename(p, final)
                moved.append((p, final, "ok"))
            except Exception as e:
                errors.append((p, str(e)))
        out = []
        for src, dst, status in moved:
            out.append(f"OK: {src} -> {dst} ({status})")
        for src, err in errors:
            out.append(f"ERROR: {src} -> {err}")
        if out:
            self.preview_box.delete(1.0, tk.END)
            for line in out:
                self.preview_box.insert(tk.END, line + "\n")
        if errors:
            messagebox.showwarning("Finished with errors", f"Some files failed to rename (see preview). {len(errors)} error(s).")
        else:
            messagebox.showinfo("Done", "All files renamed successfully.")
            newfiles = []
            new_meta = {}
            for src, dst, status in moved:
                newfiles.append(dst)
                meta = self.file_meta.pop(src, {})
                new_meta[dst] = meta
            for leftover in self.file_meta:
                newfiles.append(leftover)
                new_meta[leftover] = self.file_meta[leftover]
            self.files = newfiles
            self.file_meta = new_meta
            self.files_listbox.delete(0, tk.END)
            for f in self.files:
                self.files_listbox.insert(tk.END, f)


if __name__ == "__main__":
    app = JellyRenamer()
    app.mainloop()

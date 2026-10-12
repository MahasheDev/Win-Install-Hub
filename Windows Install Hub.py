import os
import sys
import ctypes
import threading
import subprocess
import shutil
import time
import zipfile
import re
import json
import traceback
import glob
from html import unescape
from urllib.parse import urlparse, unquote, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
try:
    import winreg
except ImportError:
    winreg = None

if getattr(sys, "frozen", False):
    base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    os.environ.setdefault("TCL_LIBRARY", os.path.join(base, "tcl", "tcl8.6"))
    os.environ.setdefault("TK_LIBRARY", os.path.join(base, "tcl", "tk8.6"))
else:
    base = None

import customtkinter as ctk

APP_TITLE = "Win Install Hub"
APPDATA_ROOT = os.path.join(
    os.environ.get("APPDATA", os.getcwd()),
    "MahasheDev",
    "WinInstallHub",
)

CACHE_DIR = os.path.join(os.environ.get("TEMP", os.getcwd()), "Win-Install-Hub")
LOG_DIR = APPDATA_ROOT
LOG_PATH = os.path.join(LOG_DIR, "installhub.log")
ZAPRET_DIR = r"C:\Windows\_Zapret"
SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
if getattr(sys, "frozen", False):
    BUNDLE_DIR = getattr(sys, "_MEIPASS", SCRIPT_DIR)
else:
    BUNDLE_DIR = SCRIPT_DIR

SOURCE_DIR = os.path.join(CACHE_DIR, "Source")
SCRIPT_SOURCE_DIR = os.path.join(SCRIPT_DIR, "Source")
SCRIPT_SOURCE_OLD_DIR = os.path.join(SCRIPT_DIR, "Source_old")
BUNDLE_SOURCE_DIR = os.path.join(BUNDLE_DIR, "Source")
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")
SETTINGS_PATH = os.path.join(APPDATA_ROOT, "settings.json")
UI_SETTINGS = None

os.makedirs(APPDATA_ROOT, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(ZAPRET_DIR, exist_ok=True)
os.makedirs(SOURCE_DIR, exist_ok=True)

USER_APPS_COUNT = 0
CONFIG_STATE = "missing"
CONFIG_ERROR = ""
_log_lock = threading.Lock()
_error_lock = threading.Lock()
ERROR_LOG_PATH = None

def log(msg: str):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    with _log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    print(line, flush=True)

def _ensure_error_log_file():
    global ERROR_LOG_PATH
    if ERROR_LOG_PATH is None:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        ERROR_LOG_PATH = os.path.join(LOG_DIR, f"AppErrors.{ts}.txt")
    return ERROR_LOG_PATH

def log_error(msg: str):
    log("[ERROR] " + msg)
    try:
        path = _ensure_error_log_file()
        with _error_lock:
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass

def set_cache_dir(new_dir: str):
    global CACHE_DIR, SOURCE_DIR
    if not new_dir:
        return
    CACHE_DIR = new_dir
    SOURCE_DIR = os.path.join(CACHE_DIR, "Source")
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(SOURCE_DIR, exist_ok=True)
    log(f"set_cache_dir: CACHE_DIR={CACHE_DIR}, SOURCE_DIR={SOURCE_DIR}")

def set_log_dir(new_dir: str):
    global LOG_DIR, LOG_PATH
    if not new_dir:
        return
    LOG_DIR = new_dir
    os.makedirs(LOG_DIR, exist_ok=True)
    LOG_PATH = os.path.join(LOG_DIR, "installhub.log")
    log(f"set_log_dir: LOG_DIR={LOG_DIR}, LOG_PATH={LOG_PATH}")

def exception_hook(exctype, value, tb):
    text = "".join(traceback.format_exception(exctype, value, tb))
    log_error(f"UNHANDLED EXCEPTION:\n{text}")


sys.excepthook = exception_hook

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def elevate_if_needed():
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
    except Exception:
        return
    params = subprocess.list2cmdline(sys.argv[1:])
    exe = sys.executable
    log(f"elevate_if_needed: re-launching with admin, exe={exe}, params={params}")
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, SCRIPT_DIR, 1)
    if isinstance(rc, int) and rc > 32:
        sys.exit(0)

def first_url_ext(urls):
    for u in urls or []:
        p = u.split("?", 1)[0]
        ext = os.path.splitext(p)[1].lower()
        if ext:
            return ext
    return ""

def file_signature(path):
    if not os.path.exists(path):
        return "unknown"
    with open(path, "rb") as f:
        buf = f.read(512)
    if len(buf) >= 2 and buf[0] == 0x4D and buf[1] == 0x5A:
        return "exe"
    if len(buf) >= 2 and buf[0] == 0x50 and buf[1] == 0x4B:
        return "zip"
    if len(buf) >= 6 and buf[0] == 0x37 and buf[1] == 0x7A:
        return "7z"
    text = buf.decode("ascii", errors="ignore").lstrip().lower()
    if text.startswith("<!doctype") or text.startswith("<html"):
        return "html"
    return "unknown"

def _sanitize_filename(name: str) -> str:
    name = os.path.basename(name or "").strip().replace("\x00", "")
    allowed = " -_.()[]{}!@#$%^&+,=~"
    clean = "".join(ch for ch in name if ch.isalnum() or ch in allowed)
    return clean or "download.bin"

def _filename_from_cd(cd: str):
    if not cd:
        return None
    m = re.search(r"filename\*=\s*(?:UTF-8'')?(\"?)([^\";]+)\1", cd, re.I)
    if m:
        return unquote(m.group(2))
    m = re.search(r'filename=\s*"?([^";]+)"?', cd, re.I)
    if m:
        return m.group(1)
    return None

def _name_from_url(u: str):
    path = urlparse(u).path
    base = os.path.basename(path)
    return unquote(base) if base else None

def download(urls, dest_path, retry=2, timeout=90):
    dest_dir = os.path.dirname(dest_path)
    os.makedirs(dest_dir, exist_ok=True)
    fallback_name = os.path.basename(dest_path)
    log(f"download: dest_dir={dest_dir}, fallback_name={fallback_name}, urls={urls}")
    for u in urls:
        for i in range(retry + 1):
            try:
                log(f"download: GET {u}, attempt {i + 1}")
                with requests.get(
                    u,
                    headers={"User-Agent": "InstallHubPY"},
                    stream=True,
                    timeout=timeout,
                    allow_redirects=True,
                ) as r:
                    r.raise_for_status()

                    cd = r.headers.get("content-disposition", "")
                    name = (
                        _filename_from_cd(cd)
                        or _name_from_url(r.url)
                        or _name_from_url(u)
                        or fallback_name
                    )
                    name = _sanitize_filename(name)

                    if not os.path.splitext(name)[1] and os.path.splitext(fallback_name)[1]:
                        name += os.path.splitext(fallback_name)[1]

                    final_path = os.path.join(dest_dir, name)
                    tmp = final_path + ".part"
                    if os.path.exists(tmp):
                        os.remove(tmp)

                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1 << 20):
                            if chunk:
                                f.write(chunk)

                os.replace(tmp, final_path)
                log(f"download: saved -> {final_path}")
                return final_path

            except Exception as e:
                log_error(f"download error [{u}] attempt={i + 1}: {e}")
                time.sleep(2 * i + 1)

    raise RuntimeError("Не удалось скачать ни по одному URL")

# ---------------- VC++ 2005–2022 (статический список) ----------------
VC_REDISTS_STATIC = [
    # 2005
    {
        "name": "Visual C++ 2005 SP1 x86",
        "url": "https://download.microsoft.com/download/1/1/1/11111111-1111-1111-1111-111111111111/vcredist_x86_2005_SP1.exe",
    },
    {
        "name": "Visual C++ 2005 SP1 x64",
        "url": "https://download.microsoft.com/download/2/2/2/22222222-2222-2222-2222-222222222222/vcredist_x64_2005_SP1.exe",
    },
    # 2008
    {
        "name": "Visual C++ 2008 SP1 x86",
        "url": "https://download.microsoft.com/download/3/3/3/33333333-3333-3333-3333-333333333333/vcredist_x86_2008_SP1.exe",
    },
    {
        "name": "Visual C++ 2008 SP1 x64",
        "url": "https://download.microsoft.com/download/4/4/4/44444444-4444-4444-4444-444444444444/vcredist_x64_2008_SP1.exe",
    },
    # 2010
    {
        "name": "Visual C++ 2010 SP1 x86",
        "url": "https://download.microsoft.com/download/5/5/5/55555555-5555-5555-5555-555555555555/vcredist_x86_2010_SP1.exe",
    },
    {
        "name": "Visual C++ 2010 SP1 x64",
        "url": "https://download.microsoft.com/download/6/6/6/66666666-6666-6666-6666-666666666666/vcredist_x64_2010_SP1.exe",
    },
    # 2012 Update 4
    {
        "name": "Visual C++ 2012 Update 4 x86",
        "url": "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/vcredist_x86.exe",
    },
    {
        "name": "Visual C++ 2012 Update 4 x64",
        "url": "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/vcredist_x64.exe",
    },
    # 2013
    {
        "name": "Visual C++ 2013 x86",
        "url": "https://aka.ms/vs/12/release/vcredist_x86.exe",
    },
    {
        "name": "Visual C++ 2013 x64",
        "url": "https://aka.ms/vs/12/release/vcredist_x64.exe",
    },
    # 2015–2022
    {
        "name": "Visual C++ 2015–2022 x86",
        "url": "https://aka.ms/vs/17/release/vc_redist.x86.exe",
    },
    {
        "name": "Visual C++ 2015–2022 x64",
        "url": "https://aka.ms/vs/17/release/vc_redist.x64.exe",
    },
]

def install_vc_redist_all(interactive: bool = True) -> bool:
    if not VC_REDISTS_STATIC:
        log_error("vc_redist_all error: Список VC++ redistributables пуст — не задан ни один URL")
        return False

    any_ok = False

    for item in VC_REDISTS_STATIC:
        name = item.get("name") or "VC++"
        url = item.get("url") or ""
        if not url:
            log_error(f"vc_redist_all: пропуск {name} — пустой URL")
            continue

        try:
            base_name = os.path.basename(url.split("?", 1)[0]) or name
            base_name = _sanitize_filename(base_name)
            if not base_name.lower().endswith(".exe"):
                base_name += ".exe"

            dest = os.path.join(CACHE_DIR, base_name)
            log(f"vc_redist_all: скачивание {name} из {url} -> {dest}")
            dl_path = download([url], dest)
            sig = file_signature(dl_path)
            log(f"vc_redist_all: {name} сигнатура={sig}, путь={dl_path}")

            if sig == "html":
                log_error(f"vc_redist_all: {name}: вместо EXE скачан HTML — пропуск")
                continue

            try:
                install_exe(dl_path, silent_args="/quiet /norestart", interactive=interactive)
                any_ok = True
            except Exception as e:
                log_error(f"vc_redist_all: ошибка установки {name}: {e}")
        except Exception:
            log_error(f"vc_redist_all: фатальная ошибка для {name}:\n{traceback.format_exc()}")

    if not any_ok:
        log_error("vc_redist_all: не удалось корректно установить ни один VC++ пакет")
    else:
        log("vc_redist_all: цикл установки VC++ завершён")

    return any_ok


if os.name == "nt":
    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    INFINITE = 0xFFFFFFFF

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", ctypes.c_ulong),
            ("fMask", ctypes.c_ulong),
            ("hwnd", ctypes.c_void_p),
            ("lpVerb", ctypes.c_wchar_p),
            ("lpFile", ctypes.c_wchar_p),
            ("lpParameters", ctypes.c_wchar_p),
            ("lpDirectory", ctypes.c_wchar_p),
            ("nShow", ctypes.c_int),
            ("hInstApp", ctypes.c_void_p),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", ctypes.c_wchar_p),
            ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", ctypes.c_ulong),
            ("hIcon", ctypes.c_void_p),
            ("hProcess", ctypes.c_void_p),
        ]

    ShellExecuteExW = ctypes.windll.shell32.ShellExecuteExW
    WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
    GetExitCodeProcess = ctypes.windll.kernel32.GetExitCodeProcess
    CloseHandle = ctypes.windll.kernel32.CloseHandle

    def _shell_execute_wait(exe_path: str, params: str, verb: str | None) -> int:
        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = verb
        sei.lpFile = exe_path
        sei.lpParameters = params
        sei.lpDirectory = os.path.dirname(exe_path) or None
        sei.nShow = 1
        if not ShellExecuteExW(ctypes.byref(sei)):
            raise OSError("ShellExecuteExW failed")
        try:
            WaitForSingleObject(sei.hProcess, INFINITE)
            code = ctypes.c_ulong(0)
            GetExitCodeProcess(sei.hProcess, ctypes.byref(code))
            return int(code.value)
        finally:
            CloseHandle(sei.hProcess)

    def _runas_cmd(cmdline: str):
        sei = SHELLEXECUTEINFOW()
        sei.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = "cmd.exe"
        sei.lpParameters = f"/c {cmdline}"
        sei.lpDirectory = None
        sei.nShow = 1
        if not ShellExecuteExW(ctypes.byref(sei)):
            raise OSError("ShellExecuteExW failed")
        try:
            WaitForSingleObject(sei.hProcess, INFINITE)
        finally:
            CloseHandle(sei.hProcess)

else:

    def _shell_execute_wait(exe_path: str, params: str, verb: str | None) -> int:
        raise OSError("ShellExecuteExW not supported on this OS")

    def _runas_cmd(cmdline: str):
        raise OSError("ShellExecuteExW not supported on this OS")


def get_latest_russian_winrar_url() -> str:
    url = "https://www.rarlab.com/download.htm"
    log(f"WinRAR: запрос страницы {url}")
    resp = requests.get(url, timeout=30, headers={"User-Agent": "WinInstallHub/2"})
    resp.raise_for_status()
    russian_links = []
    pattern = r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>'
    for href, label in re.findall(pattern, resp.text, flags=re.IGNORECASE | re.DOTALL):
        text = unescape(re.sub(r"<[^>]+>", "", label)).strip().lower()
        filename = os.path.basename(urlparse(href).path).lower()
        if "russian" in text and filename.endswith(".exe") and "x64" in filename:
            russian_links.append(urljoin(url, href))
    if not russian_links:
        raise RuntimeError("WinRAR: не найден русский установщик.")

    stable_links = [link for link in russian_links if not re.search(r"b\d+ru\.exe$", link.lower())]
    candidates = stable_links or russian_links

    def version_key(link):
        filename = os.path.basename(urlparse(link).path).lower()
        match = re.search(r"x64-(\d+)(?:b(\d+))?ru\.exe$", filename)
        if not match:
            return (0, 0, 0)
        raw = match.group(1)
        major = int(raw[0]) if raw else 0
        minor = int(raw[1:]) if len(raw) > 1 else 0
        beta = int(match.group(2) or 0)
        return (major, minor, beta)

    full = max(candidates, key=version_key)
    log(f"WinRAR: найден русский инсталлер {full}")
    return full


def get_latest_python_windows_url() -> str:
    page_url = "https://www.python.org/downloads/windows/"
    log(f"Python: запрос страницы {page_url}")
    resp = requests.get(page_url, timeout=30, headers={"User-Agent": "WinInstallHub/2"})
    resp.raise_for_status()
    pattern = r'href=["\']([^"\']*python-(\d+\.\d+\.\d+)-amd64\.exe)["\']'
    candidates = []
    for href, version in re.findall(pattern, resp.text, flags=re.IGNORECASE):
        version_key = tuple(int(part) for part in version.split("."))
        candidates.append((version_key, urljoin(page_url, href)))
    if not candidates:
        raise RuntimeError("Python: не найден стабильный Windows x64 установщик.")
    version, link = max(candidates, key=lambda item: item[0])
    log(f"Python: найден установщик {'.'.join(map(str, version))} {link}")
    return link


def get_latest_vencord_installer_url() -> str:
    page_url = "https://vencord.dev/download/"
    log(f"Vencord: запрос страницы {page_url}")
    resp = requests.get(page_url, timeout=30, headers={"User-Agent": "WinInstallHub/2"})
    resp.raise_for_status()
    matches = re.findall(
        r'href=["\']([^"\']*VencordInstaller\.exe(?:\?[^"\']*)?)["\']',
        resp.text,
        flags=re.IGNORECASE,
    )
    if not matches:
        raise RuntimeError("Vencord: ссылка на официальный установщик не найдена.")
    link = urljoin(page_url, unescape(matches[0]))
    log(f"Vencord: найден официальный установщик {link}")
    return link


def get_latest_github_asset_url(repo: str, pattern: str) -> str:
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    log(f"GitHub: запрос свежего релиза {repo}")
    resp = requests.get(api_url, timeout=30, headers={"User-Agent": "WinInstallHub/2"})
    resp.raise_for_status()
    data = resp.json()
    for asset in data.get("assets") or []:
        name = asset.get("name") or ""
        link = asset.get("browser_download_url") or ""
        if link and re.search(pattern, name, flags=re.IGNORECASE):
            log(f"GitHub: найден установщик {repo} {name}")
            return link
    raise RuntimeError(f"GitHub: Windows x64 установщик {repo} не найден.")


def get_latest_skydimo_url() -> str:
    page_url = "https://skydimo.com/en/download/windows"
    log(f"SkyDimo: запрос страницы {page_url}")
    resp = requests.get(page_url, timeout=30, headers={"User-Agent": "WinInstallHub/2"})
    resp.raise_for_status()
    matches = re.findall(
        r'href=["\']([^"\']*/Skydimo-[^"\']+\.exe(?:\?[^"\']*)?)["\']',
        resp.text,
        flags=re.IGNORECASE,
    )
    if not matches:
        raise RuntimeError("SkyDimo: Recommended Windows установщик не найден.")
    link = urljoin(page_url, unescape(matches[0]))
    log(f"SkyDimo: найден Recommended установщик {link}")
    return link


def get_latest_nvidia_rtx5070_driver_url() -> str:
    target_os = "Windows 11" if sys.getwindowsversion().build >= 22000 else "Windows 10 64-bit"
    api_url = "https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php"
    params = {
        "func": "DriverManualLookup",
        "pfid": "1070",
        "osID": "57",
        "languageCode": "1033",
        "beta": "0",
        "isWHQL": "1",
        "dltype": "-1",
        "dch": "1",
        "sort1": "0",
        "numberOfResults": "1",
    }
    log(f"NVIDIA: запрос свежего WHQL Game Ready драйвера для GeForce RTX 5070, {target_os}")
    resp = requests.get(api_url, params=params, timeout=30, headers={"User-Agent": "WinInstallHub/2"})
    resp.raise_for_status()
    data = resp.json()
    for item in data.get("IDS") or []:
        info = item.get("downloadInfo") or {}
        supported = " ".join(
            unquote(entry.get("OSName") or "")
            for entry in info.get("OSList") or []
        ).lower()
        link = info.get("DownloadURL") or ""
        if target_os.lower() in supported and link:
            version = info.get("Version") or "?"
            log(f"NVIDIA: найден драйвер {version} для {target_os} {link}")
            return link
    raise RuntimeError(f"NVIDIA: свежий драйвер RTX 5070 для {target_os} не найден.")


DYNAMIC_INSTALLERS = {
    "karing": lambda: get_latest_github_asset_url("KaringX/karing", r"windows_x64\.exe$"),
    "skydimo": get_latest_skydimo_url,
    "soundswitch": lambda: get_latest_github_asset_url("Belphemur/SoundSwitch", r"Release_Installer\.exe$"),
    "pulsesync": lambda: get_latest_github_asset_url("PulseSync-LLC/PulseSync-client", r"-x64\.exe$"),
    "nvidia_rtx5070": get_latest_nvidia_rtx5070_driver_url,
}


def launch_vencord_installer(path: str):
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if file_signature(path) != "exe":
        raise RuntimeError("Vencord: загруженный файл не является EXE.")
    subprocess.Popen(["explorer.exe", path])
    log(f"Vencord: установщик запущен без наследования повышенных прав {path}")

def download_winrar_russian() -> str:
    link = get_latest_russian_winrar_url()
    dest = os.path.join(CACHE_DIR, "winrar_ru.exe")
    log(f"WinRAR: скачивание {link} -> {dest}")
    path = download([link], dest)
    return path

def _probe_install_dir_from_registry() -> str | None:
    if winreg is None:
        return None

    def _open(root, sub, acc=winreg.KEY_READ):
        try:
            return winreg.OpenKey(root, sub, 0, acc)
        except FileNotFoundError:
            return None

    def _read_str(key, name):
        if not key:
            return None
        try:
            val, _ = winreg.QueryValueEx(key, name)
            return str(val)
        except Exception:
            return None

    for hive in (r"SOFTWARE\WinRAR", r"SOFTWARE\WOW6432Node\WinRAR"):
        k = _open(winreg.HKEY_LOCAL_MACHINE, hive, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0))
        exepath = _read_str(k, "ExePath")
        if exepath and os.path.isfile(exepath):
            return os.path.dirname(exepath)

    k = _open(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe",
        winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
    )
    p = _read_str(k, None) or _read_str(k, "Path")
    if p and os.path.isdir(p):
        return p

    def scan_uninstall(base):
        k0 = _open(winreg.HKEY_LOCAL_MACHINE, base, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0))
        if not k0:
            return None
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(k0, i)
                i += 1
            except OSError:
                break
            ks = _open(
                winreg.HKEY_LOCAL_MACHINE,
                base + "\\" + sub,
                winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0),
            )
            dn = None
            try:
                dn, _ = winreg.QueryValueEx(ks, "DisplayName")
            except Exception:
                pass
            if dn and "WinRAR" in str(dn):
                loc = _read_str(ks, "InstallLocation")
                if loc and os.path.isdir(loc):
                    return loc
                un = _read_str(ks, "UninstallString")
                if un:
                    head = un.strip().strip('"').split()[0].strip('"')
                    if os.path.isfile(head):
                        return os.path.dirname(head)
        return None

    for base in (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ):
        loc = scan_uninstall(base)
        if loc:
            return loc

    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env)
        if base:
            p = os.path.join(base, "WinRAR")
            if os.path.isdir(p):
                return p

    return None


def _wait_full_install(timeout_sec: int = 300) -> str:
    log("WinRAR: ожидание полной установки (uninstall.exe и WinRAR.exe)")
    start = time.time()
    while time.time() - start < timeout_sec:
        inst = _probe_install_dir_from_registry()
        if inst:
            u = os.path.join(inst, "uninstall.exe")
            w = os.path.join(inst, "WinRAR.exe")
            if os.path.isfile(u) and os.path.isfile(w):
                log(f"WinRAR: найден установленный каталог {inst}")
                return inst
        time.sleep(2)
    raise TimeoutError("WinRAR: не дождался появления uninstall.exe/WinRAR.exe")


def install_winrar(installer_path: str):
    log(f"WinRAR: запуск установщика {installer_path}")
    last_err = None
    for verb, params in (("runas", ""), (None, ""), (None, "")):
        try:
            code = _shell_execute_wait(installer_path, params, verb)
            log(f"WinRAR: установщик завершился с кодом {code}")
            return
        except Exception as e:
            last_err = e
            log_error(f"WinRAR: ошибка запуска (verb={verb}): {e}")
    raise RuntimeError(f"WinRAR: не удалось запустить установщик: {last_err}")


def get_assets_dir() -> str:
    pm = detect_py_modules_file()
    if pm and os.path.isfile(pm):
        return os.path.dirname(pm)
    for d in (BUNDLE_SOURCE_DIR, SCRIPT_SOURCE_DIR, SCRIPT_SOURCE_OLD_DIR, SOURCE_DIR):
        if os.path.isdir(d):
            return d
    return SCRIPT_DIR


def _resolve_rarreg_source() -> str:
    base = get_assets_dir()
    candidates = [
        os.path.join(base, "rarreg.key"),
        os.path.join(base, "Source", "rarreg.key"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    raise FileNotFoundError("WinRAR: rarreg.key не найден рядом с python-modules.txt")


def _resolve_winrar_icon() -> str | None:
    base = get_assets_dir()
    names = ["winrar.ico", "WinRAR.ico", "WinRAR_icon.ico"]
    for n in names:
        p = os.path.join(base, n)
        if os.path.isfile(p):
            return p
    for n in os.listdir(base):
        if "rar" in n.lower() and n.lower().endswith(".ico"):
            p = os.path.join(base, n)
            if os.path.isfile(p):
                return p
    return None


def _copy_rarreg(install_dir: str, src: str | None = None):
    src = src or _resolve_rarreg_source()
    dst = os.path.join(install_dir, "rarreg.key")
    shutil.copyfile(src, dst)
    log(f"WinRAR: rarreg.key скопирован в {dst}")


def _delete_default_profiles():
    base = r"HKEY_CURRENT_USER\SOFTWARE\WinRAR\Profiles"
    log("WinRAR: удаление дефолтных профилей 1..5")
    for i in range(1, 6):
        subprocess.run(
            ["reg", "delete", fr"{base}\{i}", "/f"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def swap_icons_exact(icon_path: str):
    if not os.path.isfile(icon_path):
        raise FileNotFoundError(icon_path)

    cmds = [
        fr'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WinRAR\DefaultIcon" /f /ve /t REG_SZ /d "{icon_path}"',
        fr'reg add "HKEY_CLASSES_ROOT\WinRAR\DefaultIcon" /f /ve /t REG_SZ /d "{icon_path}"',
        fr'reg add "HKEY_CLASSES_ROOT\WinRAR.ZIP\DefaultIcon" /f /ve /t REG_SZ /d "{icon_path}"',
        fr'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WinRAR.ZIP\DefaultIcon" /f /ve /t REG_SZ /d "{icon_path}"',
    ]
    for c in cmds:
        try:
            _runas_cmd(c)
        except Exception as e:
            log_error(f"WinRAR: reg add ошибка: {e}")

    try:
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)
        ie4u = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "ie4uinit.exe")
        if os.path.isfile(ie4u):
            subprocess.run(
                [ie4u, "-ClearIconCache"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass
    log("WinRAR: иконки обновлены")


def install_winrar_full(interactive: bool = True) -> bool:
    try:
        installer = download_winrar_russian()
        install_winrar(installer)
        install_dir = _wait_full_install(timeout_sec=300)
        try:
            _copy_rarreg(install_dir, None)
        except Exception as e:
            log_error(f"WinRAR: ошибка копирования rarreg.key: {e}")
        try:
            icon = _resolve_winrar_icon()
            if icon:
                swap_icons_exact(icon)
            else:
                log("WinRAR: иконка не найдена рядом с python-modules.txt — пропуск смены иконок")
        except Exception as e:
            log_error(f"WinRAR: ошибка смены иконок: {e}")
        try:
            os.remove(installer)
        except Exception:
            pass
        log("WinRAR: полная установка завершена")
        return True
    except Exception:
        log_error("WinRAR: фатальная ошибка установки:\n" + traceback.format_exc())
        return False

def expand_any_archive(archive_path, destination):
    os.makedirs(destination, exist_ok=True)
    sig = file_signature(archive_path)
    log(f"expand_any_archive: path={archive_path}, dest={destination}, sig={sig}")
    if sig == "zip":
        try:
            with zipfile.ZipFile(archive_path, "r") as z:
                z.extractall(destination)
            log("expand_any_archive: ZIP extracted ok")
            return
        except Exception as e:
            log_error(f"ZIP expand error: {e}")
    seven = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "7-Zip", "7z.exe")
    if os.path.exists(seven):
        cp = subprocess.run(
            [seven, "x", archive_path, f"-o{destination}", "-y"],
            capture_output=True,
            text=True,
        )
        log(f"expand_any_archive: 7z exit={cp.returncode}")
        if cp.returncode != 0:
            log_error(f"7z error: {cp.returncode} {cp.stderr[:300]}")
    else:
        shutil.copy2(archive_path, os.path.join(destination, os.path.basename(archive_path)))
        log("expand_any_archive: no 7z, copied archive as-is")

def install_msi(path, silent_args="/qn /norestart", interactive=True):
    args = ["msiexec.exe", "/i", path] if interactive else ["msiexec.exe", "/i", path, *silent_args.split()]
    log("install_msi RUN: " + " ".join(args))
    cp = subprocess.run(args)
    log(f"install_msi: exit={cp.returncode}")
    if cp.returncode != 0:
        log_error(f"MSI exit {cp.returncode}")
        raise RuntimeError(f"MSI exit {cp.returncode}")

def install_exe(path, silent_args="/S", interactive=True):
    args = [path] if interactive else [path, *([silent_args] if silent_args and silent_args.strip() else [])]
    log("install_exe RUN: " + " ".join(args))
    cp = subprocess.run(args)
    log(f"install_exe: first run exit={cp.returncode}")
    if cp.returncode != 0:
        log(f"install_exe: retry GUI: {path}")
        cp2 = subprocess.run([path])
        log(f"install_exe: second run exit={cp2.returncode}")
        if cp2.returncode != 0:
            log_error(f"EXE exit {cp2.returncode}: {path}")
            raise RuntimeError(f"EXE exit {cp2.returncode}")

def have_winget():
    try:
        cp = subprocess.run(["winget", "--version"], capture_output=True, text=True)
        log(f"have_winget: exit={cp.returncode}, out={cp.stdout.strip()!r}")
        return cp.returncode == 0
    except Exception as e:
        log_error(f"have_winget error: {e}")
        return False

def winget_install(ids, interactive=True):
    if not have_winget():
        log("winget_install: winget not available")
        return False
    for pkg in ids:
        args = [
            "winget",
            "install",
            "--id",
            pkg,
            "-e",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ]
        args += ["--interactive"] if interactive else ["--silent"]
        log("winget_install RUN: " + " ".join(args))
        cp = subprocess.run(args)
        log(f"winget_install: {pkg} exit={cp.returncode}")
        if cp.returncode == 0:
            return True
        log_error(f"winget error {pkg}: exit {cp.returncode}")
    return False

def create_shortcut(lnk_path, target, working_dir=None, icon=None, args=""):
    try:
        import win32com.client
    except Exception:
        log("create_shortcut: pywin32 не установлен — пропуск .lnk")
        return
    try:
        wsh = win32com.client.Dispatch("WScript.Shell")
        lnk = wsh.CreateShortcut(lnk_path)
        lnk.TargetPath = target
        if working_dir:
            lnk.WorkingDirectory = working_dir
        if icon:
            lnk.IconLocation = icon
        if args:
            lnk.Arguments = args
        lnk.WindowStyle = 1
        lnk.Save()
        log(f"create_shortcut: -> {lnk_path}")
    except Exception as e:
        log_error(f"Shortcut error: {e}")

def deploy_zapret(archive_path):
    os.makedirs(ZAPRET_DIR, exist_ok=True)
    log(f"deploy_zapret: archive={archive_path}, dest={ZAPRET_DIR}")
    expand_any_archive(archive_path, ZAPRET_DIR)
    desktops = []
    if os.environ.get("USERPROFILE"):
        desktops.append(os.path.join(os.environ["USERPROFILE"], "Desktop"))
    desktops.append(os.path.join(os.environ.get("Public", r"C:\Users\Public"), "Desktop"))
    desktops = [d for d in desktops if os.path.isdir(d)]
    for d in desktops:
        lnk = os.path.join(d, "Zapret service.lnk")
        create_shortcut(
            lnk,
            os.path.join(ZAPRET_DIR, "service.bat"),
            ZAPRET_DIR,
            r"%SystemRoot%\System32\imageres.dll,13",
        )
    log(f"deploy_zapret: done, desktops={desktops}")


def deploy_gigabyte_control_center(archive_path, interactive=True):
    extract_dir = os.path.join(SOURCE_DIR, "gigabyte_control_center")
    if os.path.isdir(extract_dir):
        shutil.rmtree(extract_dir)
    expand_any_archive(archive_path, extract_dir)
    candidates = []
    priorities = {
        "setup.exe": 0,
        "gcc.exe": 1,
        "gigabyte control center.exe": 2,
    }
    for root, dirs, files in os.walk(extract_dir):
        for name in files:
            lowered = name.lower()
            if lowered in priorities:
                path = os.path.join(root, name)
                depth = path[len(extract_dir):].count(os.sep)
                candidates.append((priorities[lowered], depth, path))
    if not candidates:
        raise RuntimeError("GIGABYTE Control Center: установщик в архиве не найден.")
    installer = min(candidates)[2]
    log(f"GIGABYTE Control Center: запуск {installer}")
    install_exe(installer, silent_args="/S", interactive=interactive)

CATALOG = [
    {
        "key": "karing",
        "name": "Karing (последняя стабильная)",
        "type": "exe",
        "silent": "",
        "urls": ["https://github.com/KaringX/karing/releases/latest"],
        "winget": ["KaringX.Karing"],
    },
    {
        "key": "zapret",
        "name": "Zapret",
        "type": "zip",
        "silent": "",
        "urls": [
            "https://github.com/Flowseal/zapret-discord-youtube/releases/download/1.8.3/zapret-discord-youtube-1.8.3.zip"
        ],
        "winget": [],
    },
    {
        "key": "chrome",
        "name": "Google Chrome",
        "type": "msi",
        "silent": "/qn /norestart",
        "urls": [
            "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
        ],
        "winget": ["Google.Chrome"],
    },
    {
        "key": "discord",
        "name": "Discord",
        "type": "exe",
        "silent": "",
        "urls": ["https://discord.com/api/download?platform=win"],
        "winget": ["Discord.Discord"],
    },
    {
        "key": "vencord",
        "name": "Vencord для Discord",
        "type": "exe",
        "silent": "",
        "urls": ["https://vencord.dev/download/"],
        "winget": [],
    },
    {
        "key": "7zip",
        "name": "7-Zip",
        "type": "exe",
        "silent": "/S",
        "urls": ["https://www.7-zip.org/a/7z2409-x64.exe"],
        "winget": ["7zip.7zip"],
    },
    {
        "key": "3utools",
        "name": "3uTools",
        "type": "exe",
        "silent": "/S",
        "urls": ["https://url2.3u.com/MNBBfyaa"],
        "winget": ["3u.3uTools"],
    },
    {
        "key": "imazing",
        "name": "iMazing",
        "type": "exe",
        "silent": "/S",
        "urls": ["https://downloads.imazing.com/windows/iMazing/iMazing3forWindows.exe"],
        "winget": ["DigiDNA.iMazing"],
    },
    {
        "key": "everything",
        "name": "Everything",
        "type": "exe",
        "silent": "/S",
        "urls": ["https://www.voidtools.com/Everything-1.4.1.1023.x64-Setup.exe"],
        "winget": ["voidtools.Everything"],
    },
    {
        "key": "autohotkey",
        "name": "AutoHotkey v2",
        "type": "exe",
        "silent": "/S",
        "urls": ["https://www.autohotkey.com/download/ahk-v2.exe"],
        "winget": ["AutoHotkey.AutoHotkey"],
    },
    {
        "key": "qbittorrent",
        "name": "qBittorrent",
        "type": "exe",
        "silent": "/S",
        "urls": [
            "https://downloads.sourceforge.net/project/qbittorrent/qbittorrent-win32/qbittorrent-4.6.6/qbittorrent_4.6.6_x64_setup.exe"
        ],
        "winget": ["qBittorrent.qBittorrent"],
    },
    {
        "key": "qttabbar",
        "name": "QtTabBar Setup",
        "type": "exe",
        "silent": "/S",
        "urls": [
            "https://mahashe.su/files/QtTabBarSetup.exe"
        ],
        "winget": ["qttabbar.qttabbar"],
    },
    {
        "key": "Upscayl",
        "name": "Upscayl — апскейл фото",
        "type": "exe",
        "silent": "",
        "urls": [
            "https://github.com/upscayl/upscayl/releases/download/v2.15.0/upscayl-2.15.0-win.exe"
        ],
        "winget": [],
    },
    {
        "key": "winrarinstaller",
        "name": "WinRaR",
        "type": "custom",
        "silent": "",
        "urls": [],
        "winget": [],
    },
    {
        "key": "steam",
        "name": "Steam",
        "type": "exe",
        "silent": "/S",
        "urls": [
            "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe"
        ],
        "winget": ["Valve.Steam"],
    },
    {
        "key": "rockstar",
        "name": "Rockstar Games Launcher",
        "type": "exe",
        "silent": "/S",
        "urls": [
            "https://gamedownloads.rockstargames.com/public/installer/Rockstar-Games-Launcher.exe"
        ],
        "winget": ["RockstarGames.RockstarGamesLauncher"],
    },
    {
        "key": "crossout",
        "name": "Crossout Launcher",
        "type": "exe",
        "silent": "/S",
        "urls": [
            "https://yupmaster.gaijinent.com/launcher/current.php?id=CrossoutLauncher"
        ],
        "winget": [],
    },
    {
        "key": "epic",
        "name": "Epic Games Launcher",
        "type": "msi",
        "silent": "/qn /norestart",
        "urls": [
            "https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi"
        ],
        "winget": ["EpicGames.EpicGamesLauncher"],
    },
    {
        "key": "uplay",
        "name": "Ubisoft Connect",
        "type": "exe",
        "silent": "/S",
        "urls": [
            "https://ubistatic3-a.akamaihd.net/orbit/launcher_installer/UbisoftConnectInstaller.exe"
        ],
        "winget": ["Ubisoft.Connect"],
    },
    {
        "key": "notepadpp",
        "name": "Notepad++",
        "type": "exe",
        "silent": "/S",
        "urls": [
            "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.8.8/npp.8.8.8.Installer.x64.exe"
        ],
        "winget": ["Notepad++.Notepad++"],
    },
    {
        "key": "vscode",
        "name": "Visual Studio Code",
        "type": "exe",
        "silent": "/VERYSILENT /NORESTART /MERGETASKS=addcontextmenufiles,addcontextmenufolders,addtopath",
        "urls": [
            "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user"
        ],
        "winget": ["Microsoft.VisualStudioCode"],
    },
    {
        "key": "skydimo",
        "name": "SkyDimo (Recommended, последняя версия)",
        "type": "exe",
        "silent": "",
        "urls": ["https://skydimo.com/en/download/windows"],
        "winget": [],
    },
    {
        "key": "soundswitch",
        "name": "SoundSwitch (последняя стабильная)",
        "type": "exe",
        "silent": "",
        "urls": ["https://github.com/Belphemur/SoundSwitch/releases/latest"],
        "winget": ["AntoineAflalo.SoundSwitch"],
    },
    {
        "key": "pulsesync",
        "name": "PulseSync (последняя версия)",
        "type": "exe",
        "silent": "",
        "urls": ["https://github.com/PulseSync-LLC/PulseSync-client/releases/latest"],
        "winget": [],
    },
    {
        "key": "gigabyte_control_center",
        "name": "GIGABYTE Control Center",
        "type": "zip",
        "silent": "",
        "urls": ["https://download.gigabyte.com/FileList/Utility/GCC_26.09.10.01.zip"],
        "winget": [],
    },
    {
        "key": "wfdownloader",
        "name": "WF Downloader",
        "type": "exe",
        "silent": "",
        "urls": [
            "https://mahashe.su/Files/WFDownloaderApp-BETA-64bit.exe"
        ],
        "winget": [],
    },
    {
        "key": "coubarchiver",
        "name": "Coub Archiver",
        "type": "exe",
        "silent": "",
        "urls": [
            "https://mahashe.su/Files/coub_archiver_v23.exe"
        ],
        "winget": [],
    },
    {
        "key": "YouTubeToMP3",
        "name": "YouTube To MP3",
        "type": "exe",
        "silent": "",
        "urls": [
            "https://mahashe.su/Files/YouTubeToMP3-x64.exe"
        ],
        "winget": [],
    },
    {
        "key": "filezilla",
        "name": "FileZilla (open site)",
        "type": "link",
        "silent": "",
        "urls": ["https://filezilla-project.org/download.php?type=client"],
        "winget": [],
    },
    # Дополнительные утилиты (rsload)
    {
        "key": "minitoolpw13",
        "name": "MiniTool Partition Wizard V13.0 (rsload)",
        "type": "custom",
        "silent": "",
        "urls": [
            "https://mahashe.su/Files/minitool.partition.wizard.V13.0.rar"
        ],
        "winget": [],
    },
    {
        "key": "aida64v675",
        "name": "AIDA64 v6.75 (rsload)",
        "type": "exe",
        "silent": "",
        "urls": [
            "https://mahashe.su/Files/AIDA64.v6.75.6100.exe"
        ],
        "winget": [],
    },
    {
        "key": "nvidia_rtx5070",
        "name": "NVIDIA RTX 5070 — свежий Game Ready драйвер",
        "type": "exe",
        "silent": "-s",
        "urls": ["https://www.nvidia.com/en-us/geforce/drivers/"],
        "winget": [],
    },
    # Компоненты
    {
        "key": "vc_redist_all",
        "name": "VC++ 2005–2022 (все пакеты)",
        "type": "custom",
        "silent": "",
        "urls": [],
        "winget": [],
    },
    {
        "key": "webview2",
        "name": "Microsoft WebView2",
        "type": "exe",
        "silent": "/silent /install",
        "urls": ["https://go.microsoft.com/fwlink/p/?LinkId=2124703"],
        "winget": [],
    },
    {
        "key": "java_site",
        "name": "Java — открыть сайт",
        "type": "link",
        "silent": "",
        "urls": ["https://www.java.com/ru/download/"],
        "winget": [],
    },
    {
        "key": "hevc",
        "name": "Кодеки HEVC (APPX)",
        "type": "custom",
        "silent": "",
        "urls": [
            "https://mahashe.su/Files/Microsoft.HEVCVideoExtension_2.0.53348.0_x64__8wekyb3d8bbwe.Appx"
        ],
        "winget": [],
    },
    {
        "key": "dotnet_sdk_7_0_102",
        "name": ".NET SDK 7.0.102",
        "type": "exe",
        "silent": "/quiet /norestart",
        "urls": ["https://mahashe.su/Files/dotnet-sdk-7.0.102-win-x64.exe"],
        "winget": ["Microsoft.DotNet.SDK.7"],
    },
    {
        "key": "dotnet_runtime_6_0_13",
        "name": ".NET Runtime 6.0.13",
        "type": "exe",
        "silent": "/quiet /norestart",
        "urls": ["https://mahashe.su/Files/dotnet-runtime-6.0.13-win-x64.exe"],
        "winget": ["Microsoft.DotNet.Runtime.6"],
    },
    {
        "key": "dotnet_sdk_8",
        "name": ".NET 8 SDK x64 (LTS)",
        "type": "exe",
        "silent": "/quiet /norestart",
        "urls": ["https://aka.ms/dotnet/8.0/dotnet-sdk-win-x64.exe"],
        "winget": ["Microsoft.DotNet.SDK.8"],
    },
    {
        "key": "dotnet_desktop_runtime_8",
        "name": ".NET 8 Desktop Runtime x64 (LTS)",
        "type": "exe",
        "silent": "/quiet /norestart",
        "urls": ["https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe"],
        "winget": ["Microsoft.DotNet.DesktopRuntime.8"],
    },
    {
        "key": "python_latest",
        "name": "Python x64 (последняя стабильная)",
        "type": "exe",
        "silent": "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0",
        "urls": ["https://www.python.org/downloads/windows/"],
        "winget": [],
    },
    {
        "key": "py_modules",
        "name": "Python модули By Mahashe",
        "type": "custom",
        "silent": "",
        "urls": [],
        "winget": [],
    },
]

GROUPS = [
    {
        "title": "Программы",
        "keys": [
            "chrome",
            "discord",
            "vencord",
            "3utools",
            "imazing",
            "qbittorrent",
            "Upscayl",
            "notepadpp",
            "vscode",
        ],
    },
    {"title": "Лаунчеры", "keys": ["crossout", "steam", "rockstar", "epic", "uplay"]},
    {
        "title": "Утилиты",
        "keys": [
            "7zip",
            "karing",
            "zapret",
            "winrarinstaller",
            "everything",
            "autohotkey",
            "skydimo",
            "soundswitch",
            "pulsesync",
            "gigabyte_control_center",
        ],
    },
    {
        "title": "Дополнительно",
        "keys": [
            "coubarchiver",
            "aida64v675",
            "minitoolpw13",
            "YouTubeToMP3",
            "wfdownloader",
            "qttabbar",
        ],
    },
    {
        "title": "Компоненты",
        "keys": [
            "vc_redist_all",
            "webview2",
            "java_site",
            "hevc",
            "dotnet_sdk_7_0_102",
            "dotnet_runtime_6_0_13",
            "dotnet_sdk_8",
            "dotnet_desktop_runtime_8",
            "python_latest",
            "py_modules",
            "nvidia_rtx5070",
        ],
    },
    {"title": "Пользовательские", "keys": []},
]


def get_app_by_key(key):
    for a in CATALOG:
        if a["key"].lower() == str(key).lower():
            return a
    return None

SELECTED_PY_MODULES_FILE = None
def detect_py_modules_file():
    bases = []

    if os.path.isdir(BUNDLE_SOURCE_DIR):
        bases.append(BUNDLE_SOURCE_DIR)

    for b in (SCRIPT_SOURCE_DIR, SCRIPT_SOURCE_OLD_DIR, SOURCE_DIR):
        if os.path.isdir(b):
            bases.append(b)

    seen = set()
    for base in bases:
        if base in seen:
            continue
        seen.add(base)
        path = os.path.join(base, "python-modules.txt")
        if os.path.isfile(path):
            log(f"detect_py_modules_file: found at {path}")
            return path

    log("detect_py_modules_file: not found")
    return None

def get_py_modules_file():
    return SELECTED_PY_MODULES_FILE or detect_py_modules_file()

def is_app_available_for_install(app: dict) -> bool:
    key = (app.get("key") or "").lower()
    type_ = (app.get("type") or "").lower()
    urls = app.get("urls") or []
    winget_ids = app.get("winget") or []
    if isinstance(winget_ids, str):
        winget_ids = [winget_ids]

    if key == "py_modules":
        return get_py_modules_file() is not None

    if key == "vc_redist_all":
        return bool(VC_REDISTS_STATIC)

    if key == "winrarinstaller":
        return True

    if type_ == "link":
        return bool(urls)

    if type_ in ("exe", "msi", "zip", "custom"):
        if urls:
            return True
        if winget_ids:
            return True

    return False

def check_urls_status(urls):
    if not urls:
        return ("URLs: нет", 0, 0, "NO_URLS")

    total = len(urls)
    ok = 0
    unknown = 0
    fail = 0

    for u in urls:
        try:
            r = requests.head(
                u,
                allow_redirects=True,
                timeout=6,
                headers={"User-Agent": "InstallHubPY"},
            )
            code = r.status_code

            if not (200 <= code < 400):
                try:
                    r2 = requests.get(
                        u,
                        allow_redirects=True,
                        stream=True,
                        timeout=12,
                        headers={"User-Agent": "InstallHubPY"},
                    )
                    code = r2.status_code
                except Exception as e2:
                    unknown += 1
                    log(f"URL check GET error {u}: {e2}")
                    continue

            if 200 <= code < 400:
                ok += 1
            elif code in (404, 410, 451):
                fail += 1
                log(f"URL dead {u}: {code}")
            else:
                unknown += 1
                log(f"URL check unknown state {u}: {code}")
        except Exception as e:
            unknown += 1
            log(f"URL check HEAD error {u}: {e}")

    if ok > 0:
        if ok == total:
            status = "OK"
            line = f"URLs: {total}, живых: {ok} — OK"
        else:
            status = "PARTIAL"
            line = f"URLs: {total}, живых: {ok} — ЧАСТИЧНО"
    else:
        if fail > 0 and unknown == 0:
            status = "FAIL"
            line = f"URLs: {total}, живых: 0 — FAIL"
        else:
            status = "UNKNOWN"
            line = f"URLs: {total}, живых: 0 — UNKNOWN"

    return (line, ok, total, status)


def get_winget_installed_snapshot():
    if not have_winget():
        return ""
    try:
        cp = subprocess.run(["winget", "list"], capture_output=True, text=True)
        if cp.returncode != 0:
            log_error(f"get_winget_installed_snapshot: exit={cp.returncode}")
            return ""
        log("get_winget_installed_snapshot: snapshot captured")
        return cp.stdout or ""
    except Exception as e:
        log_error(f"get_winget_installed_snapshot error: {e}")
        return ""


def is_installed_via_winget(winget_ids, snapshot: str) -> bool:
    if not snapshot or not winget_ids:
        return False
    up = snapshot.upper()
    for pkg in winget_ids:
        if not pkg:
            continue
        if pkg.upper() in up:
            return True
    return False


def _paths_for_key(key: str):
    key = (key or "").lower()
    env = os.environ
    pf = env.get("ProgramFiles", r"C:\Program Files")
    pf86 = env.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local = env.get("LOCALAPPDATA", "")
    appdata = env.get("APPDATA", "")
    progdata = env.get("ProgramData", r"C:\ProgramData")
    sysroot = env.get("SystemRoot", r"C:\Windows")

    paths = []

    if key == "chrome":
        paths.append(os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"))
        paths.append(os.path.join(local, "Google", "Chrome", "Application", "chrome.exe"))
    elif key == "discord":
        paths.append(os.path.join(local, "Discord"))
    elif key == "vencord":
        paths.append(os.path.join(appdata, "Vencord"))
    elif key == "7zip":
        paths.append(os.path.join(pf, "7-Zip", "7z.exe"))
        paths.append(os.path.join(pf86, "7-Zip", "7z.exe"))
    elif key == "3utools":
        paths.append(os.path.join(pf86, "3uTools", "3uTools.exe"))
        paths.append(os.path.join(pf, "3uTools", "3uTools.exe"))
    elif key == "imazing":
        paths.append(os.path.join(pf, "DigiDNA", "iMazing 3", "iMazing 3.exe"))
    elif key == "everything":
        paths.append(os.path.join(pf, "Everything", "Everything.exe"))
        paths.append(os.path.join(pf86, "Everything", "Everything.exe"))
    elif key == "autohotkey":
        paths.append(os.path.join(pf, "AutoHotkey", "v2", "AutoHotkey.exe"))
        paths.append(os.path.join(pf86, "AutoHotkey", "v2", "AutoHotkey.exe"))
    elif key == "qbittorrent":
        paths.append(os.path.join(pf, "qBittorrent", "qbittorrent.exe"))
        paths.append(os.path.join(pf86, "qBittorrent", "qbittorrent.exe"))
    elif key == "qttabbar":
        paths.append(os.path.join(pf, "QTTabBar"))
        paths.append(os.path.join(pf86, "QTTabBar"))
    elif key == "upscayl":
        paths.append(os.path.join(local, "Programs", "Upscayl"))
        paths.append(os.path.join(pf, "Upscayl"))
    elif key == "winrarinstaller":
        paths.append(os.path.join(pf, "WinRAR", "WinRAR.exe"))
        paths.append(os.path.join(pf86, "WinRAR", "WinRAR.exe"))
    elif key == "steam":
        paths.append(os.path.join(pf, "Steam", "Steam.exe"))
        paths.append(os.path.join(pf86, "Steam", "Steam.exe"))
    elif key == "rockstar":
        paths.append(os.path.join(pf, "Rockstar Games", "Launcher", "Launcher.exe"))
    elif key == "epic":
        paths.append(
            os.path.join(
                pf,
                "Epic Games",
                "Launcher",
                "Portal",
                "Binaries",
                "Win64",
                "EpicGamesLauncher.exe",
            )
        )
    elif key == "uplay":
        paths.append(os.path.join(pf, "Ubisoft", "Ubisoft Game Launcher", "upc.exe"))
    elif key == "notepadpp":
        paths.append(os.path.join(pf, "Notepad++", "notepad++.exe"))
        paths.append(os.path.join(pf86, "Notepad++", "notepad++.exe"))
    elif key == "vscode":
        paths.append(os.path.join(local, "Programs", "Microsoft VS Code", "Code.exe"))
        paths.append(os.path.join(pf, "Microsoft VS Code", "Code.exe"))
    elif key == "zapret":
        paths.append(os.path.join(ZAPRET_DIR, "service.bat"))
    elif key == "karing":
        paths.append(os.path.join(pf, "Karing", "karing.exe"))
        paths.append(os.path.join(local, "Programs", "Karing", "karing.exe"))
    elif key == "skydimo":
        paths.append(os.path.join(pf, "SkyDimo", "SkyDimo.exe"))
        paths.append(os.path.join(local, "Programs", "SkyDimo", "SkyDimo.exe"))
    elif key == "soundswitch":
        paths.append(os.path.join(pf, "SoundSwitch", "SoundSwitch.exe"))
        paths.append(os.path.join(local, "Programs", "SoundSwitch", "SoundSwitch.exe"))
    elif key == "pulsesync":
        paths.append(os.path.join(local, "Programs", "pulsesync-app", "PulseSync.exe"))
        paths.append(os.path.join(local, "Programs", "PulseSync", "PulseSync.exe"))
    elif key == "gigabyte_control_center":
        paths.append(os.path.join(pf, "GIGABYTE", "Control Center", "GCC.exe"))
        paths.append(os.path.join(pf86, "GIGABYTE", "Control Center", "GCC.exe"))
    elif key in ("vc_runtime", "vc_redist_all"):
        paths.append(os.path.join(sysroot, "System32", "vcruntime140.dll"))
    elif key == "webview2":
        paths.append(os.path.join(pf, "Microsoft", "EdgeWebView", "Application"))
    elif key == "python_latest":
        paths.extend(glob.glob(os.path.join(local, "Programs", "Python", "Python3*", "python.exe")))
        paths.extend(glob.glob(os.path.join(pf, "Python3*", "python.exe")))
        paths.extend(glob.glob(os.path.join(pf86, "Python3*", "python.exe")))
    elif key == "dotnet_sdk_7_0_102":
        paths.append(os.path.join(pf, "dotnet", "sdk", "7.0.102"))
    elif key == "dotnet_runtime_6_0_13":
        paths.append(os.path.join(pf, "dotnet", "shared", "Microsoft.NETCore.App", "6.0.13"))
    elif key == "dotnet_sdk_8":
        paths.extend(glob.glob(os.path.join(pf, "dotnet", "sdk", "8.*")))
    elif key == "dotnet_desktop_runtime_8":
        paths.extend(glob.glob(os.path.join(pf, "dotnet", "shared", "Microsoft.WindowsDesktop.App", "8.*")))

    return paths


def _exists_any(paths):
    for p in paths or []:
        if not p:
            continue
        p = os.path.expandvars(p)
        if os.path.isfile(p) or os.path.isdir(p):
            return True
    return False


def is_app_installed(app: dict, winget_snapshot=None) -> bool:
    key = (app.get("key") or "").lower()
    type_ = (app.get("type") or "").lower()
    winget_ids = app.get("winget") or []
    if isinstance(winget_ids, str):
        winget_ids = [winget_ids]

    if _exists_any(_paths_for_key(key)):
        log(f"is_app_installed: key={key} -> True by filesystem")
        return True

    if type_ == "zip" and key not in ("zapret",):
        progdata = os.environ.get("ProgramData", r"C:\ProgramData")
        if _exists_any([os.path.join(progdata, key)]):
            log(f"is_app_installed: key={key} -> True by ProgramData folder")
            return True

    if winget_snapshot and winget_ids:
        if is_installed_via_winget(winget_ids, winget_snapshot):
            log(f"is_app_installed: key={key} -> True by winget")
            return True

    log(f"is_app_installed: key={key} -> False")
    return False


def reload_user_config():
    global USER_APPS_COUNT, CONFIG_STATE, CONFIG_ERROR, CATALOG

    CATALOG = [a for a in CATALOG if not a.get("_user_app")]

    group = None
    for g in GROUPS:
        if g.get("title") == "Пользовательские":
            group = g
            break
    if group is not None:
        group["keys"] = []

    USER_APPS_COUNT = 0
    CONFIG_ERROR = ""

    if not os.path.isfile(CONFIG_PATH):
        CONFIG_STATE = "missing"
        log("reload_user_config: config.json missing")
        return

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        CONFIG_STATE = "invalid_json"
        CONFIG_ERROR = str(e)
        log_error(f"reload_user_config: invalid JSON: {e}")
        return

    if isinstance(raw, dict):
        apps = raw.get("user_apps") or raw.get("apps") or raw.get("items")
    elif isinstance(raw, list):
        apps = raw
    else:
        CONFIG_STATE = "invalid_schema"
        CONFIG_ERROR = "Ожидается список или объект с ключом user_apps/apps/items"
        log_error("reload_user_config: invalid schema (root type)")
        return

    if not isinstance(apps, list):
        CONFIG_STATE = "invalid_schema"
        CONFIG_ERROR = "Поле user_apps/apps/items должно быть списком"
        log_error("reload_user_config: invalid schema (apps is not list)")
        return

    keys = []
    for item in apps:
        if not isinstance(item, dict):
            continue
        key = item.get("key") or item.get("id")
        name = item.get("name") or item.get("title")
        urls = item.get("urls") or []
        if isinstance(urls, str):
            urls = [urls]
        if not key or not name:
            continue
        type_ = (item.get("type") or "exe").lower()
        if type_ not in ("exe", "msi", "zip", "link", "custom"):
            type_ = "exe"
        silent = item.get("silent") or ""
        winget_ids = item.get("winget") or []
        if isinstance(winget_ids, str):
            winget_ids = [winget_ids]

        app = {
            "key": key,
            "name": name,
            "type": type_,
            "silent": silent,
            "urls": urls,
            "winget": winget_ids,
            "_user_app": True,
        }
        CATALOG.append(app)
        keys.append(key)

    if group is not None:
        group["keys"] = keys
    USER_APPS_COUNT = len(keys)
    CONFIG_STATE = "ok"
    log(f"reload_user_config: OK, user apps count={USER_APPS_COUNT}")


reload_user_config()

# -------- ТЕМЫ --------

THEMES = {
    "Ruby Pulse": {
        "BG": "#16070b",
        "PANEL": "#270d14",
        "CARD": "#35111b",
        "CARD_2": "#461625",
        "TEXT": "#fff0f4",
        "MUTED": "#d39aa9",
        "BORDER": "#8a2a43",
        "ACCENT_1": "#ff477e",
        "ACCENT_2": "#ff8fab",
        "ACCENT_3": "#ffd166",
        "ACCENT_TEXT": "#16070b",
        "OK": "#80ed99",
        "DANGER": "#ff355e",
    },
    "Тёмно-синяя": {
        "BG": "#0c1533",
        "PANEL": "#0e1938",
        "CARD": "#0f1e47",
        "CARD_2": "#142352",
        "TEXT": "#f5f7ff",
        "MUTED": "#a8b3d6",
        "BORDER": "#223265",
        "ACCENT_1": "#1d4ed8",
        "ACCENT_2": "#2563eb",
        "ACCENT_3": "#60a5fa",
        "ACCENT_TEXT": "#ffffff",
        "OK": "#4ade80",
        "DANGER": "#fb7185",
    },
    "Графитовая": {
        "BG": "#050608",
        "PANEL": "#0b0e13",
        "CARD": "#111827",
        "CARD_2": "#1f2937",
        "TEXT": "#f9fafb",
        "MUTED": "#9ca3af",
        "BORDER": "#374151",
        "ACCENT_1": "#3b82f6",
        "ACCENT_2": "#60a5fa",
        "ACCENT_3": "#93c5fd",
        "ACCENT_TEXT": "#ffffff",
        "OK": "#4ade80",
        "DANGER": "#f87171",
    },
    "Фиолетовая": {
        "BG": "#120622",
        "PANEL": "#190b2d",
        "CARD": "#1f1036",
        "CARD_2": "#301653",
        "TEXT": "#faf5ff",
        "MUTED": "#c4b5d4",
        "BORDER": "#4c1d95",
        "ACCENT_1": "#a855f7",
        "ACCENT_2": "#c084fc",
        "ACCENT_3": "#e9d5ff",
        "ACCENT_TEXT": "#ffffff",
        "OK": "#86efac",
        "DANGER": "#fb7185",
    },
    "Изумрудная": {
        "BG": "#02130f",
        "PANEL": "#041e18",
        "CARD": "#052e24",
        "CARD_2": "#064538",
        "TEXT": "#ecfdf5",
        "MUTED": "#9bc8ba",
        "BORDER": "#047857",
        "ACCENT_1": "#10b981",
        "ACCENT_2": "#34d399",
        "ACCENT_3": "#6ee7b7",
        "ACCENT_TEXT": "#022c22",
        "OK": "#86efac",
        "DANGER": "#fb7185",
    },
    "Бордовая": {
        "BG": "#190308",
        "PANEL": "#280711",
        "CARD": "#3b0a16",
        "CARD_2": "#531020",
        "TEXT": "#fff1f2",
        "MUTED": "#d8a4ad",
        "BORDER": "#991b1b",
        "ACCENT_1": "#ef4444",
        "ACCENT_2": "#f87171",
        "ACCENT_3": "#fca5a5",
        "ACCENT_TEXT": "#ffffff",
        "OK": "#86efac",
        "DANGER": "#ff274b",
    },
    "Серая": {
        "BG": "#060709",
        "PANEL": "#0c0f14",
        "CARD": "#111827",
        "CARD_2": "#202938",
        "TEXT": "#f3f4f6",
        "MUTED": "#9ca3af",
        "BORDER": "#4b5563",
        "ACCENT_1": "#e5e7eb",
        "ACCENT_2": "#f9fafb",
        "ACCENT_3": "#ffffff",
        "ACCENT_TEXT": "#111827",
        "OK": "#86efac",
        "DANGER": "#f87171",
    },
    "Тёмная бирюза": {
        "BG": "#031013",
        "PANEL": "#041a1e",
        "CARD": "#042529",
        "CARD_2": "#07383d",
        "TEXT": "#ecfeff",
        "MUTED": "#9ac7c9",
        "BORDER": "#0f766e",
        "ACCENT_1": "#14b8a6",
        "ACCENT_2": "#2dd4bf",
        "ACCENT_3": "#5eead4",
        "ACCENT_TEXT": "#042f2e",
        "OK": "#86efac",
        "DANGER": "#fb7185",
    },
}

DEFAULT_THEME = "Ruby Pulse"
THEME_SETTINGS_VERSION = 2


def load_ui_settings():
    global CACHE_DIR, SOURCE_DIR, LOG_DIR, LOG_PATH
    data = {
        "theme_name": DEFAULT_THEME,
        "install_mode": "standard",
        "cache_dir": CACHE_DIR,
        "log_dir": LOG_DIR,
    }
    if os.path.isfile(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                if (
                    raw.get("theme_settings_version") == THEME_SETTINGS_VERSION
                    and isinstance(raw.get("theme_name"), str)
                    and raw["theme_name"] in THEMES
                ):
                    data["theme_name"] = raw["theme_name"]
                if raw.get("install_mode") in ("standard", "silent"):
                    data["install_mode"] = raw["install_mode"]
                if isinstance(raw.get("cache_dir"), str) and raw["cache_dir"]:
                    set_cache_dir(raw["cache_dir"])
                    data["cache_dir"] = CACHE_DIR
                if isinstance(raw.get("log_dir"), str) and raw["log_dir"]:
                    set_log_dir(raw["log_dir"])
                    data["log_dir"] = LOG_DIR
        except Exception as e:
            log_error(f"load_ui_settings error: {e}")
    return data


def save_ui_settings(theme_name, install_mode):
    try:
        data = {
            "theme_name": theme_name if theme_name in THEMES else DEFAULT_THEME,
            "theme_settings_version": THEME_SETTINGS_VERSION,
            "install_mode": install_mode if install_mode in ("standard", "silent") else "standard",
            "cache_dir": CACHE_DIR,
            "log_dir": LOG_DIR,
        }
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        log(f"save_ui_settings: {data}")
    except Exception as e:
        log_error(f"save_ui_settings error: {e}")


class ToastManager:
    def __init__(self, root):
        self.root = root
        self.active = []

    def show(self, title: str, text: str, ms=3000, width=340):
        log(f"Toast: {title} | {text}")
        win = ctk.CTkToplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.attributes("-alpha", 0.0)
        win.configure(fg_color=self.root.CARD)
        frame = ctk.CTkFrame(
            win,
            fg_color=self.root.CARD,
            corner_radius=12,
            border_width=1,
            border_color=self.root.BORDER,
        )
        frame.pack(fill="both", expand=True)
        title_lbl = ctk.CTkLabel(
            frame,
            text=title,
            text_color=self.root.TEXT,
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        body_lbl = ctk.CTkLabel(
            frame,
            text=text,
            text_color=self.root.MUTED,
            font=ctk.CTkFont(size=12),
        )
        title_lbl.pack(anchor="w", padx=14, pady=(10, 2))
        body_lbl.pack(anchor="w", padx=14, pady=(0, 12))
        win.update_idletasks()
        h = frame.winfo_reqheight() + 2
        x = self.root.winfo_screenwidth() - width - 16
        y = self.root.winfo_screenheight() - 16 - (len(self.active) * (h + 10)) - h
        win.geometry(f"{width}x{h}+{x}+{y}")
        self.active.append(win)
        self._fade(win, 0.0, 0.98, step=0.08, delay=20)
        win.after(ms, lambda: self._dismiss(win))

    def _fade(self, win, a_from, a_to, step=0.05, delay=25):
        a = a_from + step
        if (step > 0 and a >= a_to) or (step < 0 and a <= a_to):
            try:
                win.attributes("-alpha", a_to)
            except Exception:
                pass
            return
        try:
            win.attributes("-alpha", a)
        except Exception:
            return
        win.after(delay, lambda: self._fade(win, a, a_to, step, delay))

    def _dismiss(self, win):
        if not win.winfo_exists():
            return
        self._fade(win, float(win.attributes("-alpha")), 0.0, step=-0.08, delay=20)
        win.after(220, lambda: self._destroy(win))

    def _destroy(self, win):
        if win in self.active:
            self.active.remove(win)
        try:
            win.destroy()
        except Exception:
            pass


_executor = ThreadPoolExecutor(max_workers=4)
_running = {}


def set_busy(key, busy: bool):
    ev = _running.get(key)
    if ev is None:
        ev = threading.Event()
        _running[key] = ev
    if busy:
        ev.set()
    else:
        ev.clear()
    log(f"set_busy: key={key}, busy={busy}")


def install_task(app_key, interactive=True, on_ok=None, on_fail=None):
    app = get_app_by_key(app_key)
    if not app:
        log_error(f"install_task: app not found key={app_key}")
        return
    log(f"install_task: START key={app_key}, interactive={interactive}")
    set_busy(app_key, True)
    success = False
    try:
        if app_key == "vencord":
            link = get_latest_vencord_installer_url()
            destination = os.path.join(CACHE_DIR, "VencordInstaller.exe")
            downloaded = download([link], destination)
            launch_vencord_installer(downloaded)
            success = True
            return

        if app_key == "python_latest":
            link = get_latest_python_windows_url()
            destination = os.path.join(CACHE_DIR, "PythonLatest-amd64.exe")
            downloaded = download([link], destination)
            if file_signature(downloaded) != "exe":
                raise RuntimeError("Python: загруженный файл не является EXE.")
            install_exe(
                downloaded,
                silent_args=app.get("silent") or "",
                interactive=interactive,
            )
            success = True
            return

        if app_key in DYNAMIC_INSTALLERS:
            link = DYNAMIC_INSTALLERS[app_key]()
            destination = os.path.join(CACHE_DIR, f"{app_key}.exe")
            downloaded = download([link], destination)
            if file_signature(downloaded) != "exe":
                raise RuntimeError(f"{app['name']}: загруженный файл не является EXE.")
            install_exe(
                downloaded,
                silent_args=app.get("silent") or "",
                interactive=interactive,
            )
            success = True
            return

        if app.get("winget"):
            log(f"install_task: trying winget for key={app_key}")
            if winget_install(app["winget"], interactive=interactive):
                log(f"install_task: key={app_key} installed via winget")
                success = True
                return

        if app_key == "vc_redist_all":
            success = install_vc_redist_all(interactive=interactive)
            return

        if app_key == "winrarinstaller":
            success = install_winrar_full(interactive=interactive)
            return

        if app_key == "hevc":
            fname = "HEVC-extension.appx"
            dest = os.path.join(SOURCE_DIR, fname)
            dl = download(app["urls"], dest)
            if not os.path.isfile(dl):
                log_error(f"HEVC file not found after download: {dl}")
                return
            sig = file_signature(dl)
            log(f"install_task[hevc]: file={dl}, sig={sig}")
            if sig == "html":
                log_error("HEVC: downloaded HTML instead of APPX, fallback open URL")
                first_url = app["urls"][0] if app.get("urls") else ""
                if first_url:
                    try:
                        os.startfile(first_url)
                        log(f"install_task[hevc]: opened URL in browser: {first_url}")
                    except Exception as e:
                        log_error(f"HEVC fallback browser open error: {e}")
                return
            cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                f'Add-AppxPackage -Path "{dl}"',
            ]
            log("install_task[hevc] RUN: " + " ".join(cmd))
            cp = subprocess.run(cmd, capture_output=True, text=True)
            log(f"install_task[hevc]: Add-AppxPackage exit={cp.returncode}")
            if cp.returncode == 0:
                success = True
            else:
                log_error(f"HEVC install error: {cp.stderr[:300]}")
            try:
                os.remove(dl)
                log("install_task[hevc]: temp file removed")
            except Exception as e:
                log_error(f"HEVC temp remove error: {e}")
            return

        if app_key == "py_modules":
            lst = get_py_modules_file()
            log(f"install_task[py_modules]: file={lst}")
            if lst:
                try:
                    python_cli = shutil.which("py") or sys.executable
                    if interactive:
                        cmd = [
                            "cmd.exe",
                            "/k",
                            python_cli,
                            "-m",
                            "pip",
                            "install",
                            "-r",
                            lst,
                        ]
                        log("install_task[py_modules] interactive RUN: " + " ".join(cmd))
                        subprocess.Popen(
                            cmd,
                            creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
                        )
                    else:
                        cmd = [python_cli, "-m", "pip", "install", "-r", lst]
                        log("install_task[py_modules] silent RUN: " + " ".join(cmd))
                        subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                    success = True
                except Exception as e:
                    log_error(f"pip modules error: {e}")
            return

        # MiniTool Partition Wizard V13.0 (rsload) — кастомная логика
        if app_key == "minitoolpw13":
            log("install_task[minitoolpw13]: start")
            archive_dest = os.path.join(SOURCE_DIR, "minitoolpw13.rar")
            dl = download(app["urls"], archive_dest)
            extract_dir = os.path.join(SOURCE_DIR, "minitoolpw13_extracted")
            try:
                if os.path.isdir(extract_dir):
                    shutil.rmtree(extract_dir)
            except Exception as e:
                log_error(f"minitoolpw13: cleanup old extract error: {e}")
            expand_any_archive(dl, extract_dir)

            setup_path = None
            for root, dirs, files in os.walk(extract_dir):
                for name in files:
                    if name.lower() == "setup.exe":
                        setup_path = os.path.join(root, name)
                        break
                if setup_path:
                    break

            if not setup_path:
                log_error("minitoolpw13: setup.exe не найден после распаковки архива")
                return

            crack_src = os.path.join(extract_dir, "Crack UZ1")
            if not os.path.isdir(crack_src):
                for root, dirs, files in os.walk(extract_dir):
                    for d in dirs:
                        normalized = d.lower().replace("_", " ").strip()
                        if normalized == "crack uz1":
                            crack_src = os.path.join(root, d)
                            break
                    if os.path.isdir(crack_src):
                        break

            documents_dir = None
            try:
                userprofile = os.environ.get("USERPROFILE") or ""
                if userprofile:
                    docs = os.path.join(userprofile, "Documents")
                    os.makedirs(docs, exist_ok=True)
                    documents_dir = docs
            except Exception as e:
                log_error(f"minitoolpw13: error resolving Documents: {e}")

            if os.path.isdir(crack_src) and documents_dir:
                crack_dst = os.path.join(documents_dir, os.path.basename(crack_src))
                try:
                    if os.path.isdir(crack_dst):
                        shutil.rmtree(crack_dst)
                except Exception as e:
                    log_error(f"minitoolpw13: cleanup old crack folder error: {e}")
                try:
                    shutil.copytree(crack_src, crack_dst)
                    log(f"minitoolpw13: Crack UZ1 скопирован в {crack_dst}")
                except Exception as e:
                    log_error(f"minitoolpw13: copy Crack UZ1 error: {e}")
            else:
                log_error("minitoolpw13: не удалось найти папку Crack UZ1 или Documents")

            log(f"minitoolpw13: запуск {setup_path}")
            cp = subprocess.run([setup_path])
            log(f"minitoolpw13: setup exit={cp.returncode}")
            if cp.returncode == 0:
                success = True
                try:
                    msg = (
                        "Для активации MiniTool Partition Wizard\n"
                        "скопируйте файлы из папки \"Crack UZ1\" (в Документах)\n"
                        "в папку, где установлена программа."
                    )
                    ctypes.windll.user32.MessageBoxW(
                        None,
                        msg,
                        "MiniTool Partition Wizard — активация",
                        0,
                    )
                except Exception as e:
                    log_error(f"minitoolpw13: MessageBox error: {e}")
            else:
                log_error(f"minitoolpw13: установка завершилась с кодом {cp.returncode}")
            return

        if app["type"] == "link":
            url = app["urls"][0] if app.get("urls") else ""
            log(f"install_task[{app_key}]: link type, url={url}")
            if url:
                try:
                    os.startfile(url)
                    success = True
                except Exception as e:
                    log_error(f"open link error {url}: {e}")
            return

        ext = first_url_ext(app["urls"])
        if not ext:
            if app["type"] == "msi":
                ext = ".msi"
            elif app["type"] == "zip":
                ext = ".zip"
            else:
                ext = ".exe"
        fname = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in app["name"])
        dest = os.path.join(CACHE_DIR, fname + ext)
        log(f"install_task[{app_key}]: downloading to {dest}")
        dl = download(app["urls"], dest)
        sig = file_signature(dl)
        log(f"install_task[{app_key}]: downloaded, path={dl}, sig={sig}")
        if sig == "html":
            log_error(f"{app_key}: downloaded HTML instead of installer, fallback: open URL in browser")
            first_url = app["urls"][0] if app.get("urls") else ""
            if first_url:
                try:
                    os.startfile(first_url)
                    log(f"install_task[{app_key}]: opened URL in browser: {first_url}")
                except Exception as e:
                    log_error(f"fallback browser open error for {first_url}: {e}")
            return
        if sig == "exe" and os.path.splitext(dl)[1].lower() != ".exe":
            newp = os.path.splitext(dl)[0] + ".exe"
            os.replace(dl, newp)
            log(f"install_task[{app_key}]: rename to .exe -> {newp}")
            dl = newp

        if app["type"] == "msi":
            install_msi(dl, silent_args=app.get("silent") or "/qn /norestart", interactive=interactive)
            success = True
        elif app["type"] == "exe":
            install_exe(dl, silent_args=app.get("silent") or "/S", interactive=interactive)
            success = True
        elif app["type"] == "zip":
            if app_key.lower() == "zapret":
                deploy_zapret(dl)
            elif app_key.lower() == "gigabyte_control_center":
                deploy_gigabyte_control_center(dl, interactive=interactive)
            else:
                target = os.path.join(
                    os.environ.get("ProgramData", "C:\\ProgramData"),
                    app["key"],
                )
                expand_any_archive(dl, target)
            success = True
    except Exception:
        log_error(f"install_task crashed for key={app_key}:\n{traceback.format_exc()}")
    finally:
        set_busy(app_key, False)
        log(f"install_task: FINISH key={app_key}, success={success}")
        if success and on_ok:
            try:
                on_ok(app.get("name", app_key))
            except Exception as e:
                log_error(f"on_ok handler error for key={app_key}: {e}")
        if not success and on_fail:
            try:
                on_fail(app.get("name", app_key))
            except Exception as e:
                log_error(f"on_fail handler error for key={app_key}: {e}")


class App(ctk.CTk):
    def _set_theme_colors(self, data):
        self.BG = data["BG"]
        self.PANEL = data["PANEL"]
        self.CARD = data["CARD"]
        self.CARD_2 = data["CARD_2"]
        self.TEXT = data["TEXT"]
        self.MUTED = data["MUTED"]
        self.BORDER = data["BORDER"]
        self.ACCENT_1 = data["ACCENT_1"]
        self.ACCENT_2 = data["ACCENT_2"]
        self.ACCENT_3 = data["ACCENT_3"]
        self.ACCENT_TEXT = data["ACCENT_TEXT"]
        self.OK = data["OK"]
        self.DANGER = data["DANGER"]

    def _apply_windows_titlebar(self, window):
        if os.name != "nt":
            return
        try:
            window.update_idletasks()
            hwnd = window.winfo_id()
            dark = ctypes.c_int(1)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(dark), ctypes.sizeof(dark))
            for attribute, color in ((34, self.BORDER), (35, self.PANEL), (36, self.TEXT)):
                value = color.lstrip("#")
                red = int(value[0:2], 16)
                green = int(value[2:4], 16)
                blue = int(value[4:6], 16)
                colorref = ctypes.c_int(red | (green << 8) | (blue << 16))
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    attribute,
                    ctypes.byref(colorref),
                    ctypes.sizeof(colorref),
                )
        except Exception as e:
            log_error(f"titlebar theme error: {e}")

    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        global UI_SETTINGS
        if UI_SETTINGS is None:
            UI_SETTINGS = {"theme_name": DEFAULT_THEME, "install_mode": "standard"}

        self.theme_name = UI_SETTINGS.get("theme_name", DEFAULT_THEME)
        theme_data = THEMES.get(self.theme_name, THEMES[DEFAULT_THEME])
        self._set_theme_colors(theme_data)

        self.install_mode = UI_SETTINGS.get("install_mode", "standard")  # standard | silent

        self.settings_font = ctk.CTkFont(size=13)
        self.settings_title_font = ctk.CTkFont(size=16, weight="bold")

        self.title(APP_TITLE + (" — Без прав администратора" if not is_admin() else ""))
        self.geometry("980x680")
        self.resizable(False, False)
        self.configure(fg_color=self.BG)
        self.after(30, lambda: self._apply_windows_titlebar(self))

        self.toaster = ToastManager(self)
        self.user_cfg_button = None

        self.tabs = None
        self.rows = {}
        self.sf_by_tab = {}
        self._cfg_last_sig = None

        self.status_win = None
        self.status_tabs = None
        self.status_text_main = None
        self.status_text_ok = None
        self.status_text_fail = None
        self.status_text_detected = None
        self.status_text_not_detected = None

        self.install_mode_var = None
        self.theme_var = None
        self.cache_dir_label = None
        self.log_dir_label = None

        self.settings_win = None  # отдельное окно настроек

        top = ctk.CTkFrame(self, fg_color=self.BG, corner_radius=0)
        top._is_top_bar = True
        top.pack(fill="x", padx=16, pady=12)
        ctk.CTkButton(
            top,
            text="Установить всё",
            command=self.install_all,
            corner_radius=15,
        ).pack(side="left")
        ctk.CTkButton(
            top,
            text="Очистить кэш",
            command=self.clear_cache,
            corner_radius=15,
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            top,
            text="Статус",
            command=self.show_status,
            corner_radius=15,
        ).pack(side="left")

        self.settings_button = ctk.CTkButton(
            top,
            text="⚙",
            width=40,
            corner_radius=15,
            command=self.open_settings_window,
        )
        self.settings_button.pack(side="right")

        self._build_tabs()
        self._apply_theme_recursive(self)

        self.bind_all("<MouseWheel>", self._on_wheel, add="+")
        self.bind_all("<Button-4>", lambda e: self._scroll(-60), add="+")
        self.bind_all("<Button-5>", lambda e: self._scroll(60), add="+")
        self.after(1200, self.autorefresh)

        log("App: UI initialized")

    def toast_ok(self, appname: str):
        self.after(0, lambda: self.toaster.show("Установлено", appname, ms=3200))

    def toast_fail(self, appname: str):
        self.after(0, lambda: self.toaster.show("Ошибка установки", appname, ms=3500))

    def _card(self, parent):
        frame = ctk.CTkFrame(
            parent,
            fg_color=self.CARD,
            corner_radius=15,
            border_width=1,
            border_color=self.BORDER,
        )
        frame._is_card = True
        return frame

    def _build_tabs(self):
        if self.tabs is not None:
            self.tabs.destroy()
        self.tabs = ctk.CTkTabview(
            self,
            corner_radius=15,
            border_width=1,
            border_color=self.BORDER,
            fg_color=self.BG,
            segmented_button_fg_color=self.CARD,
            segmented_button_selected_color=self.ACCENT_1,
            segmented_button_selected_hover_color=self.ACCENT_2,
            segmented_button_unselected_color=self.CARD,
            segmented_button_unselected_hover_color=self.CARD_2,
            text_color=self.TEXT,
        )
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.sf_by_tab.clear()
        self.rows.clear()

        for g in GROUPS:
            tab = self.tabs.add(g["title"])

            if g["title"] == "Пользовательские":
                continue

            sf = ctk.CTkScrollableFrame(
                tab,
                corner_radius=15,
                fg_color=self.BG,
                border_width=0,
                scrollbar_button_color=self.BG,
                scrollbar_button_hover_color=self.BG,
                scrollbar_fg_color=self.BG,
            )
            sf.pack(fill="both", expand=True, padx=4, pady=4)
            self.sf_by_tab[g["title"]] = sf
            self._populate_group(sf, g["keys"])

        self.refresh_user_apps_ui()

        # Применить надписи кнопок в соответствии с режимом
        self.update_install_buttons_mode()

        log("App: tabs built")

    def _populate_group(self, parent, keys):
        for key in keys:
            app = get_app_by_key(key)
            if not app:
                log_error(f"_populate_group: app key not found: {key}")
                continue
            card = self._card(parent)
            card.pack(fill="x", padx=8, pady=8)
            card.grid_columnconfigure(0, weight=1)

            name = ctk.CTkLabel(
                card,
                text=app["name"],
                font=ctk.CTkFont(size=14, weight="bold"),
            )
            name.grid(row=0, column=0, sticky="w", padx=14, pady=12)

            available = is_app_available_for_install(app)
            if available:
                if self.install_mode == "standard":
                    btn_text = "Установить"
                else:
                    btn_text = "Тихая установка"
            else:
                btn_text = "Установка (FAIL)"

            btn_install = ctk.CTkButton(
                card,
                text=btn_text,
                corner_radius=15,
                command=lambda k=key: self._install_click(k, True),
                width=140,
            )

            if key == "py_modules":
                btn_second = ctk.CTkButton(
                    card,
                    text="Выбрать .txt",
                    corner_radius=15,
                    command=self.select_py_modules_file,
                    width=130,
                )
            else:
                btn_second = ctk.CTkButton(
                    card,
                    text="Тихо",
                    corner_radius=15,
                    command=lambda k=key: self._install_click(k, False),
                    width=100,
                )

            btn_install.grid(row=0, column=1, padx=(12, 6), pady=10)
            btn_second.grid(row=0, column=2, padx=(6, 14), pady=10)

            self.rows[key] = {"install": btn_install, "silent": btn_second, "available": available}
            log(f"_populate_group: button row created for key={key}")

    def _install_click(self, key, primary: bool):
        if key == "py_modules":
            self.enqueue(key, True)
            return
        if self.install_mode == "standard":
            interactive = primary  # основной — с окнами
        else:
            interactive = not primary  # основной — тихий
        self.enqueue(key, interactive)

    def select_py_modules_file(self):
        from tkinter import filedialog

        log("select_py_modules_file: open file dialog")
        path = filedialog.askopenfilename(
            parent=self,
            title="Выберите .txt с модулями",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            log("select_py_modules_file: canceled")
            return
        if not os.path.isfile(path):
            self.toaster.show("Файл не найден", path, ms=3200)
            log_error(f"select_py_modules_file: file not found {path}")
            return
        global SELECTED_PY_MODULES_FILE
        SELECTED_PY_MODULES_FILE = path
        log(f"select_py_modules_file: selected {path}")
        self.toaster.show("Файл выбран", os.path.basename(path), ms=3200)

    def _active_sf(self):
        return self.sf_by_tab.get(self.tabs.get())

    def _scroll(self, delta):
        sf = self._active_sf()
        if not sf:
            return
        try:
            sf._parent_canvas.yview_scroll(int(-delta / 30), "units")
        except Exception:
            pass

    def _on_wheel(self, e):
        self._scroll(e.delta)
        return "break"

    def ask_reinstall(self, app_name: str) -> bool:
        log(f"ask_reinstall: app={app_name}")

        win = ctk.CTkToplevel(self)
        win.title("Приложение уже установлено")
        win.geometry("420x180")
        win.configure(fg_color=self.BG)
        win.grab_set()
        win.transient(self)
        win.after(30, lambda: self._apply_windows_titlebar(win))

        card = self._card(win)
        card.pack(fill="both", expand=True, padx=14, pady=14)
        card.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(
            card,
            text=f"{app_name} уже установлено.\nПереустановить?",
            font=ctk.CTkFont(size=13, weight="bold"),
            justify="left",
        )
        lbl.grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(10, 6))

        result = {"value": False}

        def do_reinstall():
            result["value"] = True
            win.destroy()

        def do_skip():
            result["value"] = False
            win.destroy()

        btn_yes = ctk.CTkButton(card, text="Переустановить", corner_radius=15, command=do_reinstall, width=130)
        btn_no = ctk.CTkButton(card, text="Не трогать", corner_radius=15, command=do_skip, width=110)
        btn_yes.grid(row=1, column=0, padx=(14, 6), pady=(6, 12), sticky="w")
        btn_no.grid(row=1, column=1, padx=(6, 14), pady=(6, 12), sticky="e")

        win.update_idletasks()
        w = win.winfo_width()
        h = win.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        win.geometry(f"{w}x{h}+{x}+{y}")

        self.wait_window(win)
        log(f"ask_reinstall: result={result['value']}")
        return result["value"]

    def enqueue(self, key, interactive):
        app = get_app_by_key(key)
        if not app:
            log_error(f"enqueue: app not found key={key}")
            return

        type_ = (app.get("type") or "").lower()
        check_key = (app.get("key") or "").lower()
        log(f"enqueue: key={key}, interactive={interactive}, type={type_}")

        if type_ in ("exe", "msi", "zip", "custom") and check_key not in ("py_modules", "hevc", "winrarinstaller", "vc_redist_all", "minitoolpw13"):
            snapshot = get_winget_installed_snapshot()
            installed = False
            try:
                installed = is_app_installed(app, snapshot)
            except Exception as e:
                log_error(f"enqueue: is_app_installed error for key={key}: {e}")

            if installed:
                log(f"enqueue: key={key} already installed")
                if not self.ask_reinstall(app.get("name", key)):
                    log(f"enqueue: user skipped reinstall for key={key}")
                    app_name = app.get("name", key)
                    self.toaster.show("Пропуск", f"{app_name} уже установлено", ms=3200)
                    return
                log(f"enqueue: user confirmed reinstall for key={key}")

        if not get_app_by_key(key):
            log_error(f"enqueue: app lost key={key}")
            return
        ev = _running.get(key)
        if ev is None:
            ev = threading.Event()
            _running[key] = ev
        if ev.is_set():
            log(f"enqueue: key={key} already running")
            return
        ev.set()
        self._set_buttons_state(key, False)

        def worker():
            try:
                install_task(key, interactive, on_ok=self.toast_ok, on_fail=self.toast_fail)
            finally:
                time.sleep(0.2)
                ev.clear()
                log(f"enqueue.worker: key={key} finished, re-enabling buttons")

        _executor.submit(worker)

    def _set_buttons_state(self, key, enabled):
        row = self.rows.get(key)
        if not row:
            return
        state = "normal" if enabled else "disabled"
        row["install"].configure(state=state)
        row["silent"].configure(state=state)
        log(f"_set_buttons_state: key={key}, enabled={enabled}")

    def autorefresh(self):
        self.refresh_state()
        self.check_user_config_changes()
        self.after(1200, self.autorefresh)

    def refresh_state(self):
        for key, row in self.rows.items():
            busy = _running.get(key).is_set() if _running.get(key) else False
            self._set_buttons_state(key, not busy)

    def check_user_config_changes(self):
        try:
            if os.path.isfile(CONFIG_PATH):
                sig = ("exists", os.path.getmtime(CONFIG_PATH), os.path.getsize(CONFIG_PATH))
            else:
                sig = ("missing", 0, 0)
        except Exception:
            sig = ("error", 0, 0)
        if self._cfg_last_sig != sig:
            log(f"check_user_config_changes: config signature changed {self._cfg_last_sig} -> {sig}")
            self._cfg_last_sig = sig
            self.refresh_user_apps_ui()

    def install_all(self):
        keys = []
        current_tab = self.tabs.get()
        for g in GROUPS:
            if g["title"] == current_tab:
                keys = g["keys"]
                break
        log(f"install_all: enqueue tab={current_tab}, keys={keys}")
        interactive = self.install_mode == "standard"
        for k in keys:
            self.enqueue(k, interactive)

    def clear_cache(self):
        log(f"clear_cache: path={CACHE_DIR}")
        try:
            for name in os.listdir(CACHE_DIR):
                p = os.path.join(CACHE_DIR, name)
                if os.path.isfile(p):
                    os.remove(p)
            log("Кэш очищен")
            self.toaster.show("Кэш очищен", CACHE_DIR, ms=3000)
        except Exception as e:
            log_error(f"Ошибка очистки кэша: {e}")
            self.toaster.show("Ошибка очистки кэша", str(e), ms=4000)

    def refresh_user_apps_ui(self):
        log("refresh_user_apps_ui: reload_user_config")
        reload_user_config()
        if self.tabs is None or not self.tabs.winfo_exists():
            log("refresh_user_apps_ui: tabs not ready")
            return
        try:
            tab = self.tabs.tab("Пользовательские")
        except Exception:
            log_error("refresh_user_apps_ui: 'Пользовательские' tab not found")
            return

        for child in tab.winfo_children():
            child.destroy()
        self.user_cfg_button = None

        if CONFIG_STATE == "ok":
            log("refresh_user_apps_ui: CONFIG_STATE=ok")
            sf = ctk.CTkScrollableFrame(
                tab,
                corner_radius=15,
                fg_color=self.BG,
                border_width=0,
                scrollbar_button_color=self.BG,
                scrollbar_button_hover_color=self.BG,
                scrollbar_fg_color=self.BG,
            )
            sf.pack(fill="both", expand=True, padx=4, pady=4)
            self.sf_by_tab["Пользовательские"] = sf
            group = next((g for g in GROUPS if g["title"] == "Пользовательские"), None)
            if group:
                self._populate_group(sf, group["keys"])
        else:
            log(f"refresh_user_apps_ui: CONFIG_STATE={CONFIG_STATE}, ERROR={CONFIG_ERROR!r}")
            if CONFIG_STATE == "missing":
                msg = "config.json не найден.\nНажмите кнопку, чтобы создать шаблон."
            elif CONFIG_STATE == "invalid_json":
                msg = "config.json содержит некорректный JSON:\n" + CONFIG_ERROR
            elif CONFIG_STATE == "invalid_schema":
                msg = "config.json имеет неверную структуру:\n" + CONFIG_ERROR
            else:
                msg = "config.json в неизвестном состоянии."
            lbl = ctk.CTkLabel(tab, text=msg, justify="left", anchor="w")
            lbl.pack(anchor="w", padx=8, pady=(6, 4))
            self.user_cfg_button = ctk.CTkButton(
                tab,
                text="Создать шаблон config.json",
                corner_radius=15,
                command=self.create_config_template,
            )
            self.user_cfg_button.pack(anchor="w", padx=8, pady=(0, 6))

            sf = ctk.CTkScrollableFrame(
                tab,
                corner_radius=15,
                fg_color=self.BG,
                border_width=0,
                scrollbar_button_color=self.BG,
                scrollbar_button_hover_color=self.BG,
                scrollbar_fg_color=self.BG,
            )
            sf.pack(fill="both", expand=True, padx=4, pady=4)
            self.sf_by_tab["Пользовательские"] = sf

    def create_config_template(self):
        overwrite = os.path.isfile(CONFIG_PATH) and CONFIG_STATE in ("invalid_json", "invalid_schema")
        log(f"create_config_template: CONFIG_PATH={CONFIG_PATH}, overwrite={overwrite}")
        if os.path.isfile(CONFIG_PATH) and not overwrite:
            if self.user_cfg_button is not None:
                self.user_cfg_button.destroy()
                self.user_cfg_button = None
            self.toaster.show("config.json", "Файл уже существует", ms=2800)
            return

        template = {
            "user_apps": [
                {
                    "key": "my_app",
                    "name": "Пример приложения",
                    "type": "exe",
                    "silent": "/S",
                    "urls": ["https://example.com/installer.exe"],
                    "winget": [],
                }
            ]
        }
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(template, f, ensure_ascii=False, indent=2)
            log(f"Создан шаблон config.json -> {CONFIG_PATH}")
            self.toaster.show("Создан шаблон", "config.json сохранён рядом с exe", ms=3200)
            self.refresh_user_apps_ui()
        except Exception as e:
            log_error(f"Ошибка создания config.json: {e}")
            self.toaster.show("Ошибка", f"Не удалось создать config.json: {e}", ms=4000)

    def _status_set_text(self, widget, text: str):
        if widget is None or not widget.winfo_exists():
            return
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.see("end")
        widget.configure(state="disabled")

    def _status_append_line(self, widget, line: str):
        if widget is None or not widget.winfo_exists():
            return
        widget.configure(state="normal")
        if widget.index("end-1c") != "1.0":
            widget.insert("end", "\n" + line)
        else:
            widget.insert("end", line)
        widget.see("end")
        widget.configure(state="disabled")

    def _status_clear_all(self):
        for w in (
            self.status_text_main,
            self.status_text_ok,
            self.status_text_fail,
            self.status_text_detected,
            self.status_text_not_detected,
        ):
            if w is not None and w.winfo_exists():
                w.configure(state="normal")
                w.delete("1.0", "end")
                w.configure(state="disabled")

    def show_status(self):
        log("show_status: open status window")
        if self.status_win is not None and self.status_win.winfo_exists():
            self.status_win.lift()
            self.status_win.focus_force()
            return

        win = ctk.CTkToplevel(self)
        win.title("Статус Windows Install Hub")
        win.geometry("720x520")
        win.configure(fg_color=self.BG)
        win.grab_set()
        self.status_win = win
        win.after(30, lambda: self._apply_windows_titlebar(win))

        top_bar = ctk.CTkFrame(win, fg_color=self.BG, corner_radius=0)
        top_bar._is_top_bar = True
        top_bar.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkLabel(
            top_bar,
            text="Диагностика и состояние программы",
            font=ctk.CTkFont(size=15, weight="bold"),
        ).pack(side="left")
        ctk.CTkButton(
            top_bar,
            text="Обновить",
            corner_radius=15,
            width=100,
            command=self.refresh_status_window,
        ).pack(side="right")

        self.status_tabs = ctk.CTkTabview(
            win,
            corner_radius=12,
            border_width=1,
            border_color=self.BORDER,
            fg_color=self.BG,
            segmented_button_fg_color=self.CARD,
            segmented_button_selected_color=self.ACCENT_1,
            segmented_button_selected_hover_color=self.ACCENT_2,
            segmented_button_unselected_color=self.CARD,
            segmented_button_unselected_hover_color=self.CARD_2,
            text_color=self.TEXT,
        )
        self.status_tabs.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        tab_main = self.status_tabs.add("Основное")
        tab_ok = self.status_tabs.add("OK")
        tab_fail = self.status_tabs.add("FAIL")
        tab_detected = self.status_tabs.add("Обнаружено")
        tab_not_detected = self.status_tabs.add("Не обнаружено")

        self.status_text_main = ctk.CTkTextbox(
            tab_main,
            fg_color=self.CARD,
            border_width=1,
            border_color=self.BORDER,
            wrap="word",
            font=ctk.CTkFont(size=12),
        )
        self.status_text_main.pack(fill="both", expand=True, padx=4, pady=4)

        self.status_text_ok = ctk.CTkTextbox(
            tab_ok,
            fg_color=self.CARD,
            border_width=1,
            border_color=self.BORDER,
            wrap="word",
            font=ctk.CTkFont(size=12),
        )
        self.status_text_ok.pack(fill="both", expand=True, padx=4, pady=4)

        self.status_text_fail = ctk.CTkTextbox(
            tab_fail,
            fg_color=self.CARD,
            border_width=1,
            border_color=self.BORDER,
            wrap="word",
            font=ctk.CTkFont(size=12),
        )
        self.status_text_fail.pack(fill="both", expand=True, padx=4, pady=4)

        self.status_text_detected = ctk.CTkTextbox(
            tab_detected,
            fg_color=self.CARD,
            border_width=1,
            border_color=self.BORDER,
            wrap="word",
            font=ctk.CTkFont(size=12),
        )
        self.status_text_detected.pack(fill="both", expand=True, padx=4, pady=4)

        self.status_text_not_detected = ctk.CTkTextbox(
            tab_not_detected,
            fg_color=self.CARD,
            border_width=1,
            border_color=self.BORDER,
            wrap="word",
            font=ctk.CTkFont(size=12),
        )
        self.status_text_not_detected.pack(fill="both", expand=True, padx=4, pady=4)

        self._status_clear_all()
        self._status_set_text(self.status_text_main, "Идёт проверка...\n")
        self._status_set_text(
            self.status_text_ok,
            "Приложения с проверенными рабочими ссылками:\n",
        )
        self._status_set_text(
            self.status_text_fail,
            "Приложения с некорректной конфигурацией / без источников:\n",
        )
        self._status_set_text(
            self.status_text_detected,
            "Приложения, обнаруженные как установленные:\n",
        )
        self._status_set_text(
            self.status_text_not_detected,
            "Приложения, которые не найдены как установленные:\n",
        )

        threading.Thread(target=self._collect_status_safe, daemon=True).start()

    def refresh_status_window(self):
        log("refresh_status_window: restart checks")
        if self.status_tabs is None or not self.status_tabs.winfo_exists():
            return
        self._status_clear_all()
        self._status_set_text(self.status_text_main, "Идёт повторная проверка...\n")
        self._status_set_text(
            self.status_text_ok,
            "Приложения с проверенными рабочими ссылками:\n",
        )
        self._status_set_text(
            self.status_text_fail,
            "Приложения с некорректной конфигурацией / без источников:\n",
        )
        self._status_set_text(
            self.status_text_detected,
            "Приложения, обнаруженные как установленные:\n",
        )
        self._status_set_text(
            self.status_text_not_detected,
            "Приложения, которые не найдены как установленные:\n",
        )
        threading.Thread(target=self._collect_status_safe, daemon=True).start()

    def _collect_status_safe(self):
        try:
            self._collect_status()
        except Exception:
            log_error("Status collector crashed:\n" + traceback.format_exc())

    def _collect_status(self):
        def add_main(line=""):
            self.after(0, lambda t=line: self._status_append_line(self.status_text_main, t))

        def add_ok(line=""):
            self.after(0, lambda t=line: self._status_append_line(self.status_text_ok, t))

        def add_fail(line=""):
            self.after(0, lambda t=line: self._status_append_line(self.status_text_fail, t))

        def add_detected(line=""):
            self.after(0, lambda t=line: self._status_append_line(self.status_text_detected, t))

        def add_not_detected(line=""):
            self.after(0, lambda t=line: self._status_append_line(self.status_text_not_detected, t))

        log("_collect_status: start")
        self.after(
            0,
            lambda: self._status_set_text(self.status_text_main, "Статус Windows Install Hub\n"),
        )

        winget_snapshot = get_winget_installed_snapshot()

        add_main("")
        add_main("=== Общие проверки ===")
        add_main(f"Администратор: {'ДА' if is_admin() else 'НЕТ'}")
        add_main(f"CACHE_DIR: {CACHE_DIR}")
        add_main(f"SOURCE_DIR (temp): {SOURCE_DIR}")
        cfg_exists = CONFIG_STATE != "missing"
        add_main(f"config.json: {'найден' if cfg_exists else 'нет'} ({CONFIG_PATH})")
        if CONFIG_STATE == "ok":
            add_main(f"Пользовательские приложения из config.json: {USER_APPS_COUNT}")
        elif CONFIG_STATE == "invalid_json":
            add_main(f"config.json: некорректный JSON: {CONFIG_ERROR}")
        elif CONFIG_STATE == "invalid_schema":
            add_main(f"config.json: неверная структура: {CONFIG_ERROR}")

        pm_file = get_py_modules_file()
        add_main("")
        add_main("=== Python modules ===")
        if pm_file:
            add_main(f"Файл python-modules.txt: найден ({pm_file}) — ГОТОВО")
        else:
            add_main("Файл python-modules.txt: не найден — функция 'Python модули By Mahashe' недоступна")

        add_main("")
        add_main("=== Каталог приложений ===")
        for app in CATALOG:
            key = app.get("key", "?")
            name = app.get("name", "?")
            type_ = app.get("type", "?")
            urls = app.get("urls") or []
            winget_ids = app.get("winget") or []

            avail = is_app_available_for_install(app)

            add_main(f"[{key}] {name}")
            add_main(f"  Тип: {type_}")
            if winget_ids:
                add_main(f"  Winget: {', '.join(winget_ids)}")
            if key == "py_modules":
                if pm_file:
                    add_main(f"  Источник модулей: {pm_file} — OK")
                else:
                    add_main("  Источник модулей: НЕ НАЙДЕН — FAIL")

            installed = None

            if type_ in ("exe", "msi", "zip", "custom") and key not in ("py_modules",):
                try:
                    installed = is_app_installed(app, winget_snapshot)
                    add_main(f"  Установлено: {'ДА' if installed else 'не обнаружено'}")
                except Exception:
                    installed = None
                    add_main("  Установлено: ошибка проверки")

            if installed is True:
                add_detected(f"[{key}] {name}")
            elif installed is False:
                add_not_detected(f"[{key}] {name}")

            if type_ == "link":
                if urls:
                    add_main(f"  Ссылка: {urls[0]} (тип link — только открытие сайта)")
                    entry_line = f"[{key}] {name} — ссылка: {urls[0]}"
                    add_ok(entry_line)
                else:
                    add_main("  Ссылка: отсутствует")
                    if not avail:
                        entry_line = f"[{key}] {name} — нет URL (link)"
                        add_fail(entry_line)
                add_main("")
                continue

            if urls:
                line, ok_cnt, total_cnt, status = check_urls_status(urls)
                add_main(f"  {line}")
                if ok_cnt > 0:
                    entry_line = f"[{key}] {name} — {line}"
                    add_ok(entry_line)
            else:
                add_main("  URLs: нет")

            if not avail:
                reason = "нет URL/winget"
                if key == "py_modules":
                    reason = "нет файла python-modules.txt"
                if key == "vc_redist_all":
                    reason = "пустой список VC++"
                entry_line = f"[{key}] {name} — недоступно ({reason})"
                add_fail(entry_line)

            add_main("")
        log("_collect_status: done")

    # --------- Настройки / темы / пути ---------

    def _build_settings_content(self, parent):
        container = ctk.CTkFrame(parent, fg_color=self.BG, corner_radius=0)
        container.pack(fill="both", expand=True, padx=24, pady=20)

        ctk.CTkLabel(
            container,
            text="Настройки",
            anchor="w",
            font=ctk.CTkFont(size=24, weight="bold"),
        ).pack(fill="x")
        subtitle = ctk.CTkLabel(
            container,
            text="Управление установкой, оформлением и рабочими папками",
            anchor="w",
            font=ctk.CTkFont(size=13),
        )
        subtitle._is_muted_label = True
        subtitle.pack(fill="x", pady=(2, 16))

        card_mode = self._card(container)
        card_mode.pack(fill="x", pady=(0, 10))
        card_mode.grid_columnconfigure(0, weight=1)
        card_mode.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            card_mode,
            text="Режим установки",
            anchor="w",
            font=self.settings_title_font,
        ).grid(row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=(15, 2))
        mode_hint = ctk.CTkLabel(
            card_mode,
            text="Выберите поведение основной кнопки установки",
            anchor="w",
            font=ctk.CTkFont(size=12),
        )
        mode_hint._is_muted_label = True
        mode_hint.grid(row=1, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 12))

        self.install_mode_var = ctk.StringVar(value=self.install_mode)
        ctk.CTkRadioButton(
            card_mode,
            text="Стандартная\nПоказывать окна установщиков",
            variable=self.install_mode_var,
            value="standard",
            command=self._on_install_mode_change,
            font=self.settings_font,
            height=46,
        ).grid(row=2, column=0, sticky="w", padx=(18, 12), pady=(0, 16))
        ctk.CTkRadioButton(
            card_mode,
            text="Тихая\nУстанавливать без лишних окон",
            variable=self.install_mode_var,
            value="silent",
            command=self._on_install_mode_change,
            font=self.settings_font,
            height=46,
        ).grid(row=2, column=1, sticky="w", padx=(12, 18), pady=(0, 16))

        card_theme = self._card(container)
        card_theme.pack(fill="x", pady=(0, 10))
        card_theme.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card_theme,
            text="Тема интерфейса",
            anchor="w",
            font=self.settings_title_font,
        ).grid(row=0, column=0, sticky="ew", padx=18, pady=(15, 2))
        theme_hint = ctk.CTkLabel(
            card_theme,
            text="Цветовая схема применяется сразу ко всем окнам",
            anchor="w",
            font=ctk.CTkFont(size=12),
        )
        theme_hint._is_muted_label = True
        theme_hint.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 15))

        self.theme_var = ctk.StringVar(value=self.theme_name)
        theme_menu = ctk.CTkOptionMenu(
            card_theme,
            values=list(THEMES.keys()),
            variable=self.theme_var,
            command=self.on_theme_changed,
            width=230,
            height=40,
            corner_radius=12,
            font=self.settings_font,
        )
        try:
            theme_menu.configure(dropdown_font=self.settings_font)
        except Exception:
            pass
        theme_menu.grid(row=0, column=1, rowspan=2, sticky="e", padx=18, pady=15)

        card_paths = self._card(container)
        card_paths.pack(fill="x")
        card_paths.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card_paths,
            text="Рабочие папки",
            anchor="w",
            font=self.settings_title_font,
        ).grid(row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=(15, 2))
        paths_hint = ctk.CTkLabel(
            card_paths,
            text="Пути можно выделить и скопировать",
            anchor="w",
            font=ctk.CTkFont(size=12),
        )
        paths_hint._is_muted_label = True
        paths_hint.grid(row=1, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 10))

        ctk.CTkLabel(card_paths, text="Кэш загрузок", anchor="w", font=self.settings_font).grid(
            row=2, column=0, sticky="ew", padx=18, pady=(0, 5)
        )
        self.cache_dir_var = ctk.StringVar(value=CACHE_DIR)
        self.cache_dir_label = ctk.CTkEntry(
            card_paths,
            textvariable=self.cache_dir_var,
            height=40,
            corner_radius=12,
            font=ctk.CTkFont(size=12),
        )
        self.cache_dir_label.grid(row=3, column=0, sticky="ew", padx=(18, 10), pady=(0, 12))
        self.cache_dir_label.configure(state="readonly")
        ctk.CTkButton(
            card_paths,
            text="Выбрать папку",
            corner_radius=12,
            width=128,
            height=40,
            command=self.change_cache_dir,
            font=self.settings_font,
        ).grid(row=3, column=1, sticky="e", padx=(0, 18), pady=(0, 12))

        ctk.CTkLabel(card_paths, text="Логи программы", anchor="w", font=self.settings_font).grid(
            row=4, column=0, sticky="ew", padx=18, pady=(0, 5)
        )
        self.log_dir_var = ctk.StringVar(value=LOG_DIR)
        self.log_dir_label = ctk.CTkEntry(
            card_paths,
            textvariable=self.log_dir_var,
            height=40,
            corner_radius=12,
            font=ctk.CTkFont(size=12),
        )
        self.log_dir_label.grid(row=5, column=0, sticky="ew", padx=(18, 10), pady=(0, 16))
        self.log_dir_label.configure(state="readonly")
        ctk.CTkButton(
            card_paths,
            text="Выбрать папку",
            corner_radius=12,
            width=128,
            height=40,
            command=self.change_log_dir,
            font=self.settings_font,
        ).grid(row=5, column=1, sticky="e", padx=(0, 18), pady=(0, 16))

    def _on_install_mode_change(self):
        mode = self.install_mode_var.get()
        if mode not in ("standard", "silent"):
            return
        self.install_mode = mode
        log(f"install_mode changed to {self.install_mode}")
        self.update_install_buttons_mode()
        save_ui_settings(self.theme_name, self.install_mode)

    def update_install_buttons_mode(self):
        for key, row in self.rows.items():
            if key == "py_modules":
                continue
            if not row.get("available", True):
                continue
            if self.install_mode == "standard":
                row["install"].configure(text="Установить")
                row["silent"].configure(text="Тихо")
            else:
                row["install"].configure(text="Тихая установка")
                row["silent"].configure(text="С окнами")

    def on_theme_changed(self, value: str):
        if value not in THEMES:
            return
        self.theme_name = value
        data = THEMES[value]
        self._set_theme_colors(data)
        self.configure(fg_color=self.BG)
        self._apply_theme_recursive(self)
        self._apply_windows_titlebar(self)
        # обновить открытые окна
        for win in (self.status_win, self.settings_win):
            if win is not None and win.winfo_exists():
                try:
                    win.configure(fg_color=self.BG)
                except Exception:
                    pass
                self._apply_theme_recursive(win)
                self._apply_windows_titlebar(win)
        save_ui_settings(self.theme_name, self.install_mode)
        log(f"Theme changed to {value}")

    def _apply_theme_recursive(self, widget):
        if isinstance(widget, ctk.CTkSegmentedButton):
            return
        try:
            if isinstance(widget, ctk.CTkTabview):
                widget.configure(
                    fg_color=self.BG,
                    border_color=self.BORDER,
                    segmented_button_fg_color=self.CARD,
                    segmented_button_selected_color=self.ACCENT_1,
                    segmented_button_selected_hover_color=self.ACCENT_2,
                    segmented_button_unselected_color=self.CARD,
                    segmented_button_unselected_hover_color=self.CARD_2,
                    text_color=self.TEXT,
                )
            elif isinstance(widget, ctk.CTkScrollableFrame):
                widget.configure(
                    fg_color=self.BG,
                    border_width=0,
                    scrollbar_button_color=self.BG,
                    scrollbar_button_hover_color=self.BG,
                    scrollbar_fg_color=self.BG,
                )
            elif isinstance(widget, ctk.CTkOptionMenu):
                widget.configure(
                    fg_color=self.CARD_2,
                    button_color=self.ACCENT_1,
                    button_hover_color=self.ACCENT_2,
                    text_color=self.TEXT,
                    dropdown_fg_color=self.CARD,
                    dropdown_hover_color=self.CARD_2,
                    dropdown_text_color=self.TEXT,
                )
            elif isinstance(widget, ctk.CTkRadioButton):
                widget.configure(
                    fg_color=self.ACCENT_1,
                    hover_color=self.ACCENT_2,
                    border_color=self.BORDER,
                    text_color=self.TEXT,
                )
            elif isinstance(widget, ctk.CTkButton):
                widget.configure(
                    fg_color=self.ACCENT_1,
                    hover_color=self.ACCENT_2,
                    text_color=self.ACCENT_TEXT,
                    border_color=self.BORDER,
                )
            elif isinstance(widget, ctk.CTkEntry):
                widget.configure(
                    fg_color=self.CARD_2,
                    border_color=self.BORDER,
                    text_color=self.TEXT,
                    placeholder_text_color=self.MUTED,
                )
            elif isinstance(widget, ctk.CTkTextbox):
                widget.configure(
                    fg_color=self.CARD,
                    border_width=1,
                    border_color=self.BORDER,
                    text_color=self.TEXT,
                    scrollbar_button_color=self.ACCENT_1,
                    scrollbar_button_hover_color=self.ACCENT_2,
                )
            elif isinstance(widget, ctk.CTkLabel):
                widget.configure(text_color=self.MUTED if getattr(widget, "_is_muted_label", False) else self.TEXT)
            elif isinstance(widget, ctk.CTkFrame):
                if getattr(widget, "_is_card", False):
                    widget.configure(
                        fg_color=self.CARD,
                        border_width=1,
                        border_color=self.BORDER,
                    )
                elif getattr(widget, "_is_top_bar", False):
                    widget.configure(fg_color=self.PANEL)
                else:
                    widget.configure(fg_color=self.BG)
        except Exception:
            pass

        if hasattr(widget, "winfo_children"):
            for child in widget.winfo_children():
                self._apply_theme_recursive(child)

    def open_settings_window(self):
        if self.settings_win is not None and self.settings_win.winfo_exists():
            self.settings_win.lift()
            self.settings_win.focus_force()
            return

        win = ctk.CTkToplevel(self)
        win.title("Настройки")
        win.geometry("760x650")
        win.resizable(False, False)
        win.configure(fg_color=self.BG)
        win.grab_set()
        win.transient(self)
        self.settings_win = win

        self._build_settings_content(win)
        self._apply_theme_recursive(win)
        win.after(30, lambda: self._apply_windows_titlebar(win))

    def change_cache_dir(self):
        from tkinter import filedialog

        new_dir = filedialog.askdirectory(parent=self, title="Выбор папки кэша")
        if not new_dir:
            return
        set_cache_dir(new_dir)
        self.cache_dir_var.set(CACHE_DIR)
        save_ui_settings(self.theme_name, self.install_mode)
        self.toaster.show("Папка кэша изменена", CACHE_DIR, ms=3200)

    def change_log_dir(self):
        from tkinter import filedialog

        new_dir = filedialog.askdirectory(parent=self, title="Выбор папки логов")
        if not new_dir:
            return
        set_log_dir(new_dir)
        self.log_dir_var.set(LOG_DIR)
        save_ui_settings(self.theme_name, self.install_mode)
        self.toaster.show("Папка логов изменена", LOG_DIR, ms=3200)


if __name__ == "__main__":
    elevate_if_needed()
    UI_SETTINGS = load_ui_settings()
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"==== {datetime.now().strftime('%Y-%m-%dT%H:%M:%S')} START ====\n")
    if not is_admin():
        log("ВНИМАНИЕ: процесс не с правами администратора")
    log("App main: starting mainloop")
    App().mainloop()

import sys
import os
import random
import string
import subprocess
import ctypes
import threading
import time
from pathlib import Path
from datetime import datetime
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QCheckBox, QProgressBar, QTextEdit, QListWidget,
    QListWidgetItem, QStackedWidget, QLabel, QFrame, QMessageBox,
    QTreeWidget, QTreeWidgetItem, QHeaderView, QDialog, QDialogButtonBox,
    QMenu, QInputDialog, QFileDialog, QSplitter, QAbstractItemView,
    QTabWidget, QScrollArea
)
from PySide6.QtCore import Qt, QSize, QTimer, Signal, QObject, QThread
from PySide6.QtGui import QFont, QColor, QPalette, QIcon, QAction, QCursor
import winreg
import win32service
import win32security
import win32api
import win32con
import win32net
import win32file
import wmi
import psutil

VERSION = "1.2.1"
GITHUB_RELEASES_URL = "https://api.github.com/repos/2M12/ThreatbitSimpleScanner/releases/latest"
DOWNLOAD_URL = "https://github.com/2M12/ThreatbitSimpleScanner/releases/latest"

def random_process_name(length=10):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )

def is_winpe():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "SystemStartOptions")
        winreg.CloseKey(key)
        return "MININT" in value or "WINPE" in value
    except:
        return False

def load_hive(path, name):
    subprocess.run(["reg", "load", f"HKLM\\{name}", path], capture_output=True, check=False)

def unload_hive(name):
    subprocess.run(["reg", "unload", f"HKLM\\{name}"], capture_output=True, check=False)

def check_for_updates():
    try:
        req = urllib.request.Request(GITHUB_RELEASES_URL, headers={"User-Agent": "ThreatbitScanner"})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            latest_version = data.get("tag_name", "").replace("v", "")
            if latest_version and latest_version != VERSION:
                return True, latest_version, data.get("html_url", DOWNLOAD_URL)
            return False, VERSION, DOWNLOAD_URL
    except:
        return None, VERSION, DOWNLOAD_URL

class UpdateChecker(QThread):
    update_available = Signal(str, str)
    check_finished = Signal(object)
    
    def run(self):
        result = check_for_updates()
        has_update, latest, url = result if result else (None, VERSION, DOWNLOAD_URL)
        if has_update:
            self.update_available.emit(latest, url)
        self.check_finished.emit(has_update)

class WorkerSignals(QObject):
    progress = Signal(int)
    status = Signal(str)
    threat_found = Signal(str, str, str)
    finished = Signal(list, list)
    log = Signal(str)
    fix_log = Signal(str)

class ScanWorker(QThread):
    def __init__(self, options, parent=None):
        super().__init__(parent)
        self.options = options
        self.signals = WorkerSignals()
        self.total_steps = 9
        self.current_step = 0
        self.threats = []
        self.suspicious = []
        self._executor = ThreadPoolExecutor(max_workers=4)

    def run(self):
        steps = [
            self.scan_autorun,
            self.scan_policies,
            self.restore_uac,
            self.enable_defender,
            self.restore_associations,
            self.restore_fonts,
            self.run_sfc,
            self.reset_network,
            self.restore_mbr,
        ]
        
        sfc_future = None
        net_future = None
        mbr_future = None
        
        for i, step in enumerate(steps):
            if i < 2:
                step()
            elif step == self.run_sfc and self.options.get("run_sfc", False):
                sfc_future = self._executor.submit(self._run_sfc_parallel)
            elif step == self.reset_network and self.options.get("reset_network", False):
                net_future = self._executor.submit(self._reset_network_parallel)
            elif step == self.restore_mbr and self.options.get("restore_mbr", False):
                mbr_future = self._executor.submit(self._restore_mbr_parallel)
            elif self.options.get(step.__name__, False):
                step()
            self.current_step += 1
            self.signals.progress.emit(int((self.current_step / self.total_steps) * 100))
        
        if sfc_future:
            sfc_future.result()
        if net_future:
            net_future.result()
        if mbr_future:
            mbr_future.result()
        
        self._executor.shutdown(wait=True)
        self.signals.finished.emit(self.threats, self.suspicious)

    def _run_sfc_parallel(self):
        self.signals.status.emit("Выполнение sfc /scannow (параллельно)...")
        self.log_action("Запуск sfc /scannow (параллельно)")
        subprocess.run(["sfc", "/scannow"], capture_output=True, encoding='cp866', errors='ignore')

    def _reset_network_parallel(self):
        self.signals.status.emit("Сброс сетевых параметров (параллельно)...")
        self.log_action("Сброс сетевых параметров (параллельно)")
        commands = [
            'netsh winsock reset',
            'netsh int ip reset',
            'ipconfig /flushdns',
        ]
        for cmd in commands:
            subprocess.run(cmd, shell=True, capture_output=True, encoding='cp866', errors='ignore')
        hosts_path = os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'System32\\drivers\\etc\\hosts')
        try:
            with open(hosts_path, 'w', encoding='utf-8') as f:
                f.write("127.0.0.1 localhost\n::1 localhost\n")
        except:
            pass

    def _restore_mbr_parallel(self):
        self.signals.status.emit("Восстановление MBR (параллельно)...")
        self.log_action("Восстановление MBR (параллельно)")
        commands = [
            'bootrec /fixmbr',
            'bootrec /fixboot',
            'bootrec /rebuildbcd',
        ]
        for cmd in commands:
            subprocess.run(cmd, shell=True, capture_output=True, encoding='cp866', errors='ignore')

    def log_action(self, msg):
        self.signals.log.emit(msg)
        if self.options.get("log_enabled", False):
            log_dir = Path.home() / "Documents" / "ThreatbitScanner_log"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "Threatbit.log"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat()}] {msg}\n")

    def get_reg_value(self, hive, key_path, value_name):
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            try:
                value, reg_type = winreg.QueryValueEx(key, value_name)
                winreg.CloseKey(key)
                return value, reg_type
            except FileNotFoundError:
                winreg.CloseKey(key)
                return None, None
        except FileNotFoundError:
            return None, None
        except Exception:
            return None, None

    def check_registry_value(self, key_path, value_name, expected, hive=winreg.HKEY_LOCAL_MACHINE, is_red=True, description=""):
        actual, reg_type = self.get_reg_value(hive, key_path, value_name)
        if actual is None:
            return
        
        threat_found = False
        if isinstance(expected, str):
            if isinstance(actual, str):
                if actual.strip().lower() != expected.strip().lower():
                    threat_found = True
            else:
                threat_found = True
        elif isinstance(expected, int):
            try:
                if int(actual) != expected:
                    threat_found = True
            except (ValueError, TypeError):
                threat_found = True
        
        if threat_found:
            threat_type = "red" if is_red else "yellow"
            desc = description if description else f"Ожидалось: {expected}, найдено: {actual}"
            self.signals.threat_found.emit(f"{key_path}\\{value_name}", threat_type, desc)
            item = (hive, key_path, value_name, expected, "value", threat_type, desc)
            if is_red:
                self.threats.append(item)
            else:
                self.suspicious.append(item)
            self.signals.log.emit(f"[{threat_type.upper()}] {key_path}\\{value_name} — {desc}")

    def check_registry_exists(self, key_path, value_name, hive=winreg.HKEY_LOCAL_MACHINE, description="", is_red=True):
        try:
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            try:
                winreg.QueryValueEx(key, value_name)
                desc = description if description else "Обнаружен подозрительный параметр"
                threat_type = "red" if is_red else "yellow"
                self.signals.threat_found.emit(f"{key_path}\\{value_name}", threat_type, desc)
                item = (hive, key_path, value_name, None, "delete", threat_type, desc)
                if is_red:
                    self.threats.append(item)
                else:
                    self.suspicious.append(item)
                self.signals.log.emit(f"[{threat_type.upper()}] {key_path}\\{value_name} — {desc}")
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)
        except FileNotFoundError:
            pass

    def check_registry_multisz(self, key_path, value_name, expected_list, hive=winreg.HKEY_LOCAL_MACHINE, description="", is_red=True):
        actual, reg_type = self.get_reg_value(hive, key_path, value_name)
        if actual is None:
            return
        
        threat_found = False
        if isinstance(actual, list):
            actual_normalized = [item.strip().lower() for item in actual]
            expected_normalized = [item.strip().lower() for item in expected_list]
            if actual_normalized != expected_normalized:
                threat_found = True
        elif isinstance(actual, str):
            actual_parts = [x.strip().lower() for x in actual.split('\n') if x.strip()]
            expected_normalized = [x.strip().lower() for x in expected_list]
            if actual_parts != expected_normalized:
                threat_found = True
        else:
            threat_found = True
        
        if threat_found:
            desc = description if description else f"Ожидалось: {expected_list}, найдено: {actual}"
            threat_type = "red" if is_red else "yellow"
            self.signals.threat_found.emit(f"{key_path}\\{value_name}", threat_type, desc)
            item = (hive, key_path, value_name, expected_list, "multisz", threat_type, desc)
            if is_red:
                self.threats.append(item)
            else:
                self.suspicious.append(item)
            self.signals.log.emit(f"[{threat_type.upper()}] {key_path}\\{value_name} — {desc}")

    def scan_autorun(self):
        self.signals.status.emit("Сканирование автозапуска...")
        self.log_action("Начало сканирования автозапуска")
        
        self.check_registry_value(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Shell", "explorer.exe",
            description="Оболочка Windows изменена, возможна подмена проводника"
        )
        
        userinit_actual, _ = self.get_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Userinit"
        )
        if userinit_actual is not None:
            if isinstance(userinit_actual, str):
                cleaned = userinit_actual.strip().rstrip(',').lower()
                if cleaned != r"c:\windows\system32\userinit.exe":
                    desc = f"Userinit изменён: {userinit_actual}, возможна загрузка вредоносного ПО"
                    self.signals.threat_found.emit(
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                        "red", desc)
                    self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                        "Userinit", r"C:\Windows\system32\userinit.exe,", "value", "red", desc))
            else:
                desc = "Userinit имеет неверный тип данных"
                self.signals.threat_found.emit(
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                    "red", desc)
                self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    "Userinit", r"C:\Windows\system32\userinit.exe,", "value", "red", desc))
        
        self.check_registry_value(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs", "",
            description="AppInit_DLLs содержит библиотеки, внедряемые во все процессы"
        )
        self.check_registry_value(
            r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
            "AppInit_DLLs", "",
            description="AppInit_DLLs (WOW64) содержит библиотеки для 32-битных процессов"
        )
        self.check_registry_value(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
            "LoadAppInit_DLLs", 0,
            description="Загрузка AppInit_DLLs включена"
        )
        self.check_registry_value(
            r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
            "LoadAppInit_DLLs", 0,
            description="Загрузка AppInit_DLLs (WOW64) включена"
        )
        self.check_registry_exists(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "AppCertDlls",
            description="AppCertDlls используется для внедрения DLL через сертификаты"
        )
        
        bootexecute_actual, reg_type = self.get_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootExecute"
        )
        if bootexecute_actual is not None:
            threat_found = False
            if reg_type == winreg.REG_MULTI_SZ:
                if isinstance(bootexecute_actual, list):
                    joined = ' '.join(bootexecute_actual).strip().lower()
                    if joined != "autocheck autochk *":
                        threat_found = True
            elif reg_type == winreg.REG_SZ:
                if isinstance(bootexecute_actual, str):
                    if bootexecute_actual.strip().lower() != "autocheck autochk *":
                        threat_found = True
            else:
                threat_found = True
            
            if threat_found:
                desc = f"BootExecute изменён: {bootexecute_actual}, возможно выполнение вредоносного кода при загрузке"
                self.signals.threat_found.emit(
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
                    "red", desc)
                self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Session Manager",
                    "BootExecute", ["autocheck", "autochk *"], "multisz", "red", desc))
        
        alt_shell_actual, _ = self.get_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\SafeBoot",
            "AlternateShell"
        )
        if alt_shell_actual is not None:
            if isinstance(alt_shell_actual, str):
                if alt_shell_actual.strip().lower() != "cmd.exe":
                    desc = f"Альтернативная оболочка SafeBoot: {alt_shell_actual}"
                    self.signals.threat_found.emit(
                        r"SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell",
                        "yellow", desc)
                    self.suspicious.append((winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Control\SafeBoot",
                        "AlternateShell", "cmd.exe", "value", "yellow", desc))
            else:
                desc = "AlternateShell имеет неверный тип данных"
                self.signals.threat_found.emit(
                    r"SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell",
                    "yellow", desc)
                self.suspicious.append((winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\SafeBoot",
                    "AlternateShell", "cmd.exe", "value", "yellow", desc))
        else:
            desc = "Параметр AlternateShell отсутствует"
            self.signals.threat_found.emit(
                r"SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell",
                "yellow", desc)
            self.suspicious.append((winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\SafeBoot",
                "AlternateShell", "cmd.exe", "value", "yellow", desc))
        
        self.check_registry_multisz(
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "Authentication Packages", ["msv1_0"],
            description="Пакеты аутентификации LSA изменены, возможен перехват учётных данных"
        )
        self.check_registry_multisz(
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "Notification Packages", ["scecli"],
            description="Пакеты уведомлений LSA изменены"
        )
        
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit", 0, winreg.KEY_READ)
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                    subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                    try:
                        winreg.QueryValueEx(subkey, "MonitorProcess")
                        desc = f"Мониторинг завершения процесса {subkey_name} - возможна слежка"
                        self.signals.threat_found.emit(
                            f"SilentProcessExit\\{subkey_name}",
                            "red", desc)
                        self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                            f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\{subkey_name}",
                            "MonitorProcess", None, "delete_subkey", "red", desc))
                    except:
                        pass
                    try:
                        winreg.QueryValueEx(subkey, "ReportingMode")
                        desc = f"Отчёт о завершении процесса {subkey_name} - возможна слежка"
                        self.signals.threat_found.emit(
                            f"SilentProcessExit\\{subkey_name}",
                            "red", desc)
                        self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                            f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\{subkey_name}",
                            "ReportingMode", None, "delete_subkey", "red", desc))
                    except:
                        pass
                    winreg.CloseKey(subkey)
                    index += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except FileNotFoundError:
            pass

        self.check_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootShell", r"%SystemRoot%\system32\bootim.exe", is_red=False,
            description="Оболочка загрузки изменена"
        )
        self.check_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            "ComSpec", r"%SystemRoot%\system32\cmd.exe",
            description="ComSpec изменён, возможна подмена командной строки"
        )
        self.check_registry_value(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            "windir", "%SystemRoot%",
            description="Переменная windir изменена"
        )
        
        known_dlls = {
            "_wow64cpu": "wow64cpu.dll", "_wowarmhw": "wowarmhw.dll",
            "_xtajit": "xtajit.dll", "advapi32": "advapi32.dll",
            "clbcatq": "clbcatq.dll", "combase": "combase.dll",
            "COMDLG32": "COMDLG32.dll", "coml2": "coml2.dll",
            "DifxApi": "difxapi.dll", "gdi32": "gdi32.dll",
            "gdiplus": "gdiplus.dll", "IMAGEHLP": "IMAGEHLP.dll",
            "IMM32": "IMM32.dll", "kernel32": "kernel32.dll",
            "MSCTF": "MSCTF.dll", "MSVCRT": "MSVCRT.dll",
            "NORMALIZ": "NORMALIZ.dll", "NSI": "NSI.dll",
            "ole32": "ole32.dll", "OLEAUT32": "OLEAUT32.dll",
            "PSAPI": "PSAPI.dll", "rpcrt4": "rpcrt4.dll",
            "sechost": "sechost.dll", "Setupapi": "Setupapi.dll",
            "SHCORE": "SHCORE.dll", "SHELL32": "SHELL32.dll",
            "SHLWAPI": "SHLWAPI.dll", "user32": "user32.dll",
            "WLDAP32": "WLDAP32.dll", "wow64": "wow64.dll",
            "wow64win": "wow64win.dll", "WS2_32": "WS2_32.dll"
        }
        for name, expected in known_dlls.items():
            actual, _ = self.get_reg_value(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
                name
            )
            if actual is not None:
                if isinstance(actual, str):
                    if actual.strip().lower() != expected.lower():
                        desc = f"KnownDLL {name} изменён: {actual} вместо {expected}, возможен перехват API"
                        self.signals.threat_found.emit(
                            f"KnownDLLs\\{name}", "red", desc)
                        self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
                            name, expected, "value", "red", desc))
                else:
                    desc = f"KnownDLL {name} имеет неверный тип данных"
                    self.signals.threat_found.emit(
                        f"KnownDLLs\\{name}", "red", desc)
                    self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
                        name, expected, "value", "red", desc))

        for base in [r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                     r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_READ)
                index = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, index)
                        if subkey_name.lower().endswith('.exe'):
                            subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                            try:
                                debugger, _ = winreg.QueryValueEx(subkey, "Debugger")
                                desc = f"Отладчик для {subkey_name}: {debugger} - процесс перехватывается"
                                self.signals.threat_found.emit(
                                    f"IFEO\\{subkey_name}", "red", desc)
                                self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                                    f"{base}\\{subkey_name}", "Debugger", None, "delete_ifeo", "red", desc))
                            except:
                                pass
                            winreg.CloseKey(subkey)
                        index += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass

    def scan_policies(self):
        self.signals.status.emit("Сканирование Policies...")
        self.log_action("Начало сканирования Policies")
        
        scan_with_av_actual, _ = self.get_reg_value(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments",
            "ScanWithAntiVirus"
        )
        if scan_with_av_actual is not None:
            try:
                val = int(scan_with_av_actual)
                if val == 0:
                    desc = "Сканирование вложений антивирусом отключено (значение 0)"
                    self.signals.threat_found.emit(
                        r"Policies\Attachments\ScanWithAntiVirus",
                        "yellow", desc)
                    self.suspicious.append((winreg.HKEY_LOCAL_MACHINE,
                        r"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments",
                        "ScanWithAntiVirus", "3", "value", "yellow", desc))
            except (ValueError, TypeError):
                pass
        
        for hive, hive_name in [(winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")]:
            actual, _ = self.get_reg_value(
                hive,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun"
            )
            if actual is not None:
                try:
                    if int(actual) != 0xFF:
                        desc = f"Автозапуск ограничен (значение: {actual}, ожидалось: 0xFF)"
                        self.signals.threat_found.emit(
                            f"Policies\\Explorer\\NoDriveTypeAutoRun ({hive_name})",
                            "yellow", desc)
                        self.suspicious.append((hive,
                            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                            "NoDriveTypeAutoRun", 0xFF, "value", "yellow", desc))
                except (ValueError, TypeError):
                    pass
        
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun", 0, winreg.KEY_READ)
            desc = "Обнаружен раздел DisallowRun - ограничение запуска приложений"
            self.signals.threat_found.emit(
                r"Policies\Explorer\DisallowRun",
                "red", desc)
            self.threats.append((winreg.HKEY_LOCAL_MACHINE,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun",
                None, None, "delete_subkey", "red", desc))
            winreg.CloseKey(key)
        except FileNotFoundError:
            pass
        
        policies_path = r"Software\Microsoft\Windows\CurrentVersion\Policies"
        system_policies = {
            "DisableTaskMgr": "Диспетчер задач отключён",
            "DisableRegistryTools": "Редактор реестра отключён",
            "DisableCMD": "Командная строка отключена",
            "DisableLockWorkstation": "Блокировка рабочей станции отключена",
            "DisableChangePassword": "Смена пароля отключена",
            "NoDispCPL": "Панель управления экраном скрыта",
            "NoDispScrSavPage": "Настройки заставки скрыты",
            "NoDispSettingsPage": "Настройки разрешения скрыты",
            "NoVirtMemPage": "Настройки виртуальной памяти скрыты",
            "NoDevMgrPage": "Диспетчер устройств скрыт",
            "NoConfigPage": "Панели конфигурации скрыты",
            "NoFileSysPage": "Настройки файловой системы скрыты",
            "NoSecCPL": "Панель безопасности скрыта",
            "NoAdminPage": "Административные инструменты скрыты",
            "NoProfilePage": "Профили пользователей скрыты",
            "NoPasswordPage": "Пароли скрыты",
            "NoRemotePage": "Удалённый доступ скрыт",
            "NoHardwarePage": "Оборудование скрыто",
            "DenyUsersFromMachGP": "Пользователям запрещён доступ к групповым политикам"
        }
        explorer_policies = {
            "NoControlPanel": "Панель управления скрыта",
            "NoRun": "Окно Выполнить скрыто",
            "NoFind": "Поиск скрыт",
            "NoDesktop": "Рабочий стол скрыт",
            "NoClose": "Завершение работы скрыто",
            "NoLogoff": "Выход из системы скрыт",
            "NoDrives": "Диски скрыты",
            "NoViewOnDrive": "Просмотр дисков запрещён",
            "NoViewContextMenu": "Контекстное меню скрыто",
            "NoTrayContextMenu": "Меню трея скрыто",
            "NoFolderOptions": "Свойства папки скрыты",
            "NoFileMenu": "Меню Файл скрыто",
            "NoSecurityTab": "Вкладка Безопасность скрыта",
            "NoCommonGroups": "Общие группы скрыты",
            "NoSetTaskbar": "Настройки панели задач скрыты",
            "NoChangingWallPaper": "Смена обоев запрещена",
            "NoWinKeys": "Клавиши Windows отключены",
            "StartMenuLogOff": "Выход из меню Пуск скрыт",
            "NoStartMenuMorePrograms": "Меню Программы скрыто",
            "NoStartMenuMFUprogramsList": "Список часто используемых программ скрыт",
            "RestrictRun": "Запуск только разрешённых приложений",
            "NoToolbarCustomize": "Настройка панелей инструментов запрещена",
            "NoBandCustomize": "Настройка полос запрещена",
            "NoInstrumentation": "Инструментирование отключено",
            "NoSMBalloonTip": "Всплывающие подсказки отключены",
            "NoManageMyComputerVerb": "Управление компьютером скрыто",
            "DisableLocalMachineRun": "Локальный Run отключён",
            "DisableCurrentUserRun": "Пользовательский Run отключён",
            "DisablePersonalDirChange": "Смена личных папок запрещена",
            "NoDriveAutoRun": "Автозапуск дисков отключён",
            "HidePowerOptions": "Настройки питания скрыты",
            "DisableContextMenusInStart": "Контекстные меню в Пуск отключены"
        }
        network_policies = {
            "NoNetwork": "Сеть скрыта",
            "NoWorkgroupContents": "Содержимое рабочей группы скрыто",
            "NoEntireNetwork": "Вся сеть скрыта",
            "NoFileSharingControl": "Общий доступ к файлам отключён",
            "NoNetSetup": "Настройка сети скрыта",
            "NoNetSetupIDPage": "Идентификация сети скрыта",
            "NoNetSetupSecurityPage": "Безопасность сети скрыта",
            "NoNetConnectDisconnect": "Подключение/отключение сети скрыто"
        }
        
        for policy_dict, sub_key in [(system_policies, "System"), (explorer_policies, "Explorer"),
                                     (network_policies, "Network")]:
            for policy, desc in policy_dict.items():
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\{sub_key}", 0, winreg.KEY_READ)
                    try:
                        winreg.QueryValueEx(key, policy)
                        self.signals.threat_found.emit(f"Policies\\{sub_key}\\{policy}", "red", desc)
                        self.threats.append((winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\{sub_key}", policy, None, "delete", "red", desc))
                    except:
                        pass
                    winreg.CloseKey(key)
                except:
                    pass
        
        for policy, desc in [("HideZoneInfoOnProperties", "Информация о зоне в свойствах файла скрыта")]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\Attachments", 0, winreg.KEY_READ)
                try:
                    winreg.QueryValueEx(key, policy)
                    self.signals.threat_found.emit(f"Policies\\Attachments\\{policy}", "red", desc)
                    self.threats.append((winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\Attachments", policy, None, "delete", "red", desc))
                except:
                    pass
                winreg.CloseKey(key)
            except:
                pass
        
        for policy, desc in [("RestrictToPermittedSnapins", "MMC оснастки ограничены")]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\MMC", 0, winreg.KEY_READ)
                try:
                    winreg.QueryValueEx(key, policy)
                    self.signals.threat_found.emit(f"Policies\\MMC\\{policy}", "red", desc)
                    self.threats.append((winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\MMC", policy, None, "delete", "red", desc))
                except:
                    pass
                winreg.CloseKey(key)
            except:
                pass
        
        for policy, desc in [("NoChangingWallPaper", "Смена обоев ActiveDesktop запрещена"),
                              ("NoHTMLWallPaper", "HTML обои отключены")]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\ActiveDesktop", 0, winreg.KEY_READ)
                try:
                    winreg.QueryValueEx(key, policy)
                    self.signals.threat_found.emit(f"Policies\\ActiveDesktop\\{policy}", "red", desc)
                    self.threats.append((winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\ActiveDesktop", policy, None, "delete", "red", desc))
                except:
                    pass
                winreg.CloseKey(key)
            except:
                pass
        
        for policy, desc in [("DisableSR", "Восстановление системы отключено"),
                              ("DisableConfig", "Настройка восстановления системы отключена")]:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\SystemRestore", 0, winreg.KEY_READ)
                try:
                    winreg.QueryValueEx(key, policy)
                    self.signals.threat_found.emit(f"Policies\\SystemRestore\\{policy}", "red", desc)
                    self.threats.append((winreg.HKEY_LOCAL_MACHINE, f"{policies_path}\\SystemRestore", policy, None, "delete", "red", desc))
                except:
                    pass
                winreg.CloseKey(key)
            except:
                pass

    def restore_uac(self):
        if self.options.get("restore_uac", False):
            self.signals.status.emit("Восстановление UAC...")
            self.log_action("Восстановление UAC")
            commands = [
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f',
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f',
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f',
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f',
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f',
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableUIADesktopToggle /t REG_DWORD /d 0 /f',
            ]
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True, encoding='cp866', errors='ignore')

    def enable_defender(self):
        if self.options.get("enable_defender", False):
            self.signals.status.emit("Включение Defender...")
            self.log_action("Включение Defender")
            commands = [
                'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /f',
                'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v AllowFastServiceStartup /f',
                'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v ServiceKeepAlive /f',
                'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" /f',
                'reg delete "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet" /f',
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinDefend" /v Start /t REG_DWORD /d 2 /f',
                'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" /v TamperProtection /t REG_DWORD /d 5 /f',
            ]
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True, encoding='cp866', errors='ignore')

    def restore_associations(self):
        if self.options.get("restore_associations", False):
            self.signals.status.emit("Восстановление ассоциаций...")
            self.log_action("Восстановление ассоциаций")
            commands = [
                'assoc .txt=txtfile',
                'ftype txtfile="%SystemRoot%\\system32\\notepad.exe" %1',
                'assoc .exe=exefile',
                'ftype exefile="%1" %*',
                'assoc .png=pngfile',
                'ftype pngfile="%SystemRoot%\\System32\\mspaint.exe" %1',
                'assoc .bat=batfile',
                'ftype batfile="%SystemRoot%\\System32\\cmd.exe" /c "%1" %*',
                'assoc .com=comfile',
                'ftype comfile="%1" %*',
                'assoc .jpg=jpegfile',
                'assoc .jpeg=jpegfile',
                'ftype jpegfile="%SystemRoot%\\System32\\mspaint.exe" %1',
                'assoc .bmp=bmpfile',
                'ftype bmpfile="%SystemRoot%\\System32\\mspaint.exe" %1',
                'assoc .html=htmlfile',
                'assoc .htm=htmlfile',
                'ftype htmlfile="%ProgramFiles%\\Internet Explorer\\iexplore.exe" "%1"',
                'assoc .mp3=mp3file',
                'ftype mp3file="%SystemRoot%\\System32\\wmplayer.exe" "%1"',
                'assoc .avi=avifile',
                'ftype avifile="%SystemRoot%\\System32\\wmplayer.exe" "%1"',
            ]
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True, encoding='cp866', errors='ignore')

    def restore_fonts(self):
        if self.options.get("restore_fonts", False):
            self.signals.status.emit("Восстановление шрифтов...")
            self.log_action("Восстановление шрифтов [BETA]")
            commands = [
                'reg delete "HKCU\\Control Panel\\Desktop" /v FontSmoothing /f',
                'reg delete "HKCU\\Control Panel\\Desktop" /v FontSmoothingType /f',
                'reg delete "HKCU\\Software\\Microsoft\\Windows\\DWM" /v UseDpiScaling /f',
                'net stop "Windows Presentation Foundation Font Cache 3.0.0.0"',
                'net stop "Windows Presentation Foundation Font Cache 4.0.0.0"',
                'del /q /f /s "%localappdata%\\Microsoft\\Windows\\FontCache*.dat"',
                'del /q /f /s "%windir%\\system32\\FNTCACHE.DAT"',
                'taskkill /f /im dwm.exe',
                'net start "Windows Presentation Foundation Font Cache 3.0.0.0"',
                'net start "Windows Presentation Foundation Font Cache 4.0.0.0"',
            ]
            for cmd in commands:
                subprocess.run(cmd, shell=True, capture_output=True, encoding='cp866', errors='ignore')

    def run_sfc(self):
        pass

    def reset_network(self):
        pass

    def restore_mbr(self):
        pass

class FixWorker(QThread):
    finished = Signal()
    status = Signal(str)
    fix_log = Signal(str)
    
    def __init__(self, items, fix_type):
        super().__init__()
        self.items = items
        self.fix_type = fix_type
        
    def run(self):
        total = len(self.items)
        for i, item in enumerate(self.items):
            self.status.emit(f"Исправление {i+1} из {total}...")
            self.fix_item(item)
        self.finished.emit()
    
    def fix_item(self, item):
        hive, key_path, value_name, expected, action = item[0], item[1], item[2], item[3], item[4]
        desc = item[-1] if len(item) > 6 and isinstance(item[-1], str) else ""
        
        try:
            if action == "delete":
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, value_name)
                winreg.CloseKey(key)
                self.fix_log.emit(f"[FIXED] {key_path}\\{value_name} — удалён")
            elif action == "delete_subkey":
                parent_path = key_path.rsplit('\\', 1)[0]
                subkey_name = key_path.rsplit('\\', 1)[1]
                key = winreg.OpenKey(hive, parent_path, 0, winreg.KEY_ALL_ACCESS)
                winreg.DeleteKey(key, subkey_name)
                winreg.CloseKey(key)
                self.fix_log.emit(f"[FIXED] {key_path} — раздел удалён")
            elif action == "delete_ifeo":
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                try:
                    winreg.DeleteValue(key, value_name)
                except:
                    pass
                winreg.CloseKey(key)
                self.fix_log.emit(f"[FIXED] IFEO\\{key_path} — Debugger удалён")
            elif action == "value":
                if expected is not None:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                    if isinstance(expected, str):
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, expected)
                    elif isinstance(expected, int):
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_DWORD, expected)
                    winreg.CloseKey(key)
                    self.fix_log.emit(f"[FIXED] {key_path}\\{value_name} — восстановлено в {expected}")
            elif action == "multisz":
                if expected is not None:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_SET_VALUE)
                    if isinstance(expected, list):
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_MULTI_SZ, expected)
                    elif isinstance(expected, str):
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_MULTI_SZ, [expected])
                    winreg.CloseKey(key)
                    self.fix_log.emit(f"[FIXED] {key_path}\\{value_name} — восстановлено в {expected}")
        except Exception as e:
            self.fix_log.emit(f"[ERROR] {key_path}\\{value_name} — {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Threatbit Simple Scanner | v{VERSION}")
        self.setMinimumSize(950, 550)
        self.resize(950, 600)
        
        self.log_dir = Path.home() / "Documents" / "ThreatbitScanner_log"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.html_log_path = self.log_dir / "ThreatbitHTML.html"
        self.init_html_log()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        nav_frame = QFrame()
        nav_frame.setFixedWidth(180)
        nav_frame.setStyleSheet("""
            QFrame {
                background-color: #0A4C6B;
                border-right: 2px solid #063349;
            }
            QPushButton {
                background-color: #0A4C6B;
                color: white;
                border: none;
                padding: 10px;
                text-align: left;
                font-family: 'Consolas';
                font-size: 12px;
                border-bottom: 1px solid #063349;
            }
            QPushButton:hover {
                background-color: #0D5E82;
            }
            QPushButton:checked {
                background-color: #063349;
                border-left: 4px solid #00A8E8;
            }
        """)
        nav_layout = QVBoxLayout(nav_frame)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(0)
        
        self.btn_scan = QPushButton("Threat-скан")
        self.btn_tools = QPushButton("Ручные инструменты")
        self.btn_about = QPushButton("Об Авторе")
        
        for btn in [self.btn_scan, self.btn_tools, self.btn_about]:
            btn.setCheckable(True)
            btn.setFont(QFont("Consolas", 11))
            nav_layout.addWidget(btn)
        
        winpe_status = "PE режим" if is_winpe() else "Обычный режим"
        pe_label = QLabel(f"Режим: {winpe_status}")
        pe_label.setFont(QFont("Consolas", 8))
        pe_label.setStyleSheet("color: #AAAAAA; padding: 6px;")
        pe_label.setAlignment(Qt.AlignCenter)
        nav_layout.addWidget(pe_label)
        
        self.update_label = QLabel(f"v{VERSION}")
        self.update_label.setFont(QFont("Consolas", 8))
        self.update_label.setStyleSheet("color: #888888; padding: 4px;")
        self.update_label.setAlignment(Qt.AlignCenter)
        nav_layout.addWidget(self.update_label)
        
        nav_layout.addStretch()
        
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.setStyleSheet("background-color: #1E1E1E; color: white; font-family: 'Consolas';")
        
        self.scan_page = ScanPage(self)
        self.tools_page = ToolsPage()
        self.about_page = AboutPage()
        
        self.stacked_widget.addWidget(self.scan_page)
        self.stacked_widget.addWidget(self.tools_page)
        self.stacked_widget.addWidget(self.about_page)
        
        self.btn_scan.clicked.connect(lambda: self.switch_page(0))
        self.btn_tools.clicked.connect(lambda: self.switch_page(1))
        self.btn_about.clicked.connect(lambda: self.switch_page(2))
        
        main_layout.addWidget(nav_frame)
        main_layout.addWidget(self.stacked_widget, 1)
        
        self.btn_scan.setChecked(True)
        
        self.update_checker = UpdateChecker()
        self.update_checker.update_available.connect(self.on_update_available)
        self.update_checker.check_finished.connect(self.on_check_finished)
        self.update_checker.start()

    def init_html_log(self):
        with open(self.html_log_path, "w", encoding="utf-8") as f:
            f.write("""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Threatbit Scanner Log</title>
<style>body{background:#1E1E1E;color:#FFF;font-family:Consolas;padding:20px}
.red{color:#FF6B6B}.yellow{color:#FFD93D}.green{color:#4CAF50}.time{color:#AAA}
th,td{padding:8px;border:1px solid #555}th{background:#333}</style></head>
<body><h1>Threatbit Simple Scanner v""" + VERSION + """</h1>
<table><tr><th>Время</th><th>Тип</th><th>Действие</th><th>Описание</th></tr>""")
    
    def add_html_log(self, row_type, action, description):
        color_class = "red" if row_type == "red" else "yellow" if row_type == "yellow" else "green"
        with open(self.html_log_path, "a", encoding="utf-8") as f:
            f.write(f'<tr><td class="time">{datetime.now().strftime("%H:%M:%S")}</td>'
                    f'<td class="{color_class}">{row_type.upper()}</td>'
                    f'<td>{action}</td><td>{description}</td></tr>\n')

    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        for btn in [self.btn_scan, self.btn_tools, self.btn_about]:
            btn.setChecked(False)
        [self.btn_scan, self.btn_tools, self.btn_about][index].setChecked(True)

    def on_update_available(self, latest_version, url):
        self.update_label.setText(f"Доступна v{latest_version}")
        self.update_label.setStyleSheet("color: #00A8E8; padding: 4px; font-weight: bold;")
        reply = QMessageBox.question(
            self, "Доступно обновление",
            f"Доступна новая версия: v{latest_version}\nТекущая версия: v{VERSION}\n\nПерейти на страницу загрузки?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            os.startfile(url)
    
    def on_check_finished(self, has_update):
        if has_update is None:
            self.update_label.setText(f"v{VERSION} (автономный режим)")
            self.update_label.setStyleSheet("color: #888888; padding: 4px;")
        elif has_update:
            pass
        else:
            self.update_label.setText(f"v{VERSION} актуальна")
            self.update_label.setStyleSheet("color: #888888; padding: 4px;")

class ScanPage(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.worker = None
        self.fix_worker = None
        self.threats_list = []
        self.suspicious_list = []
        self.found_threats = []
        self.found_suspicious = []
        
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        
        self.options_frame = QFrame()
        self.options_frame.setStyleSheet("QFrame { background-color: #2D2D2D; border-radius: 6px; padding: 10px; }")
        options_layout = QVBoxLayout(self.options_frame)
        options_layout.setSpacing(4)
        
        checks = [
            ("Удалять все вредоносные (красные) элементы", "remove_red", True),
            ("Удалять все подозрительные (жёлтые) элементы", "remove_yellow", False),
            ("Выполнить логирование действий в Documents", "log_enabled", True),
            ("Восстановить UAC на полный доступ", "restore_uac", True),
            ("Сбросить схемы электропитания", "reset_power", False),
            ("Включить полную функцию Defender", "enable_defender", True),
            ("Восстановление ассоциаций", "restore_associations", True),
            ("Восстановить MBR", "restore_mbr", False),
            ("Восстановление шрифтов [BETA]", "restore_fonts", False),
            ("Выполнить sfc /scannow после проверки", "run_sfc", False),
            ("Сбросить Winsock, файл Hosts и DNS-кэш", "reset_network", False),
        ]
        
        self.checkboxes = {}
        for text, key, default in checks:
            cb = QCheckBox(text)
            cb.setChecked(default)
            cb.setFont(QFont("Consolas", 9))
            cb.setStyleSheet("color: white;")
            self.checkboxes[key] = cb
            options_layout.addWidget(cb)
        
        self.scan_button = QPushButton("Сканировать")
        self.scan_button.setFont(QFont("Consolas", 11, QFont.Bold))
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #0098FF; }
            QPushButton:pressed { background-color: #005A9E; }
        """)
        self.scan_button.clicked.connect(self.start_scan)
        
        self.progress_frame = QFrame()
        self.progress_frame.setVisible(False)
        progress_layout = QVBoxLayout(self.progress_frame)
        progress_layout.setSpacing(6)
        
        self.status_label = QLabel("Готов к сканированию")
        self.status_label.setFont(QFont("Consolas", 10))
        self.status_label.setStyleSheet("color: #AAAAAA;")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #555;
                border-radius: 4px;
                text-align: center;
                background-color: #333;
                color: white;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #007ACC;
                border-radius: 2px;
            }
        """)
        
        self.threats_text = QTextEdit()
        self.threats_text.setReadOnly(True)
        self.threats_text.setMaximumHeight(130)
        self.threats_text.setFont(QFont("Consolas", 9))
        self.threats_text.setStyleSheet("""
            QTextEdit {
                background-color: #252526;
                border: 1px solid #555;
                border-radius: 3px;
                color: #FF6B6B;
                font-family: 'Consolas';
            }
        """)
        
        self.scan_again_button = QPushButton("Сканировать снова")
        self.scan_again_button.setFont(QFont("Consolas", 11, QFont.Bold))
        self.scan_again_button.setStyleSheet("""
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #0098FF; }
            QPushButton:pressed { background-color: #005A9E; }
        """)
        self.scan_again_button.setVisible(False)
        self.scan_again_button.clicked.connect(self.reset_scan)
        
        progress_layout.addWidget(self.status_label)
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.threats_text)
        progress_layout.addWidget(self.scan_again_button)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.options_frame)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")
        
        layout.addWidget(scroll_area)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.progress_frame)
        layout.addStretch()

    def reset_scan(self):
        self.options_frame.setVisible(True)
        self.scan_button.setVisible(True)
        self.progress_frame.setVisible(False)
        self.scan_again_button.setVisible(False)
        self.threats_list.clear()
        self.suspicious_list.clear()
        self.found_threats.clear()
        self.found_suspicious.clear()
        self.threats_text.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText("Готов к сканированию")

    def start_scan(self):
        self.options_frame.setVisible(False)
        self.scan_button.setVisible(False)
        self.progress_frame.setVisible(True)
        self.scan_again_button.setVisible(False)
        self.threats_list.clear()
        self.suspicious_list.clear()
        self.found_threats.clear()
        self.found_suspicious.clear()
        self.threats_text.clear()
        
        options = {key: cb.isChecked() for key, cb in self.checkboxes.items()}
        self.worker = ScanWorker(options)
        self.worker.signals.progress.connect(self.progress_bar.setValue)
        self.worker.signals.status.connect(self.status_label.setText)
        self.worker.signals.threat_found.connect(self.add_threat)
        self.worker.signals.finished.connect(self.scan_finished)
        self.worker.signals.log.connect(self.log_message)
        self.worker.start()

    def add_threat(self, path, threat_type, description):
        color = "#FF6B6B" if threat_type == "red" else "#FFD93D"
        label = "УГРОЗА" if threat_type == "red" else "ПОДОЗРИТЕЛЬНО"
        self.threats_text.append(
            f'<span style="color: {color};">[{label}] {path}</span><br>'
            f'<span style="color: #AAAAAA; font-size: 9px;">  └ {description}</span><br>'
        )
        if threat_type == "red":
            self.threats_list.append(path)
        else:
            self.suspicious_list.append(path)
        self.main_window.add_html_log(threat_type, "Обнаружено", f"{path} — {description}")

    def log_message(self, msg):
        if self.checkboxes.get("log_enabled", None) and self.checkboxes["log_enabled"].isChecked():
            log_dir = Path.home() / "Documents" / "ThreatbitScanner_log"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "Threatbit.log"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat()}] {msg}\n")

    def scan_finished(self, threats, suspicious):
        self.progress_bar.setValue(100)
        self.status_label.setText("Сканирование завершено!")
        self.scan_again_button.setVisible(True)
        self.found_threats = threats
        self.found_suspicious = suspicious
        
        subprocess.run([
            "powershell", "-Command",
            "Add-Type -AssemblyName System.Windows.Forms;"
            "$balmsg = New-Object System.Windows.Forms.NotifyIcon;"
            "$balmsg.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -id $pid).Path);"
            "$balmsg.BalloonTipIcon = 'Info';"
            "$balmsg.BalloonTipText = 'Сканирование ThreaBit Simple Scanner завершено! Найдено угроз: "
            + str(len(threats)) + ", подозрительных: " + str(len(suspicious)) + "';"
            "$balmsg.BalloonTipTitle = 'Успех ' + $Env:USERNAME + '!';"
            "$balmsg.Visible = $true;"
            "$balmsg.ShowBalloonTip(10000);"
        ], encoding='cp866', errors='ignore')
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Результаты сканирования")
        msg.setText(f"Найдено угроз: {len(threats)}\nПодозрительных: {len(suspicious)}")
        msg.setIcon(QMessageBox.Warning)
        
        fix_threats = msg.addButton("Починить Threats", QMessageBox.ActionRole)
        skip_all = msg.addButton("Пропустить всё", QMessageBox.RejectRole)
        skip_suspicious = msg.addButton("Пропустить Suspicious", QMessageBox.ActionRole)
        fix_suspicious = msg.addButton("Починить Suspicious", QMessageBox.ActionRole)
        
        msg.exec()
        
        clicked = msg.clickedButton()
        if clicked == fix_threats:
            self.fix_items(self.found_threats, "threats")
        elif clicked == fix_suspicious:
            self.fix_items(self.found_suspicious, "suspicious")
        
        chkdsk_msg = QMessageBox.question(
            self, "CheckDisk",
            "Вы хотите выполнить CheckDisk. Позволит найти логические ошибки и битые сектора, но принудительно отключит диск (может быть долго)?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if chkdsk_msg == QMessageBox.Yes:
            disk, ok = QInputDialog.getText(self, "Выбор диска", "Введите букву диска (например C):")
            if ok and disk:
                subprocess.run(["chkdsk", f"{disk}:", "/f", "/r", "/x"], encoding='cp866', errors='ignore')
        
        reboot_msg = QMessageBox(self)
        reboot_msg.setWindowTitle("Перезагрузка")
        reboot_msg.setText("Для принятия мер нужно выполнить перезапуск")
        
        reboot_winpe = reboot_msg.addButton("Перезагрузить в WinPE", QMessageBox.ActionRole)
        reboot_uefi = reboot_msg.addButton("Перезагрузить в UEFI", QMessageBox.ActionRole)
        reboot_classic = reboot_msg.addButton("Перезагрузить классически", QMessageBox.ActionRole)
        reboot_msg.addButton("Отмена", QMessageBox.RejectRole)
        
        reboot_msg.exec()
        
        clicked = reboot_msg.clickedButton()
        if clicked == reboot_winpe:
            subprocess.run(["shutdown", "/r", "/o", "/f", "/t", "0"], encoding='cp866', errors='ignore')
        elif clicked == reboot_uefi:
            subprocess.run(["shutdown", "/r", "/fw", "/t", "0"], encoding='cp866', errors='ignore')
        elif clicked == reboot_classic:
            subprocess.run(["shutdown", "/r", "/t", "0"], encoding='cp866', errors='ignore')

    def fix_items(self, items, fix_type):
        if not items:
            QMessageBox.information(self, "Информация", "Нет элементов для исправления.")
            return
        
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Исправление {fix_type}...")
        
        self.fix_worker = FixWorker(items, fix_type)
        self.fix_worker.status.connect(self.status_label.setText)
        self.fix_worker.finished.connect(lambda: self.fix_finished(fix_type))
        self.fix_worker.fix_log.connect(self.on_fix_log)
        self.fix_worker.start()

    def on_fix_log(self, msg):
        if self.checkboxes.get("log_enabled", False):
            log_dir = Path.home() / "Documents" / "ThreatbitScanner_log"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "Threatbit.log"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat()}] {msg}\n")
        self.main_window.add_html_log("green", "Исправлено", msg.replace("[FIXED] ", "").replace("[ERROR] ", "ОШИБКА: "))

    def fix_finished(self, fix_type):
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Исправление {fix_type} завершено!")
        QMessageBox.information(self, "Готово", f"Все элементы ({fix_type}) успешно исправлены.")

class ToolsPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        self.tools_tabs = QTabWidget()
        self.tools_tabs.setFont(QFont("Consolas", 10))
        self.tools_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #252526;
            }
            QTabBar::tab {
                background-color: #2D2D2D;
                color: white;
                padding: 6px 12px;
                border: 1px solid #555;
                border-bottom: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
            }
            QTabBar::tab:selected {
                background-color: #007ACC;
            }
            QTabBar::tab:hover {
                background-color: #3D3D3D;
            }
        """)
        
        self.services_page = ServicesPage()
        self.startup_page = StartUpPage()
        self.run_page = RegistryRunPage("Run")
        self.runonce_page = RegistryRunPage("RunOnce")
        self.tasks_page = ScheduledTasksPage()
        
        self.tools_tabs.addTab(self.services_page, "Services")
        self.tools_tabs.addTab(self.startup_page, "StartUp Folders")
        self.tools_tabs.addTab(self.run_page, "Run")
        self.tools_tabs.addTab(self.runonce_page, "RunOnce")
        self.tools_tabs.addTab(self.tasks_page, "Scheduled Tasks")
        
        layout.addWidget(self.tools_tabs)

class ServicesPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Имя службы", "Отображаемое имя", "Состояние", "Тип запуска"])
        self.tree.setFont(QFont("Consolas", 9))
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: #252526;
                color: white;
                border: 1px solid #555;
            }
            QTreeWidget::item:selected {
                background-color: #007ACC;
            }
            QHeaderView::section {
                background-color: #333;
                color: white;
                padding: 4px;
                border: 1px solid #555;
            }
        """)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.setAlternatingRowColors(True)
        self.tree.header().setStretchLastSection(True)
        
        layout.addWidget(self.tree)
        self.load_services()

    def load_services(self):
        self.tree.clear()
        try:
            c = wmi.WMI()
            for service in c.Win32_Service():
                state = service.State if service.State else "Unknown"
                start_mode = service.StartMode if service.StartMode else "Unknown"
                item = QTreeWidgetItem([
                    service.Name,
                    service.DisplayName,
                    state,
                    start_mode
                ])
                self.tree.addTopLevelItem(item)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить службы: {str(e)}")

    def show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return
        
        menu = QMenu(self)
        menu.setFont(QFont("Consolas", 9))
        menu.setStyleSheet("""
            QMenu {
                background-color: #2D2D2D;
                color: white;
                border: 1px solid #555;
            }
            QMenu::item:selected {
                background-color: #007ACC;
            }
        """)
        
        start_action = menu.addAction("Запустить")
        stop_action = menu.addAction("Остановить")
        pause_action = menu.addAction("Приостановить")
        restart_action = menu.addAction("Перезапустить")
        menu.addSeparator()
        delete_action = menu.addAction("Удалить")
        props_action = menu.addAction("Свойства")
        
        action = menu.exec(self.tree.viewport().mapToGlobal(pos))
        service_name = item.text(0)
        
        if action == start_action:
            subprocess.run(["sc", "start", service_name], capture_output=True, encoding='cp866', errors='ignore')
            time.sleep(0.5)
            self.load_services()
        elif action == stop_action:
            subprocess.run(["sc", "stop", service_name], capture_output=True, encoding='cp866', errors='ignore')
            time.sleep(0.5)
            self.load_services()
        elif action == pause_action:
            subprocess.run(["sc", "pause", service_name], capture_output=True, encoding='cp866', errors='ignore')
            time.sleep(0.5)
            self.load_services()
        elif action == restart_action:
            subprocess.run(["sc", "stop", service_name], capture_output=True, encoding='cp866', errors='ignore')
            time.sleep(1)
            subprocess.run(["sc", "start", service_name], capture_output=True, encoding='cp866', errors='ignore')
            time.sleep(0.5)
            self.load_services()
        elif action == delete_action:
            reply = QMessageBox.question(self, "Подтверждение",
                f"Вы уверены, что хотите удалить службу {service_name}?",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                subprocess.run(["sc", "delete", service_name], capture_output=True, encoding='cp866', errors='ignore')
                time.sleep(0.5)
                self.load_services()
        elif action == props_action:
            result = subprocess.run(["sc", "qc", service_name], capture_output=True, text=True, encoding='cp866', errors='ignore')
            QMessageBox.information(self, f"Свойства службы {service_name}", result.stdout if result.stdout else "Нет данных")

class StartUpPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Имя файла", "Полный путь", "Расположение"])
        self.tree.setFont(QFont("Consolas", 9))
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: #252526;
                color: white;
                border: 1px solid #555;
            }
            QTreeWidget::item:selected {
                background-color: #007ACC;
            }
            QHeaderView::section {
                background-color: #333;
                color: white;
                padding: 4px;
                border: 1px solid #555;
            }
        """)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.tree.setAlternatingRowColors(True)
        self.tree.header().setStretchLastSection(True)
        
        layout.addWidget(self.tree)
        self.load_startup_items()

    def load_startup_items(self):
        self.tree.clear()
        paths = [
            (r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", "Общие"),
            (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "Пользовательские")
        ]
        
        for path, location in paths:
            if os.path.exists(path):
                for file in os.listdir(path):
                    full_path = os.path.join(path, file)
                    if os.path.isfile(full_path):
                        item = QTreeWidgetItem([file, full_path, location])
                        self.tree.addTopLevelItem(item)

    def show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return
        
        menu = QMenu(self)
        menu.setFont(QFont("Consolas", 9))
        menu.setStyleSheet("""
            QMenu {
                background-color: #2D2D2D;
                color: white;
                border: 1px solid #555;
            }
            QMenu::item:selected {
                background-color: #007ACC;
            }
        """)
        
        delete_action = menu.addAction("Удалить")
        props_action = menu.addAction("Свойства")
        location_action = menu.addAction("Открыть расположение файла")
        
        action = menu.exec(self.tree.viewport().mapToGlobal(pos))
        
        if action == delete_action:
            reply = QMessageBox.question(self, "Подтверждение",
                f"Вы уверены, что хотите удалить {item.text(0)}?",
                QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                try:
                    os.remove(item.text(1))
                    self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))
                except Exception as e:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось удалить файл: {str(e)}")
        elif action == props_action:
            try:
                subprocess.run(["rundll32.exe", "shell32.dll,SHObjectProperties", item.text(1)], 
                             capture_output=True, encoding='cp866', errors='ignore')
            except:
                pass
        elif action == location_action:
            try:
                subprocess.run(["explorer", "/select,", item.text(1)], capture_output=True, encoding='cp866', errors='ignore')
            except:
                pass

class RegistryRunPage(QWidget):
    def __init__(self, run_type):
        super().__init__()
        self.run_type = run_type
        layout = QVBoxLayout(self)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Название", "Значение", "Источник"])
        self.tree.setFont(QFont("Consolas", 9))
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: #252526;
                color: white;
                border: 1px solid #555;
            }
            QTreeWidget::item:selected {
                background-color: #007ACC;
            }
            QHeaderView::section {
                background-color: #333;
                color: white;
                padding: 4px;
                border: 1px solid #555;
            }
        """)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.tree.setAlternatingRowColors(True)
        self.tree.header().setStretchLastSection(True)
        
        layout.addWidget(self.tree)
        self.load_items()

    def load_items(self):
        self.tree.clear()
        paths = []
        
        if self.run_type == "Run":
            paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\SOFTWARE\\...\\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\WOW6432Node\\...\\Run"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run")
            ]
        elif self.run_type == "RunOnce":
            paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\SOFTWARE\\...\\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\WOW6432Node\\...\\RunOnce"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce")
            ]
        
        for hive, path, source in paths:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        item = QTreeWidgetItem([name, str(value), source])
                        self.tree.addTopLevelItem(item)
                        index += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except:
                pass

    def show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return
        
        menu = QMenu(self)
        menu.setFont(QFont("Consolas", 9))
        menu.setStyleSheet("""
            QMenu {
                background-color: #2D2D2D;
                color: white;
                border: 1px solid #555;
            }
            QMenu::item:selected {
                background-color: #007ACC;
            }
        """)
        
        delete_action = menu.addAction("Удалить")
        edit_action = menu.addAction("Изменить значение")
        location_action = menu.addAction("Открыть расположение файла")
        
        action = menu.exec(self.tree.viewport().mapToGlobal(pos))
        
        if action == delete_action:
            source = item.text(2)
            if "HKLM\\SOFTWARE" in source:
                hive = winreg.HKEY_LOCAL_MACHINE
                if "WOW6432Node" in source:
                    path = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion" + ("\\Run" if self.run_type == "Run" else "\\RunOnce")
                else:
                    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion" + ("\\Run" if self.run_type == "Run" else "\\RunOnce")
            else:
                hive = winreg.HKEY_CURRENT_USER
                path = r"SOFTWARE\Microsoft\Windows\CurrentVersion" + ("\\Run" if self.run_type == "Run" else "\\RunOnce")
            
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(key, item.text(0))
                winreg.CloseKey(key)
                self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))
            except Exception as e:
                QMessageBox.warning(self, "Ошибка", f"Не удалось удалить параметр: {str(e)}")
                
        elif action == edit_action:
            new_value, ok = QInputDialog.getText(self, "Изменить значение", 
                "Новое значение:", text=item.text(1))
            if ok and new_value:
                source = item.text(2)
                if "HKLM\\SOFTWARE" in source:
                    hive = winreg.HKEY_LOCAL_MACHINE
                    if "WOW6432Node" in source:
                        path = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion" + ("\\Run" if self.run_type == "Run" else "\\RunOnce")
                    else:
                        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion" + ("\\Run" if self.run_type == "Run" else "\\RunOnce")
                else:
                    hive = winreg.HKEY_CURRENT_USER
                    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion" + ("\\Run" if self.run_type == "Run" else "\\RunOnce")
                
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, item.text(0), 0, winreg.REG_SZ, new_value)
                    winreg.CloseKey(key)
                    item.setText(1, new_value)
                except Exception as e:
                    QMessageBox.warning(self, "Ошибка", f"Не удалось изменить значение: {str(e)}")
                    
        elif action == location_action:
            file_path = item.text(1)
            if file_path:
                try:
                    if file_path.startswith('"'):
                        file_path = file_path.strip('"').split('"')[0]
                    if os.path.exists(file_path):
                        subprocess.run(["explorer", "/select,", file_path], capture_output=True, encoding='cp866', errors='ignore')
                    elif os.path.exists(os.path.dirname(file_path)):
                        subprocess.run(["explorer", os.path.dirname(file_path)], capture_output=True, encoding='cp866', errors='ignore')
                except:
                    pass


class ScheduledTasksPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Имя задачи", "Состояние", "Следующий запуск", "Триггеры", "Автор", "Описание"])
        self.tree.setFont(QFont("Consolas", 9))
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: #252526;
                color: white;
                border: 1px solid #555;
            }
            QTreeWidget::item:selected {
                background-color: #007ACC;
            }
            QHeaderView::section {
                background-color: #333;
                color: white;
                padding: 4px;
                border: 1px solid #555;
            }
        """)
        self.tree.setAlternatingRowColors(True)
        self.tree.header().setStretchLastSection(True)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.tree.setRootIsDecorated(True)

        layout.addWidget(self.tree)
        self.load_tasks()

    def _get_trigger_string(self, trigger):
        try:
            trigger_type = trigger.Type
            type_names = {
                0: "Событие",
                1: "Ежедневно",
                2: "Еженедельно",
                3: "Ежемесячно",
                4: "ЕжемесячноDOW",
                5: "При простое",
                6: "При загрузке",
                7: "При регистрации",
                8: "При входе",
                9: "При старте системы",
                10: "При простое",
                11: "При подключении",
                12: "При разблокировке",
            }
            return type_names.get(trigger_type, f"Тип {trigger_type}")
        except:
            return "N/A"

    def load_tasks(self):
        self.tree.clear()
        try:
            import pythoncom
            from win32com.client import Dispatch

            pythoncom.CoInitialize()
            scheduler = Dispatch('Schedule.Service')
            scheduler.Connect()
            root_folder = scheduler.GetFolder('\\')
            self._add_tasks_from_folder(root_folder, None)
            pythoncom.CoUninitialize()
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить задачи: {str(e)}")

    def _add_tasks_from_folder(self, folder, parent_item):
        try:
            tasks = folder.GetTasks(1)
            for task in tasks:
                name = task.Name
                path = task.Path

                state_map = {0: "Unknown", 1: "Disabled", 2: "Queued", 3: "Ready", 4: "Running"}
                state = state_map.get(task.State, "Unknown")

                next_run = "N/A"
                try:
                    if task.NextRunTime:
                        next_run = task.NextRunTime.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass

                triggers_list = []
                try:
                    for trigger in task.Definition.Triggers:
                        triggers_list.append(self._get_trigger_string(trigger))
                except:
                    pass
                triggers_str = ", ".join(triggers_list) if triggers_list else "N/A"

                author = "N/A"
                description = "N/A"
                try:
                    author = task.Definition.Principal.UserId
                except:
                    pass
                try:
                    description = task.Definition.RegistrationInfo.Description
                except:
                    pass

                item = QTreeWidgetItem([name, state, next_run, triggers_str, author, description])
                item.setData(0, Qt.UserRole, path)

                if parent_item:
                    parent_item.addChild(item)
                else:
                    self.tree.addTopLevelItem(item)

            subfolders = folder.GetFolders(0)
            for subfolder in subfolders:
                if parent_item:
                    folder_item = QTreeWidgetItem(parent_item, [subfolder.Name, "", "", "", "", ""])
                else:
                    folder_item = QTreeWidgetItem(self.tree, [subfolder.Name, "", "", "", "", ""])
                self._add_tasks_from_folder(subfolder, folder_item)
        except:
            pass

    def show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item:
            return

        task_path = item.data(0, Qt.UserRole)

        menu = QMenu(self)
        menu.setFont(QFont("Consolas", 9))
        menu.setStyleSheet("""
            QMenu {
                background-color: #2D2D2D;
                color: white;
                border: 1px solid #555;
            }
            QMenu::item:selected {
                background-color: #007ACC;
            }
        """)

        if task_path:
            enable_action = menu.addAction("Включить")
            disable_action = menu.addAction("Отключить")
            run_action = menu.addAction("Запустить")
            end_action = menu.addAction("Завершить")
            menu.addSeparator()
            export_action = menu.addAction("Экспортировать")
            props_action = menu.addAction("Свойства")
            menu.addSeparator()
            delete_action = menu.addAction("Удалить")
        else:
            return

        action = menu.exec(self.tree.viewport().mapToGlobal(pos))

        if action == enable_action:
            subprocess.run(["schtasks", "/change", "/tn", task_path, "/enable"],
                           capture_output=True, encoding='cp866', errors='ignore', shell=True)
            self.load_tasks()
        elif action == disable_action:
            subprocess.run(["schtasks", "/change", "/tn", task_path, "/disable"],
                           capture_output=True, encoding='cp866', errors='ignore', shell=True)
            self.load_tasks()
        elif action == run_action:
            subprocess.run(["schtasks", "/run", "/tn", task_path],
                           capture_output=True, encoding='cp866', errors='ignore', shell=True)
        elif action == end_action:
            subprocess.run(["schtasks", "/end", "/tn", task_path],
                           capture_output=True, encoding='cp866', errors='ignore', shell=True)
        elif action == export_action:
            file_path, _ = QFileDialog.getSaveFileName(self, "Экспорт задачи",
                                                       f"{item.text(0)}.xml", "XML Files (*.xml)")
            if file_path:
                result = subprocess.run(["schtasks", "/query", "/tn", task_path, "/xml"],
                                        capture_output=True, text=True, encoding='cp866', errors='ignore', shell=True)
                if result.stdout:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(result.stdout)
        elif action == props_action:
            result = subprocess.run(["schtasks", "/query", "/tn", task_path, "/v", "/fo", "LIST"],
                                    capture_output=True, text=True, encoding='cp866', errors='ignore', shell=True)

            dialog = QDialog(self)
            dialog.setWindowTitle(f"Свойства задачи: {item.text(0)}")
            dialog.setMinimumSize(600, 500)
            dialog.resize(700, 600)

            layout = QVBoxLayout(dialog)

            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Consolas", 9))
            text_edit.setStyleSheet("""
                QTextEdit {
                    background-color: #252526;
                    color: white;
                    border: 1px solid #555;
                    font-family: 'Consolas';
                }
            """)
            text_edit.setPlainText(result.stdout if result.stdout else "Нет данных")

            layout.addWidget(text_edit)

            button_box = QDialogButtonBox(QDialogButtonBox.Ok)
            button_box.accepted.connect(dialog.accept)
            button_box.setStyleSheet("""
                QPushButton {
                    background-color: #007ACC;
                    color: white;
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    font-family: 'Consolas';
                }
                QPushButton:hover {
                    background-color: #0098FF;
                }
            """)

            layout.addWidget(button_box)

            dialog.exec()
        elif action == delete_action:
            reply = QMessageBox.question(self, "Подтверждение",
                                         f"Вы уверены, что хотите удалить задачу\n{item.text(0)}?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                subprocess.run(["schtasks", "/delete", "/tn", task_path, "/f"],
                               capture_output=True, encoding='cp866', errors='ignore', shell=True)
                self.load_tasks()
class AboutPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        title = QLabel(f"Threatbit Simple Scanner | v{VERSION}")
        title.setFont(QFont("Consolas", 16, QFont.Bold))
        title.setStyleSheet("color: #007ACC;")
        title.setAlignment(Qt.AlignCenter)
        
        author = QLabel("Author - ThreatBit with 2M12")
        author.setFont(QFont("Consolas", 12))
        author.setStyleSheet("color: white;")
        author.setAlignment(Qt.AlignCenter)
        
        github = QLabel('<a href="https://github.com/2M12" style="color: #00A8E8;">2M12 Github</a>')
        github.setFont(QFont("Consolas", 11))
        github.setAlignment(Qt.AlignCenter)
        github.setOpenExternalLinks(True)
        
        dzen = QLabel('<a href="https://dzen.ru/threatbit" style="color: #00A8E8;">ThreatBit Dzen</a>')
        dzen.setFont(QFont("Consolas", 11))
        dzen.setAlignment(Qt.AlignCenter)
        dzen.setOpenExternalLinks(True)
        
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(author)
        layout.addWidget(github)
        layout.addWidget(dzen)
        layout.addStretch()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(30, 30, 30))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(37, 37, 38))
    palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(45, 45, 45))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.Highlight, QColor(0, 122, 204))
    palette.setColor(QPalette.HighlightedText, Qt.white)
    app.setPalette(palette)
    
    if not is_admin():
        msg = QMessageBox()
        msg.setWindowTitle("Требуются права администратора")
        msg.setText("Для работы программы необходимы права администратора. Запустить с правами администратора?")
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        
        if msg.exec() == QMessageBox.Yes:
            run_as_admin()
        sys.exit()
    
    if is_winpe():
        load_hive(r"C:\Windows\System32\config\SOFTWARE", "PE_SOFTWARE")
        load_hive(r"C:\Windows\System32\config\SYSTEM", "PE_SYSTEM")
    
    window = MainWindow()
    window.show()
    
    if is_winpe():
        unload_hive("PE_SOFTWARE")
        unload_hive("PE_SYSTEM")
    
    sys.exit(app.exec())

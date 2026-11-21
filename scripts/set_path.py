import winreg
import os
import shutil

scripts_dir = r"C:\Users\Chamika\AppData\Roaming\Python\Python314\Scripts"

# 1. Update Windows User Environment PATH in Registry
try:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_ALL_ACCESS)
    try:
        path_val, _ = winreg.QueryValueEx(key, "Path")
    except FileNotFoundError:
        path_val = ""

    if scripts_dir.lower() not in path_val.lower():
        new_val = f"{scripts_dir};{path_val}"
        winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_val)
        print("Updated User Registry PATH with:", scripts_dir)
    else:
        print("Already in User PATH registry.")
    winreg.CloseKey(key)
except Exception as e:
    print("Could not update registry:", e)

# 2. Also ensure umbra.exe is in C:\Users\Chamika\AppData\Local\Microsoft\WindowsApps
windows_apps = r"C:\Users\Chamika\AppData\Local\Microsoft\WindowsApps"
src_umbra = os.path.join(scripts_dir, "umbra.exe")
if os.path.exists(src_umbra):
    try:
        shutil.copy2(src_umbra, os.path.join(windows_apps, "umbra.exe"))
        print("Copied umbra.exe to WindowsApps")
    except Exception as e:
        print("Copy to WindowsApps error:", e)

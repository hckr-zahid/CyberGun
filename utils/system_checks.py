import ctypes
import os
import sys
def is_admin() -> bool:
    """
    Checks if the current process has administrator/root privileges.
    Works on both Windows and POSIX systems.
    """
    try:
        if sys.platform == 'win32':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except AttributeError:
        return False
    except Exception:
        return False
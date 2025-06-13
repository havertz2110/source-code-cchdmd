import psutil
import pefile
import ctypes
import time
from ctypes import wintypes

# --- Windows API definitions ---
# (Keep all your existing Windows API definitions here)
# Define ULONG_PTR and SIZE_T based on Python's architecture
if ctypes.sizeof(ctypes.c_void_p) == 8:  # 64-bit Python
    ULONG_PTR = ctypes.c_ulonglong
    SIZE_T = ctypes.c_ulonglong
else:  # 32-bit Python
    ULONG_PTR = ctypes.c_ulong
    SIZE_T = ctypes.c_ulong

# Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# Structures
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", wintypes.LPVOID),
        ("PebBaseAddress", wintypes.LPVOID),
        ("Reserved2", wintypes.LPVOID * 2),
        ("UniqueProcessId", ULONG_PTR),
        ("Reserved3", wintypes.LPVOID),
    ]

ntdll = ctypes.WinDLL("ntdll")
kernel32 = ctypes.WinDLL("kernel32")

try:
    NtQueryInformationProcess = ntdll.NtQueryInformationProcess
    NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.POINTER(PROCESS_BASIC_INFORMATION),
        wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
    ]
    NtQueryInformationProcess.restype = ctypes.c_long
except AttributeError:
    NtQueryInformationProcess = None

IsWow64Process = kernel32.IsWow64Process
IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
IsWow64Process.restype = wintypes.BOOL
# --- End Windows API definitions ---

# Define the target status string for suspended processes on Windows
# For psutil versions/builds where STATUS_SUSPENDED is not exposed,
# 'stopped' is typically used for suspended processes on Windows.
PSUTIL_SUSPENDED_STATUS_STRING = "stopped"


def get_process_is_wow64(h_process):
    # (Your existing get_process_is_wow64 function - unchanged)
    if not hasattr(kernel32, 'IsWow64Process2'):
        is_wow64 = wintypes.BOOL()
        if IsWow64Process(h_process, ctypes.byref(is_wow_64)): # Corrected variable name
            return bool(is_wow_64.value) # Corrected variable name
        return False

    IMAGE_FILE_MACHINE_I386 = 0x014c
    IMAGE_FILE_MACHINE_AMD64 = 0x8664 # Not used directly here but good for context
    p_process_machine = wintypes.USHORT()
    p_native_machine = wintypes.USHORT()
    if hasattr(kernel32, 'IsWow64Process2') and \
       kernel32.IsWow64Process2(h_process, ctypes.byref(p_process_machine), ctypes.byref(p_native_machine)):
        # A process is WOW64 if its machine type is I386 and the host is AMD64
        return p_process_machine.value == IMAGE_FILE_MACHINE_I386 # Simplified based on typical usage
    # Fallback for older systems or if IsWow64Process2 fails
    is_wow_64_fallback = wintypes.BOOL()
    if kernel32.IsWow64Process(h_process, ctypes.byref(is_wow_64_fallback)):
        return bool(is_wow_64_fallback.value)
    return False


def get_peb_image_base_address(pid):
    # (Your existing get_peb_image_base_address function - unchanged, ensure SIZE_T is used for bytes_read)
    if NtQueryInformationProcess is None: return None
    h_process = None
    image_base_address = None
    try:
        h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_process: return None

        pbi = PROCESS_BASIC_INFORMATION()
        return_length = wintypes.ULONG()
        status = NtQueryInformationProcess(h_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(return_length))
        if status != 0: return None

        peb_base_address_ptr = pbi.PebBaseAddress
        if not peb_base_address_ptr: return None

        is_target_wow64 = get_process_is_wow64(h_process)
        image_base_offset = 0x08 if is_target_wow64 else 0x10
        address_size = 4 if is_target_wow64 else 8
        image_base_buffer = (ctypes.c_byte * address_size)()
        bytes_read = SIZE_T() # Use our defined SIZE_T

        if kernel32.ReadProcessMemory(
            h_process,
            ctypes.c_void_p(peb_base_address_ptr + image_base_offset),
            ctypes.byref(image_base_buffer),
            address_size,
            ctypes.byref(bytes_read)
        ):
            if bytes_read.value == address_size:
                if is_target_wow64:
                    image_base_address = ctypes.cast(image_base_buffer, ctypes.POINTER(wintypes.UINT)).contents.value
                else:
                    image_base_address = ctypes.cast(image_base_buffer, ctypes.POINTER(wintypes.ULONG64)).contents.value
    except Exception:
        pass
    finally:
        if h_process: kernel32.CloseHandle(h_process)
    return image_base_address

def get_disk_image_base(exe_path):
    # (Your existing get_disk_image_base function - unchanged)
    try:
        pe = pefile.PE(exe_path)
        return pe.OPTIONAL_HEADER.ImageBase
    except (pefile.PEFormatError, FileNotFoundError, AttributeError, Exception):
        return None

def monitor_processes():
    print("Starting process hollowing monitor (focusing on SUSPENDED processes)...")
    print(f"(Using status string '{PSUTIL_SUSPENDED_STATUS_STRING}' to identify suspended processes)")
    print("Run this script with Administrator privileges for best results.")
    print("Monitoring processes. Press Ctrl+C to stop.\n")

    checked_suspended_pids = set()

    while True:
        try:
            current_pids = set()
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'status']):
                pid = proc.info['pid']
                current_pids.add(pid)

                try:
                    status_str = proc.info['status'] # Get the status string
                    exe_path = proc.info['exe']
                    name = proc.info['name']

                    if not exe_path:
                        continue

                    # MODIFICATION HERE: Compare with the string directly
                    if status_str == PSUTIL_SUSPENDED_STATUS_STRING:
                        if pid not in checked_suspended_pids:
                            print(f"[*] Process '{name}' (PID: {pid}, Path: {exe_path}) is '{status_str}'. Analyzing...")
                            checked_suspended_pids.add(pid)

                            mem_image_base = get_peb_image_base_address(pid)
                            disk_image_base = get_disk_image_base(exe_path)

                            if mem_image_base is not None and disk_image_base is not None:
                                print(f"    PID {pid}: In-Memory PEB ImageBase: {hex(mem_image_base)}, On-Disk PE ImageBase: {hex(disk_image_base)}")
                                if mem_image_base != disk_image_base:
                                    print(f"  [!!!] POTENTIAL PROCESS HOLLOWING DETECTED (Status: {status_str}) [!!!]")
                                    print(f"        Process: {name} (PID: {pid})")
                                    print(f"        Executable: {exe_path}")
                                    print(f"        PEB ImageBase (Memory): {hex(mem_image_base)}")
                                    print(f"        PE ImageBase (Disk):    {hex(disk_image_base)}")
                                    print("-" * 70)
                                else:
                                    print(f"    PID {pid}: ImageBases match. Likely not hollowed via PEB ImageBase change.")
                            elif mem_image_base is None:
                                print(f"    PID {pid}: Could not retrieve in-memory PEB ImageBase (Access Denied or process unstable?).")
                            elif disk_image_base is None and exe_path:
                                print(f"    PID {pid}: Could not retrieve on-disk PE ImageBase for {exe_path}.")
                            print("-" * 70)
                    else:
                        if pid in checked_suspended_pids:
                            print(f"[*] Process '{name}' (PID: {pid}) status changed from '{PSUTIL_SUSPENDED_STATUS_STRING}' to '{status_str}'. Removing from checked list.")
                            checked_suspended_pids.remove(pid)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    if pid in checked_suspended_pids:
                        checked_suspended_pids.remove(pid)
                    continue

            stale_pids = checked_suspended_pids - current_pids
            for stale_pid in stale_pids:
                checked_suspended_pids.remove(stale_pid)

            time.sleep(1.5)

        except psutil.Error as e:
            print(f"A psutil error occurred: {e}. Re-syncing PIDs.")
            try:
                all_current_pids = {p.pid for p in psutil.process_iter(['pid'])}
                checked_suspended_pids = checked_suspended_pids.intersection(all_current_pids)
            except:
                checked_suspended_pids.clear()
            time.sleep(5)
            continue
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            time.sleep(5)

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Warning: This script is not running with Administrator privileges.")
        print("It may not be able to access information for all processes and accurately detect suspended states.")
    # Ensure NtQueryInformationProcess is loaded before monitoring
    if NtQueryInformationProcess is None:
        print("Critical Error: NtQueryInformationProcess could not be loaded. PEB check will fail.")
        print("Exiting.")
    else:
        monitor_processes()
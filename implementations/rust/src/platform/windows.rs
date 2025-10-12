//! Windows-specific memory management and API bindings

use crate::error::{Result, ScannerError};
use winapi::{
    ctypes::c_void,
    um::{
        libloaderapi::GetModuleHandleW,
        memoryapi::{VirtualProtect, VirtualQuery},
        processthreadsapi::GetCurrentProcess,
        psapi::{GetModuleInformation, MODULEINFO},
        winnt::{
            MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
        },
    },
};

/// RAII wrapper for Windows memory protection
pub struct MemoryProtection {
    address: *mut c_void,
    size: usize,
    old_protection: u32,
}

impl MemoryProtection {
    /// Create new memory protection, changing to PAGE_EXECUTE_READWRITE
    pub fn new(address: *mut c_void, size: usize) -> Result<Self> {
        let mut old_protection = 0;
        let result =
            unsafe { VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &mut old_protection) };

        if result != 0 {
            Ok(Self {
                address,
                size,
                old_protection,
            })
        } else {
            Err(ScannerError::WindowsApi(
                "Failed to change memory protection".to_string(),
            ))
        }
    }
}

impl Drop for MemoryProtection {
    fn drop(&mut self) {
        unsafe {
            let mut _temp = 0;
            VirtualProtect(self.address, self.size, self.old_protection, &mut _temp);
        }
    }
}

/// Information about the current process module
pub struct ProcessInfo {
    pub process_handle: *mut c_void,
    pub base_address: usize,
    pub module_size: usize,
}

impl ProcessInfo {
    /// Get information about the current process module
    pub fn current_process() -> Result<Self> {
        let process_handle = unsafe { GetCurrentProcess() };
        let base_address = unsafe {
            let handle = GetModuleHandleW(std::ptr::null());
            if handle.is_null() {
                return Err(ScannerError::WindowsApi(
                    "Failed to get module handle".to_string(),
                ));
            }
            handle as usize
        };

        let mut module_info = MODULEINFO {
            lpBaseOfDll: std::ptr::null_mut(),
            SizeOfImage: 0,
            EntryPoint: std::ptr::null_mut(),
        };

        let result = unsafe {
            GetModuleInformation(
                process_handle,
                base_address as *mut _,
                &mut module_info,
                std::mem::size_of::<MODULEINFO>() as u32,
            )
        };

        if result == 0 {
            return Err(ScannerError::WindowsApi(
                "Failed to get module information".to_string(),
            ));
        }

        Ok(Self {
            process_handle,
            base_address,
            module_size: module_info.SizeOfImage as usize,
        })
    }
}

/// Check if memory protection allows reading
pub fn is_memory_readable(protect: u32) -> bool {
    (protect & PAGE_READONLY) != 0
        || (protect & PAGE_READWRITE) != 0
        || (protect & PAGE_WRITECOPY) != 0
        || (protect & PAGE_EXECUTE_READ) != 0
        || (protect & PAGE_EXECUTE_READWRITE) != 0
        || (protect & PAGE_EXECUTE_WRITECOPY) != 0
}

/// Check if memory protection indicates executable code
pub fn is_memory_executable(protect: u32) -> bool {
    (protect & PAGE_EXECUTE_READ) != 0
        || (protect & PAGE_EXECUTE_READWRITE) != 0
        || (protect & PAGE_EXECUTE_WRITECOPY) != 0
}

/// Query memory information for a given address
pub fn query_memory(address: usize) -> Result<MEMORY_BASIC_INFORMATION> {
    let mut mem_info = MEMORY_BASIC_INFORMATION {
        BaseAddress: std::ptr::null_mut(),
        AllocationBase: std::ptr::null_mut(),
        AllocationProtect: 0,
        RegionSize: 0,
        State: 0,
        Protect: 0,
        Type: 0,
    };

    let result = unsafe {
        VirtualQuery(
            address as *const c_void,
            &mut mem_info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };

    if result == 0 {
        Err(ScannerError::WindowsApi(
            "VirtualQuery failed".to_string(),
        ))
    } else {
        Ok(mem_info)
    }
}
//! Platform-specific implementations

#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub mod unix;
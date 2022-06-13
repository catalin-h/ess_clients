pub(crate) mod ess;

use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

use std::cell::RefCell;
thread_local! {
    pub static LAST_ERROR: RefCell<CString> = RefCell::default();
}

fn set_last_error_str(err_str: &str) {
    LAST_ERROR.with(|refcs: &RefCell<CString>| {
        *refcs.borrow_mut() = CString::new(err_str).unwrap_or_default();
    })
}

/// Returns the last error, as a description string, that was generated after calling the ess pam API.
/// This function should be called only if the ess pam API returned [`ESS_ERROR`](ESS_ERROR).
#[no_mangle]
pub extern "C" fn ess_pam_last_error_str() -> *const c_char {
    LAST_ERROR.with(|refcs: &RefCell<CString>| refcs.borrow().as_ptr())
}

/// Request finished without errors
pub const ESS_OK: c_int = 0;
/// Request finished with errors.
/// Use ess_pam_last_error_str() to get the last error string for more details
pub const ESS_ERROR: c_int = -1;

/// Verify one time password for the unique username
///
/// Returns [`ESS_OK`](ESS_OK) if the one time password verification succeeds
/// Returns a non-zero value in case of an error. Use ess_pam_last_error_str
/// to get the last error string.
#[no_mangle]
pub extern "C" fn verify_otp(username: *const c_char, otp: *const c_char) -> c_int {
    let user_name = match to_str(username) {
        Some(user) => user,
        None => {
            set_last_error_str("Invalid user name arg");
            return ESS_ERROR;
        }
    };

    let one_time_psswd = match to_str(otp) {
        Some(otp) => otp,
        None => {
            set_last_error_str("Invalid one time password arg");
            return ESS_ERROR;
        }
    };

    match ess::verity_username_otp(user_name, one_time_psswd) {
        Ok(_) => ESS_OK,
        Err(e) => {
            set_last_error_str(&format!("Error: {}", e));
            ESS_ERROR
        }
    }
}

fn to_str(c_string: *const c_char) -> Option<&'static str> {
    if c_string.is_null() {
        return None;
    }

    unsafe { CStr::from_ptr(c_string) }.to_str().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    // return error scenario
    // Make sure you to run tests with -- --nocapture
    // https://stackoverflow.com/questions/25106554/why-doesnt-println-work-in-rust-unit-tests
    #[test]
    fn test_ret_error() {
        assert_eq!(
            verify_otp(
                CString::new("rust").unwrap_or_default().as_ptr(),
                CString::new("123456").unwrap_or_default().as_ptr()
            ),
            ESS_ERROR
        );
        let errstr = unsafe { CStr::from_ptr(ess_pam_last_error_str()) }
            .to_str()
            .unwrap();
        println!("verify_otp error: {}", errstr);
        assert!(!errstr.is_empty());
    }
}

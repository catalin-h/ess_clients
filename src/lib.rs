pub(crate) mod ess;

use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
};

/// OTP code verification was ok
pub const ESS_OK: c_int = 0;
/// OTP code verification failed
pub const ESS_OTP_VERIFY_FAILED: c_int = -1;
/// The username arg is invalid
pub const ESS_INVALID_USER_ARG: c_int = -2;
/// The otp arg is invalid
pub const ESS_INVALID_OTP_ARG: c_int = -3;
/// The username is not found
pub const ESS_USERNAME_NOT_FOUND: c_int = -4;
/// PAM service general error, e.g. not available
pub const ESS_PAM_SERVICE_ERROR: c_int = 1;
/// The unknown error
pub const ESS_UNKNOWN_ERROR: c_int = 255;

#[no_mangle]
pub extern "C" fn ess_errstr(err: c_int) -> *const c_char {
    match err {
        ESS_OK => "OK",
        ESS_OTP_VERIFY_FAILED => "OTP verify failed",
        ESS_INVALID_USER_ARG => "Invalid input user name",
        ESS_INVALID_OTP_ARG => "Invalid input OTP code",
        ESS_USERNAME_NOT_FOUND => "Username not found",
        ESS_PAM_SERVICE_ERROR => "PAM service error",
        _ => "unknown",
    }
    .as_ptr() as *const c_char
}

fn to_str(c_string: *const c_char) -> Option<&'static str> {
    if c_string.is_null() {
        return None;
    }

    unsafe { CStr::from_ptr(c_string) }.to_str().ok()
}

/// Verify one time password for the unique username
///
/// Returns [`ESS_OK`](ESS_OK) if the one time password verification succeeds
/// Returns a non-zero value in case of an error. Use [`ess_errstr`](ess_errstr)
/// to get the error string.
#[no_mangle]
pub extern "C" fn verify_otp(username: *const c_char, otp: *const c_char) -> c_int {
    let user_name = match to_str(username) {
        Some(user) => user,
        None => return ESS_INVALID_USER_ARG,
    };

    let one_time_psswd = match to_str(otp) {
        Some(otp) => otp,
        None => return ESS_INVALID_OTP_ARG,
    };

    match ess::verity_username_otp(user_name, one_time_psswd) {
        Ok(_) => ESS_OK,
        Err(_) => ESS_OTP_VERIFY_FAILED,
    }
}

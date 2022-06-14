use std::{
    env,
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

#[link(name = "ess")]
extern "C" {
    fn ess_pam_version() -> *const c_char;
    fn ess_pam_last_error_str() -> *const c_char;
    fn verify_otp(username: *const c_char, otp: *const c_char) -> c_int;
}

#[test]
pub fn test_version() {
    let version = unsafe { CStr::from_ptr(ess_pam_version()) }
        .to_str()
        .unwrap();

    println!("Found version: {}", version);
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn test_call_verify_otp() {
    env::set_var(
        "ESS_PAM_ROOT_CA",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pam-root-ca.crt"),
    );
    env::set_var(
        "ESS_PAM_CERT",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pam-client-crt.pem"),
    );
    env::set_var(
        "ESS_PAM_CERT_KEY",
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pam-client-key.pem"),
    );

    unsafe {
        assert_eq!(
            verify_otp(
                CString::new("rust").unwrap_or_default().as_ptr(),
                CString::new("123456").unwrap_or_default().as_ptr()
            ),
            -1
        )
    };
    let errstr = unsafe { CStr::from_ptr(ess_pam_last_error_str()) }
        .to_str()
        .unwrap();

    println!("verify_otp error: {}", errstr);

    assert!(!errstr.is_empty());
}

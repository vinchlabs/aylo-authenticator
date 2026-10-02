#![cfg_attr(not(test), no_std)]
#![no_main]
#![feature(custom_test_frameworks)]
#![reexport_test_harness_main = "test_main"]

#[cfg(test)]
#[test]
fn native_authenticator() {
    unsafe extern "C" {
        safe fn test_authenticator();
        safe fn test_authenticator_crypto();
        safe fn test_authenticator_call();
        safe fn test_optiga_backend();
    }
    test_authenticator();
    test_authenticator_crypto();
    test_authenticator_call();
    test_optiga_backend();
}

#[cfg(test)]
#[unsafe(no_mangle)]
pub fn main() -> i32 {
    unsafe extern "C" {
        safe fn rust_tests_c_setup();
    }

    // Initialize the C part of the library before running any tests
    rust_tests_c_setup();

    // Call the Rust test harness main function
    // The function panics if any test fails.
    // Asserting that it returns () to ensure that if a future Rust version
    // changes the signature and behavior, we'll be notified.
    assert_eq!(test_main(), ());

    // Return 0 to indicate success
    0
}

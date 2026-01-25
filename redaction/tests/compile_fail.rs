//! Compile-fail tests to ensure proper error messages for incorrect usage.
//!
//! These tests verify that the derive macro produces helpful compiler errors
//! when used incorrectly, such as:
//! - Using a classification on a struct type (should use `#[sensitive]` instead)
//! - Using `#[sensitive]` on a type that doesn't implement `SensitiveContainer`

#[test]
fn compile_fail_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}

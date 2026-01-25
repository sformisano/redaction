//! Test: Using a classification on a struct field should fail.
//!
//! Classifications like `#[sensitive(Secret)]` are for leaf values (String, etc.).
//! For struct types that derive Sensitive, use `#[sensitive]` instead to walk into them.

use redaction::{Secret, Sensitive};

#[derive(Clone, Sensitive)]
struct Inner {
    #[sensitive(Secret)]
    secret: String,
}

#[derive(Clone, Sensitive)]
struct Outer {
    // ERROR: Inner is a struct, not a SensitiveValue
    // Should use #[sensitive] instead to walk into it
    #[sensitive(Secret)]
    inner: Inner,
}

fn main() {}

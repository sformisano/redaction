//! Test: Using a classification on a scalar type should fail.
//!
//! Scalars (i32, bool, etc.) cannot use classifications like `#[sensitive(Secret)]`.
//! Use bare `#[sensitive]` instead, which redacts to the default value.

use redaction::{Secret, Sensitive};

#[derive(Clone, Sensitive)]
struct Record {
    // ERROR: scalar fields cannot use a classification
    // Use bare #[sensitive] instead
    #[sensitive(Secret)]
    count: i32,
}

fn main() {}

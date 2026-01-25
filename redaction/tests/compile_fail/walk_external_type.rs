//! Test: Using #[sensitive] on an external type that doesn't implement SensitiveContainer.
//!
//! External types like `std::time::SystemTime` don't implement `SensitiveContainer`.
//! Use no annotation to pass them through, or wrap them in a newtype.

use redaction::Sensitive;
use std::time::SystemTime;

#[derive(Clone, Sensitive)]
struct Record {
    // ERROR: SystemTime doesn't implement SensitiveContainer
    // Remove #[sensitive] to pass through unchanged
    #[sensitive]
    timestamp: SystemTime,
}

fn main() {}

//! Generic type parameter handling and trait bound management.
//!
//! This module adds bounds only for generics that are used by walked or
//! classified fields.
//!
//! ## PhantomData Handling
//!
//! `PhantomData<T>` fields are explicitly skipped when collecting generics.
//! This is essential for external type support:
//!
//! ```ignore
//! struct TypedId<T> {
//!     id: String,
//!     _marker: PhantomData<T>,  // T should NOT require SensitiveType
//! }
//! ```
//!
//! Without this, `TypedId<DateTime<Utc>>` would fail because `DateTime<Utc>`
//! doesn't implement `SensitiveType`, even though `_marker` passes through
//! unchanged (no `#[sensitive]` annotation).

use syn::{parse_quote, Ident};

use crate::crate_path;

pub(crate) fn collect_generics_from_type(
    ty: &syn::Type,
    generics: &syn::Generics,
    result: &mut Vec<Ident>,
) {
    let mut visit = |ty: &syn::Type| {
        if let syn::Type::Path(path) = ty {
            if let Some(segment) = path.path.segments.last() {
                // Skip PhantomData - it's a zero-sized marker that doesn't need bounds.
                // This is critical: PhantomData<T> fields pass through unchanged,
                // so we shouldn't require T: SensitiveType. This enables
                // patterns like `struct TypedId<T> { id: String, _marker: PhantomData<T> }`
                // to work even when T is an external type like DateTime<Utc>.
                if segment.ident == "PhantomData" {
                    return;
                }

                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    for arg in &args.args {
                        if let syn::GenericArgument::Type(inner_ty) = arg {
                            collect_generics_from_type(inner_ty, generics, result);
                        }
                    }
                }

                // Check if this type identifier matches a generic parameter
                for param in generics.type_params() {
                    if segment.ident == param.ident && !result.iter().any(|g| g == &param.ident) {
                        result.push(param.ident.clone());
                    }
                }
            }
        }
    };
    visit(ty);
}

/// Adds `SensitiveType` bounds to generic parameters used in walked fields.
pub(crate) fn add_container_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            let container_path = crate_path("SensitiveType");
            param.bounds.push(parse_quote!(#container_path));
        }
    }
    generics
}

/// Adds `Classifiable` bounds to generic parameters used in classified fields.
///
/// This enables `#[sensitive(Classification)]` to work on generic types like `T`
/// where `T` could be `String`, `Option<String>`, `Vec<String>`, etc.
pub(crate) fn add_classified_value_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            let classifiable_path = crate_path("Classifiable");
            param.bounds.push(parse_quote!(#classifiable_path));
        }
    }
    generics
}

pub(crate) fn add_debug_bounds(
    mut generics: syn::Generics,
    used_generics: &[Ident],
) -> syn::Generics {
    for param in generics.type_params_mut() {
        if used_generics.iter().any(|g| g == &param.ident) {
            param.bounds.push(parse_quote!(::core::fmt::Debug));
        }
    }
    generics
}

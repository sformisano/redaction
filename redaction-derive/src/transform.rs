//! Shared field transformation logic for struct and enum derivation.
//!
//! This module extracts the common code for generating field transformations,
//! which was previously duplicated between `derive_struct` and `derive_enum`.

use proc_macro2::{Ident, Span, TokenStream};
use quote::quote_spanned;
use syn::Result;

use crate::{
    crate_path, generics::collect_generics_from_type, strategy::Strategy, types::is_scalar_type,
};

/// Accumulated state during field processing.
///
/// This struct groups the mutable vectors that collect generics and output tokens
/// during traversal of struct fields or enum variants.
pub(crate) struct DeriveContext<'a> {
    pub(crate) generics: &'a syn::Generics,
    pub(crate) container_path: &'a TokenStream,
    pub(crate) used_generics: &'a mut Vec<Ident>,
    pub(crate) classified_generics: &'a mut Vec<Ident>,
    pub(crate) debug_redacted_generics: &'a mut Vec<Ident>,
    pub(crate) debug_unredacted_generics: &'a mut Vec<Ident>,
}

/// Generates the transform token stream for a single field.
///
/// This function encapsulates the logic that was previously duplicated in
/// `derive_named_struct`, `derive_unnamed_struct`, `derive_named_variant`,
/// and `derive_unnamed_variant`.
///
/// ## Field Transformation Rules
///
/// | Annotation | Behavior |
/// |------------|----------|
/// | None | Pass through unchanged (identity) |
/// | `#[sensitive]` | Walk containers OR redact scalars to default |
/// | `#[sensitive(Class)]` | Apply classification recursively through wrappers |
pub(crate) fn generate_field_transform(
    ctx: &mut DeriveContext<'_>,
    ty: &syn::Type,
    binding: &Ident,
    span: Span,
    strategy: &Strategy,
) -> Result<TokenStream> {
    let container_path = ctx.container_path;

    match strategy {
        // No annotation: pass through unchanged
        // This allows external types (DateTime, Decimal, etc.) to work without issues
        Strategy::PassThrough => {
            // No trait bounds needed - any type can pass through
            // Still track for Debug impl
            collect_generics_from_type(ty, ctx.generics, ctx.debug_unredacted_generics);
            Ok(quote_spanned! { span =>
                // Field passes through unchanged (no #[sensitive] annotation)
                let #binding = #binding;
            })
        }
        // Bare #[sensitive]: walk containers or redact scalars
        Strategy::Walk => {
            if is_scalar_type(ty) {
                // Scalars redact to their default value
                Ok(quote_spanned! { span =>
                    let #binding = mapper.map_scalar(#binding);
                })
            } else {
                // Non-scalars: walk using SensitiveType
                collect_generics_from_type(ty, ctx.generics, ctx.used_generics);
                collect_generics_from_type(ty, ctx.generics, ctx.debug_redacted_generics);
                collect_generics_from_type(ty, ctx.generics, ctx.debug_unredacted_generics);
                Ok(quote_spanned! { span =>
                    let #binding = #container_path::redact_with(#binding, mapper);
                })
            }
        }
        // #[sensitive(Classification)]: apply classification policy recursively
        // Uses Classifiable trait which handles any nesting depth:
        // String, Option<String>, Vec<String>, Option<Vec<String>>, etc.
        Strategy::Classify(classification) => {
            if is_scalar_type(ty) {
                Err(syn::Error::new(
                    span,
                    "scalar fields cannot use a classification: use bare #[sensitive]. \
                    Scalars redact to their default value (0, false, etc.), \
                    except char which redacts to 'X'.",
                ))
            } else {
                // Use Classifiable for ALL non-scalar types
                // This handles: String, Option<String>, Vec<String>, Option<Vec<String>>, etc.
                collect_generics_from_type(ty, ctx.generics, ctx.classified_generics);
                collect_generics_from_type(ty, ctx.generics, ctx.debug_unredacted_generics);
                let classification = classification.clone();
                let classifiable_path = crate_path("Classifiable");
                Ok(quote_spanned! { span =>
                    let #binding = #classifiable_path::apply_classification::<#classification, _>(#binding, mapper);
                })
            }
        }
    }
}

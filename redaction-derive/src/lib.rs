//! Derive macros for `redaction`.
//!
//! This crate generates the traversal code behind `#[derive(Sensitive)]`. It:
//! - reads `#[sensitive(...)]` field attributes
//! - emits a `SensitiveType` implementation that calls into a mapper
//!
//! It does **not** define classifications or policies. Those live in the main
//! `redaction` crate and are applied at runtime.

// <https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html>
#![warn(
    anonymous_parameters,
    bare_trait_objects,
    elided_lifetimes_in_paths,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unsafe_code,
    unused_extern_crates,
    unused_import_braces
)]
// <https://rust-lang.github.io/rust-clippy/stable>
#![warn(
    clippy::all,
    clippy::cargo,
    clippy::dbg_macro,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::mem_forget,
    clippy::nursery,
    clippy::pedantic,
    clippy::todo,
    clippy::unwrap_used,
    clippy::uninlined_format_args
)]
// Allow some clippy lints
#![allow(
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::if_not_else,
    clippy::module_name_repetitions,
    clippy::multiple_crate_versions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::needless_ifs,
    clippy::use_self,
    clippy::cargo_common_metadata,
    clippy::missing_errors_doc,
    clippy::enum_glob_use,
    clippy::struct_excessive_bools,
    clippy::missing_const_for_fn,
    clippy::redundant_pub_crate,
    clippy::result_large_err,
    clippy::future_not_send,
    clippy::option_if_let_else,
    clippy::from_over_into,
    clippy::manual_inspect
)]
// Allow some lints while testing
#![cfg_attr(test, allow(clippy::non_ascii_literal, clippy::unwrap_used))]

#[allow(unused_extern_crates)]
extern crate proc_macro;

#[cfg(feature = "slog")]
use proc_macro2::Span;
use proc_macro2::{Ident, TokenStream};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::{format_ident, quote};
#[cfg(feature = "slog")]
use syn::parse_quote;
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput, Result};

mod container;
mod derive_enum;
mod derive_struct;
mod generics;
mod strategy;
mod transform;
mod types;
use container::{parse_container_options, ContainerOptions};
use derive_enum::derive_enum;
use derive_struct::derive_struct;
use generics::{add_classified_value_bounds, add_container_bounds, add_debug_bounds};

/// Derives `redaction::SensitiveType` (and related impls) for structs and enums.
///
/// # Container Attributes
///
/// These attributes are placed on the struct/enum itself:
///
/// - `#[sensitive(skip_debug)]` - Opt out of `Debug` impl generation. Use this when you need a
///   custom `Debug` implementation or the type already derives `Debug` elsewhere.
///
/// # Field Attributes
///
/// - **No annotation**: The field passes through unchanged. Use this for fields that don't contain
///   sensitive data, including external types like `chrono::DateTime` or `rust_decimal::Decimal`.
///
/// - `#[sensitive]`: For scalar types (i32, bool, char, etc.), redacts to default values (0, false,
///   'X'). For struct/enum types that derive `Sensitive`, walks into them using `SensitiveType`.
///
/// - `#[sensitive(Classification)]`: Treats the field as a sensitive string-like value and applies
///   the classification's policy. Works for `String`, `Option<String>`, `Vec<String>`, `Box<String>`.
///   The type must implement `SensitiveValue`.
///
/// Unions are rejected at compile time.
///
/// # Additional Generated Impls
///
/// - `Debug`: when *not* building with `cfg(any(test, feature = "testing"))`, sensitive fields are
///   formatted as the string `"[REDACTED]"` rather than their values. Use `#[sensitive(skip_debug)]`
///   on the container to opt out.
/// - `slog::Value` (behind `cfg(feature = "slog")`): implemented by cloning the value and routing
///   it through `redaction::slog::IntoRedactedJson`. **Note:** this impl requires the type to
///   implement `Clone`. The derive first looks for a top-level `slog` crate; if not found, it
///   checks the `REDACTION_SLOG_CRATE` env var for an alternate path (e.g., `my_log::slog`). If
///   neither is available, compilation fails with a clear error.
#[proc_macro_derive(Sensitive, attributes(sensitive))]
pub fn derive_sensitive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.into_compile_error().into(),
    }
}

/// Returns the token stream to reference the redaction crate root.
///
/// Handles crate renaming (e.g., `my_redact = { package = "redaction", ... }`)
/// and internal usage (when derive is used inside the redaction crate itself).
fn crate_root() -> proc_macro2::TokenStream {
    match crate_name("redaction") {
        Ok(FoundCrate::Itself) => quote! { crate },
        Ok(FoundCrate::Name(name)) => {
            let ident = format_ident!("{}", name);
            quote! { ::#ident }
        }
        Err(_) => quote! { ::redaction },
    }
}

/// Returns the token stream to reference the slog crate root.
///
/// Handles crate renaming (e.g., `my_slog = { package = "slog", ... }`).
/// If the top-level `slog` crate is not available, falls back to the
/// `REDACTION_SLOG_CRATE` env var, which should be a path like `my_log::slog`.
#[cfg(feature = "slog")]
fn slog_crate() -> Result<proc_macro2::TokenStream> {
    match crate_name("slog") {
        Ok(FoundCrate::Itself) => Ok(quote! { crate }),
        Ok(FoundCrate::Name(name)) => {
            let ident = format_ident!("{}", name);
            Ok(quote! { ::#ident })
        }
        Err(_) => {
            let env_value = std::env::var("REDACTION_SLOG_CRATE").map_err(|_| {
                syn::Error::new(
                    Span::call_site(),
                    "slog support is enabled, but no top-level `slog` crate was found. \
Set the REDACTION_SLOG_CRATE env var to a path (e.g., `my_log::slog`) or add \
`slog` as a direct dependency.",
                )
            })?;
            let path = syn::parse_str::<syn::Path>(&env_value).map_err(|_| {
                syn::Error::new(
                    Span::call_site(),
                    format!("REDACTION_SLOG_CRATE must be a valid Rust path (got `{env_value}`)"),
                )
            })?;
            Ok(quote! { #path })
        }
    }
}

fn crate_path(item: &str) -> proc_macro2::TokenStream {
    let root = crate_root();
    let item_ident = syn::parse_str::<syn::Path>(item).expect("redaction crate path should parse");
    quote! { #root::#item_ident }
}

struct DeriveOutput {
    redaction_body: TokenStream,
    used_generics: Vec<Ident>,
    classified_generics: Vec<Ident>,
    debug_redacted_body: TokenStream,
    debug_redacted_generics: Vec<Ident>,
    debug_unredacted_body: TokenStream,
    debug_unredacted_generics: Vec<Ident>,
}

#[allow(clippy::too_many_lines)]
fn expand(input: DeriveInput) -> Result<TokenStream> {
    let DeriveInput {
        ident,
        generics,
        data,
        attrs,
        ..
    } = input;

    let ContainerOptions { skip_debug } = parse_container_options(&attrs)?;

    let crate_root = crate_root();

    let derive_output = match &data {
        Data::Struct(data) => {
            let output = derive_struct(&ident, data.clone(), &generics)?;
            DeriveOutput {
                redaction_body: output.redaction_body,
                used_generics: output.used_generics,
                classified_generics: output.classified_generics,
                debug_redacted_body: output.debug_redacted_body,
                debug_redacted_generics: output.debug_redacted_generics,
                debug_unredacted_body: output.debug_unredacted_body,
                debug_unredacted_generics: output.debug_unredacted_generics,
            }
        }
        Data::Enum(data) => {
            let output = derive_enum(&ident, data.clone(), &generics)?;
            DeriveOutput {
                redaction_body: output.redaction_body,
                used_generics: output.used_generics,
                classified_generics: output.classified_generics,
                debug_redacted_body: output.debug_redacted_body,
                debug_redacted_generics: output.debug_redacted_generics,
                debug_unredacted_body: output.debug_unredacted_body,
                debug_unredacted_generics: output.debug_unredacted_generics,
            }
        }
        Data::Union(u) => {
            return Err(syn::Error::new(
                u.union_token.span(),
                "`Sensitive` cannot be derived for unions",
            ));
        }
    };

    let classify_generics = add_container_bounds(generics.clone(), &derive_output.used_generics);
    let classify_generics =
        add_classified_value_bounds(classify_generics, &derive_output.classified_generics);
    let (impl_generics, ty_generics, where_clause) = classify_generics.split_for_impl();
    let debug_redacted_generics =
        add_debug_bounds(generics.clone(), &derive_output.debug_redacted_generics);
    let (debug_redacted_impl_generics, debug_redacted_ty_generics, debug_redacted_where_clause) =
        debug_redacted_generics.split_for_impl();
    let debug_unredacted_generics =
        add_debug_bounds(generics.clone(), &derive_output.debug_unredacted_generics);
    let (
        debug_unredacted_impl_generics,
        debug_unredacted_ty_generics,
        debug_unredacted_where_clause,
    ) = debug_unredacted_generics.split_for_impl();
    let redaction_body = &derive_output.redaction_body;
    let debug_redacted_body = &derive_output.debug_redacted_body;
    let debug_unredacted_body = &derive_output.debug_unredacted_body;
    let debug_impl = if skip_debug {
        quote! {}
    } else {
        quote! {
            #[cfg(any(test, feature = "testing"))]
            impl #debug_unredacted_impl_generics ::core::fmt::Debug for #ident #debug_unredacted_ty_generics #debug_unredacted_where_clause {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    #debug_unredacted_body
                }
            }

            #[cfg(not(any(test, feature = "testing")))]
            #[allow(unused_variables)]
            impl #debug_redacted_impl_generics ::core::fmt::Debug for #ident #debug_redacted_ty_generics #debug_redacted_where_clause {
                fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                    #debug_redacted_body
                }
            }
        }
    };

    // Only generate slog impl when the slog feature is enabled on redaction-derive.
    // If slog is not available, emit a clear error with instructions.
    #[cfg(feature = "slog")]
    let slog_impl = {
        let slog_crate = slog_crate()?;
        let mut slog_generics = generics;
        let slog_where_clause = slog_generics.make_where_clause();
        let self_ty: syn::Type = parse_quote!(#ident #ty_generics);
        slog_where_clause
            .predicates
            .push(parse_quote!(#self_ty: ::core::clone::Clone));
        // IntoRedactedJson requires Self: Serialize, so we add this bound to enable
        // generic types to work with slog when their type parameters implement Serialize.
        slog_where_clause
            .predicates
            .push(parse_quote!(#self_ty: ::serde::Serialize));
        slog_where_clause
            .predicates
            .push(parse_quote!(#self_ty: #crate_root::slog::IntoRedactedJson));
        let (slog_impl_generics, slog_ty_generics, slog_where_clause) =
            slog_generics.split_for_impl();
        quote! {
            impl #slog_impl_generics #slog_crate::Value for #ident #slog_ty_generics #slog_where_clause {
                fn serialize(
                    &self,
                    _record: &#slog_crate::Record<'_>,
                    key: #slog_crate::Key,
                    serializer: &mut dyn #slog_crate::Serializer,
                ) -> #slog_crate::Result {
                    let redacted = #crate_root::slog::IntoRedactedJson::into_redacted_json(self.clone());
                    #slog_crate::Value::serialize(&redacted, _record, key, serializer)
                }
            }
        }
    };

    #[cfg(not(feature = "slog"))]
    let slog_impl = quote! {};

    let trait_impl = quote! {
        impl #impl_generics #crate_root::SensitiveType for #ident #ty_generics #where_clause {
            fn redact_with<M: #crate_root::RedactionMapper>(self, mapper: &M) -> Self {
                use #crate_root::SensitiveType as _;
                #redaction_body
            }
        }

        #debug_impl

        #slog_impl

        // `slog` already provides `impl<V: Value> Value for &V`, so a reference
        // impl here would conflict with the blanket impl.
    };
    Ok(trait_impl)
}

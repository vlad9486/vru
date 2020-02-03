// The `quote!` macro requires deep recursion.
#![recursion_limit = "512"]

#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;

extern crate proc_macro;

mod pattern;
use self::pattern::PatternDescriptor;

use proc_macro::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Type, Result};

struct PatternInput {
    algorithm: Type,
    descriptor: PatternDescriptor,
}

impl Parse for PatternInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let algorithm = input.parse()?;
        let _ = input.parse::<Token![,]>()?;
        let descriptor = input.parse()?;
        Ok(PatternInput {
            algorithm,
            descriptor,
        })
    }
}

/// Takes `NoiseAlgorithm` type, text description of the pattern and optionally payload type.
/// Generates `Pattern` type.
#[proc_macro]
#[allow(non_snake_case)]
pub fn Pattern(input: TokenStream) -> TokenStream {
    use syn::parse_macro_input;

    let PatternInput {
        algorithm,
        descriptor,
    } = parse_macro_input!(input as PatternInput);
    descriptor.generate(&algorithm, None).into()
}

struct HandshakeInput {
    algorithm: Type,
    descriptors: Punctuated<PatternDescriptor, Token![,]>,
}

impl Parse for HandshakeInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let algorithm = input.parse()?;
        let _ = input.parse::<Token![,]>()?;
        let descriptors = input.parse_terminated(PatternDescriptor::parse)?;
        Ok(HandshakeInput {
            algorithm,
            descriptors,
        })
    }
}

/// Takes `NoiseAlgorithm` type, series of payload descriptions and payload types.
/// Generates `History` type.
#[proc_macro]
#[allow(non_snake_case)]
pub fn Handshake(input: TokenStream) -> TokenStream {
    use syn::parse_macro_input;

    let HandshakeInput {
        algorithm,
        descriptors,
    } = parse_macro_input!(input as HandshakeInput);
    PatternDescriptor::generate_handshake(descriptors.into_iter(), &algorithm).into()
}

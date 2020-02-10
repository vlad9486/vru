use std::iter::Iterator;
use quote::__rt::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::{Type, LitStr, Error};

#[derive(Debug)]
struct PartyState {
    has_ephemeral: bool,
    has_static: bool,
    randomized_cipher: bool,
}

impl PartyState {
    fn new() -> Self {
        PartyState {
            has_ephemeral: false,
            has_static: false,
            randomized_cipher: false,
        }
    }
}

#[derive(Debug)]
pub struct ValidityContext {
    initiator: PartyState,
    responder: PartyState,
}

impl ValidityContext {
    fn new() -> Self {
        ValidityContext {
            initiator: PartyState::new(),
            responder: PartyState::new(),
        }
    }
}

pub struct PatternDescriptor {
    code: LitStr,
    payload: Option<Type>,
}

impl Parse for PatternDescriptor {
    fn parse(input: ParseStream) -> Result<Self, Error> {
        use syn::Ident;

        let code = input.parse()?;
        let lookahead = input.lookahead1();
        // will not work for type not start by `Ident`, e.g. tuple or array
        let payload = if lookahead.peek(Ident) {
            Some(input.parse()?)
        } else {
            None
        };
        Ok(PatternDescriptor { code, payload })
    }
}

impl PatternDescriptor {
    pub fn generate(self, algorithm: &Type, context: Option<&mut ValidityContext>) -> TokenStream {
        fn append(
            inner: TokenStream,
            algorithm: &Type,
            incoming: bool,
            token: &str,
            context: Option<&mut ValidityContext>,
        ) -> Result<TokenStream, &'static str> {
            let e = context.and_then(|c| {
                let modifier = |state: &mut PartyState| {
                    if let "s" | "S" = token {
                        if state.has_static {
                            Some("the party already has the static key")
                        } else {
                            state.has_static = true;
                            None
                        }
                    } else if let "e" = token {
                        if state.has_ephemeral {
                            Some("the party already has the ephemeral key")
                        } else {
                            state.has_ephemeral = true;
                            None
                        }
                    } else {
                        None
                    }
                };
                if incoming {
                    modifier(&mut c.initiator)
                } else {
                    modifier(&mut c.responder)
                }
            });
            if let Some(error) = e {
                return Err(error);
            }
            let appender = match (token, incoming) {
                ("s", false) => quote![vru_noise::Point<#algorithm, vru_noise::typenum::U1, vru_noise::typenum::B0>],
                ("s", true) => quote![vru_noise::Point<#algorithm, vru_noise::typenum::U3, vru_noise::typenum::B0>],

                ("e", false) => quote![vru_noise::Point<#algorithm, vru_noise::typenum::U0, vru_noise::typenum::B1>],
                ("e", true) => quote![vru_noise::Point<#algorithm, vru_noise::typenum::U2, vru_noise::typenum::B1>],

                ("S", false) => quote![vru_noise::EncryptedPoint<#algorithm, vru_noise::typenum::U1>],
                ("S", true) => quote![vru_noise::EncryptedPoint<#algorithm, vru_noise::typenum::U3>],

                ("ss", _) => quote![vru_noise::MixDh<#algorithm, vru_noise::typenum::U1, vru_noise::typenum::U3>],
                ("ee", _) => quote![vru_noise::MixDh<#algorithm, vru_noise::typenum::U0, vru_noise::typenum::U2>],

                ("es", _) => quote![vru_noise::MixDh<#algorithm, vru_noise::typenum::U0, vru_noise::typenum::U3>],
                ("se", _) => quote![vru_noise::MixDh<#algorithm, vru_noise::typenum::U2, vru_noise::typenum::U1>],

                ("psk", _) => quote![vru_noise::MixPsk<#algorithm>],

                (token, _) => panic!("bad token: {}", token),
            };
            Ok(quote! {
                (#inner, #appender)
            })
        }

        let mut context = context;

        let base = quote! {
            vru_noise::BasePattern<#algorithm>
        };
        let original_code_value = self.code.value();
        let (incoming, code_value) = if original_code_value.starts_with("->") {
            (false, original_code_value.trim_start_matches("->"))
        } else if original_code_value.starts_with("<-") {
            (true, original_code_value.trim_start_matches("<-"))
        } else {
            panic!("bad pattern: {}", original_code_value)
        };
        let pattern_type = code_value.split(",").fold(base, |temp, code| {
            let code = code.trim();
            match context.take() {
                None => append(temp, algorithm, incoming, code, None),
                Some(inner) => {
                    let stream = append(temp, algorithm, incoming, code, Some(inner));
                    context = Some(inner);
                    stream
                },
            }
            .unwrap_or_else(|description| {
                let position = code.as_ptr() as usize - original_code_value.as_ptr() as usize;
                panic!(
                    "\"{}\" in pattern: \"{}\", at: ...{}",
                    description,
                    original_code_value,
                    &original_code_value[position..]
                )
            })
        });
        if let Some(payload) = self.payload {
            quote! {
                (#pattern_type, vru_noise::Payload<#algorithm, #payload>)
            }
        } else {
            pattern_type
        }
    }

    pub fn generate_handshake<I>(iterator: I, algorithm: &Type) -> TokenStream
    where
        I: Iterator<Item = Self>,
    {
        let mut context = ValidityContext::new();
        let base = quote! {
            vru_noise::BaseHistory<#algorithm>
        };
        iterator.fold(base, |temp, descriptor| {
            let appender = descriptor.generate(algorithm, Some(&mut context));
            quote! {
                (#temp, #appender)
            }
        })
    }
}

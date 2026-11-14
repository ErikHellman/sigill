//! Rendering: MiniJinja templates (MJML compiled with `mrml`), multipart MIME built with
//! `mail-builder`, and DKIM signatures (RSA-SHA256 and Ed25519) from `mail-auth`.

pub mod dkim;
pub mod mime;
pub mod template;

pub use dkim::{DkimError, DkimKeys, Signers};
pub use mime::{MimeError, MimeParts, build_mime};
pub use template::{Rendered, TemplateError, TemplateSource, compile_mjml, render, validate};

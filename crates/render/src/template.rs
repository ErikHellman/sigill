//! Templates: subject, HTML and text, each a MiniJinja template. HTML may be uploaded as
//! MJML and is compiled to HTML once, at upload time.

use minijinja::{Environment, UndefinedBehavior};

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("MJML error: {0}")]
    Mjml(String),
    #[error("template error in {part}: {message}")]
    Template { part: &'static str, message: String },
    #[error("subject renders to an empty line")]
    EmptySubject,
}

/// The three template parts of one version.
#[derive(Debug, Clone)]
pub struct TemplateSource<'a> {
    pub subject: &'a str,
    pub html: &'a str,
    pub text: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Rendered {
    pub subject: String,
    pub html: String,
    pub text: String,
}

/// Compile MJML to HTML. MiniJinja expressions in text and attributes pass through.
pub fn compile_mjml(src: &str) -> Result<String, TemplateError> {
    let parsed = mrml::parse(src).map_err(|e| TemplateError::Mjml(e.to_string()))?;
    let opts = mrml::prelude::render::RenderOptions { disable_comments: true, ..Default::default() };
    parsed.element.render(&opts).map_err(|e| TemplateError::Mjml(e.to_string()))
}

/// Work one render may do, in MiniJinja's instruction units. Ordinary templates use a few
/// thousand; this stops a runaway loop from holding a thread.
pub const RENDER_FUEL: u64 = 2_000_000;

fn env() -> Environment<'static> {
    let mut env = Environment::new();
    env.set_fuel(Some(RENDER_FUEL));
    // A missing variable is an error, not an empty string in someone's inbox.
    env.set_undefined_behavior(UndefinedBehavior::Strict);
    env
}

fn err(part: &'static str, e: minijinja::Error) -> TemplateError {
    let mut message = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        message.push_str(": ");
        message.push_str(&s.to_string());
        source = s.source();
    }
    TemplateError::Template { part, message }
}

/// Check that all three parts parse.
pub fn validate(t: &TemplateSource<'_>) -> Result<(), TemplateError> {
    let env = env();
    env.template_from_named_str("subject.txt", t.subject).map_err(|e| err("subject", e))?;
    env.template_from_named_str("body.html", t.html).map_err(|e| err("html", e))?;
    env.template_from_named_str("body.txt", t.text).map_err(|e| err("text", e))?;
    Ok(())
}

/// Render all three parts. HTML output is auto-escaped; subject and text are not.
pub fn render(t: &TemplateSource<'_>, vars: &serde_json::Value) -> Result<Rendered, TemplateError> {
    let env = env();
    let ctx = minijinja::Value::from(minijinja::value::Serde(vars));
    let subject =
        env.render_named_str("subject.txt", t.subject, ctx.clone()).map_err(|e| err("subject", e))?;
    // Subjects are one line: fold any newlines a template produced.
    let subject = subject.split_whitespace().collect::<Vec<_>>().join(" ");
    if subject.is_empty() {
        return Err(TemplateError::EmptySubject);
    }
    let html = env.render_named_str("body.html", t.html, ctx.clone()).map_err(|e| err("html", e))?;
    let text = env.render_named_str("body.txt", t.text, ctx).map_err(|e| err("text", e))?;
    Ok(Rendered { subject, html, text })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MJML: &str = r#"<mjml><mj-body><mj-section><mj-column>
<mj-text>Hello {{ name }}!</mj-text>
<mj-button href="{{ url }}">Confirm</mj-button>
</mj-column></mj-section></mj-body></mjml>"#;

    #[test]
    fn renders_and_escapes() {
        let html = compile_mjml(MJML).unwrap();
        assert!(html.contains("{{ name }}"));
        let t = TemplateSource {
            subject: "Welcome,\n{{ name }}",
            html: &html,
            text: "Hi {{ name }}, go to {{ url }}",
        };
        validate(&t).unwrap();
        let r = render(&t, &json!({"name": "<Ann>", "url": "https://x.test/c?a=1&b=2"})).unwrap();
        assert_eq!(r.subject, "Welcome, <Ann>");
        assert!(r.html.contains("Hello &lt;Ann&gt;!"));
        assert!(r.html.contains("https:&#x2f;&#x2f;x.test") || r.html.contains("https://x.test"));
        assert_eq!(r.text, "Hi <Ann>, go to https://x.test/c?a=1&b=2");
        insta::assert_snapshot!(r.text);
    }

    #[test]
    fn errors() {
        let t = TemplateSource { subject: "{{ missing }}", html: "x", text: "x" };
        assert!(matches!(render(&t, &json!({})), Err(TemplateError::Template { part: "subject", .. })));
        let t = TemplateSource { subject: "ok", html: "{% if %}", text: "x" };
        assert!(matches!(validate(&t), Err(TemplateError::Template { part: "html", .. })));
        let t = TemplateSource { subject: "{{ '' }}", html: "x", text: "x" };
        assert!(matches!(render(&t, &json!({})), Err(TemplateError::EmptySubject)));
        assert!(compile_mjml("<mjml><mj-body>").is_err());
        // A runaway loop runs out of fuel instead of holding the thread.
        let looping = "{% for a in range(100000) %}{% for b in range(100000) %}x{% endfor %}{% endfor %}";
        let t = TemplateSource { subject: "ok", html: "x", text: looping };
        assert!(matches!(render(&t, &json!({})), Err(TemplateError::Template { part: "text", .. })));
    }
}

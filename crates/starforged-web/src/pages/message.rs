//! A page with a title, one paragraph, and an optional link: confirmations and dead ends.

use askama::Template;
use askama_web::WebTemplate;

use crate::views::NavUser;

#[derive(Template, WebTemplate)]
#[template(path = "message.html")]
pub struct MessagePage {
    nav_user: Option<NavUser>,
    title: &'static str,
    message: String,
    link_href: &'static str,
    link_text: &'static str,
}

impl MessagePage {
    pub fn new(
        nav_user: Option<NavUser>,
        title: &'static str,
        message: impl Into<String>,
    ) -> MessagePage {
        MessagePage {
            nav_user,
            title,
            message: message.into(),
            link_href: "",
            link_text: "",
        }
    }

    pub fn with_link(mut self, href: &'static str, text: &'static str) -> MessagePage {
        self.link_href = href;
        self.link_text = text;
        self
    }
}

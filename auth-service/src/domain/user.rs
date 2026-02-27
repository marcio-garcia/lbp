use crate::domain::{Email, HashedPassword};

#[derive(Debug, PartialEq)]
pub struct User {
    pub email: Email,
    pub password: HashedPassword,
    pub requires_2fa: bool,
}

impl User {
    pub fn new(email: Email, password: HashedPassword, requires_2fa: bool) -> Self {
        User { email, password, requires_2fa }
    }
}

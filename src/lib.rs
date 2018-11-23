use md5::compute;
use std::{error::Error, str};

const FORMATS: &[(&str, &str); 6] = &[
    ("md5", "$1$"),
    ("blf", "$2"),
    ("nth", "$3$"),
    ("sha256", "$5$"),
    ("sha512", "$6$"),
    ("des", ""),
];

pub fn crypt<B: AsRef<[u8]>>(password: B, salt: B) -> Result<[u8; 16], Box<Error>> {
    if let Some(magic) = format_from_magic(&salt) {
        delegate(magic.0, password, salt)
    } else {
        Err("can't find algorithm".into())
    }
}

fn format_from_magic<B: AsRef<[u8]>>(salt: B) -> Option<&'static (&'static str, &'static str)> {
    FORMATS
        .iter()
        .find(|format| match str::from_utf8(salt.as_ref()) {
            Ok(s) => s.contains(format.1),
            _ => false,
        })
}

fn delegate<B: AsRef<[u8]>>(algorithm: &str, password: B, salt: B) -> Result<[u8; 16], Box<Error>> {
    match algorithm {
        "md5" => Ok(compute(password).into()),
        _ => Err("can't find algorithm".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_from_magic_returns_md5() {
        let x = format_from_magic("$1$");
        assert_eq!("md5", x.unwrap().0);
    }

    #[test]
    fn md5_works() {
        let digest = crypt(&"foo", &"$1$bar");
        let expected: [u8; 16] = compute("foo").into();
        assert_eq!(digest.unwrap(), expected);
    }

}

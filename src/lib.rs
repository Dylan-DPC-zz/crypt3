#![feature(try_from)]

use md5::{compute, Digest};
use std::{convert::TryInto, error::Error, fmt::Debug, str};
use ring::digest::{digest, SHA256, SHA512, Digest as RingDigest};

const FORMATS: &[(&str, &str); 6] = &[
    ("md5", "$1$"),
    ("blf", "$2"),
    ("nth", "$3$"),
    ("sha256", "$5$"),
    ("sha512", "$6$"),
    ("des", ""),
];

pub fn crypt(password: &mut [u8], salt: &mut [u8]) -> Result<Encrypted, Box<Error>> {
    if let Some(magic) = format_from_magic(salt) {
        delegate(magic.0, password, salt)
    } else {
        Err("cant find algorithm".into())
    }
}

fn format_from_magic(salt: &mut [u8]) -> Option<&'static (&'static str, &'static str)> {
    FORMATS
        .iter()
        .find(|format| match str::from_utf8(salt.as_ref()) {
            Ok(s) => s.contains(format.1),
            _ => false,
        })
}

fn delegate(
    algorithm: &str,
    password: &mut [u8],
    salt: &mut [u8],
) -> Result<Encrypted, Box<Error>> {
    match algorithm {
        "md5" => Ok(Encrypted::Md5(compute(password))),
        "sha256" => Ok(Encrypted::Sha256(digest(&SHA256, password))),
        "sha512" => Ok(Encrypted::Sha512(digest(&SHA512, password))),
        _ => unreachable!()
        }
    }


#[derive(Clone, Debug)]
pub enum Encrypted {
    Md5(Digest),
    Sha256(RingDigest),
    Sha512(RingDigest),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_from_magic_returns_md5() {
        unsafe {
            let x = format_from_magic(String::from("$1$").as_bytes_mut());
            assert_eq!("md5", x.unwrap().0);
        }
    }

    #[test]
    fn md5_works() {
        unsafe {
            let mut password = String::from("abcdefghijklmnop");
            let mut salt = String::from("$1$");

            let digest = crypt(password.as_bytes_mut(), salt.as_bytes_mut());
            let expected = compute("abcdefghijklmnop");

            let value = match digest.unwrap() {
                Encrypted::Md5(x) => x,
                _ => unreachable!(),
            };

            assert_eq!(value, expected);
        }
    }

    #[test]
    fn sha256_works() {
        use ring::digest;
        unsafe {
            let mut password = String::from("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f
        989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76fc");

            let mut salt = String::from("$5$");

            let digest = crypt(password.as_bytes_mut(), salt.as_bytes_mut());

            let expected = digest::digest(&digest::SHA256, &password.as_bytes());

            let value = match digest.unwrap() {
                Encrypted::Sha256(x) => x,
                _ => unreachable!(),
            };

            assert_eq!(value.as_ref(), expected.as_ref());
        }

    }  #[test]
    fn sha512_works() {
        use ring::digest;
        unsafe {
            let mut password = String::from("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f
        989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76fc");

            let mut salt = String::from("$6$");

            let digest = crypt(password.as_bytes_mut(), salt.as_bytes_mut());

            let expected = digest::digest(&digest::SHA512, &password.as_bytes());

            let value = match digest.unwrap() {
                Encrypted::Sha512(x) => x,
                _ => unreachable!(),
            };

            assert_eq!(value.as_ref(), expected.as_ref());
        }

    }

}

//! This crate is a clone of the linux [crypt](http://man7.org/linux/man-pages/man3/crypt.3.html) command.
//! It is a wrapper for the crypto algorithms used in crypt - Md5, blowfish, SHA256 and SHA512.
//! The algorithm is chosen based on the first 3 characters of the secret. If it starts with `$x$` where x is one of
//! 1, 2, 3, 5 or 6.
//!
//! Till this release (0.1), only MD5($1$), SHA256 ($5$) and SHA512 ($6$) are supported.
//!
//! # SECURITY ALERT:
//! The package is provided for the purposes of interoperability with protocols and systems that mandate the use of MD5.
//! However, MD5 should be considered cryptographically broken and unsuitable for further use.
//! Collision attacks against MD5 are both practical and trivial, and theoretical attacks against MD5 have been found.
//! RFC6151 advises no new protocols to be designed with any MD5-based constructions, including HMAC-MD5.
//!
//!
//! # INSTALLATION:
//! To add crypt to your package, add this to your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! crypt3 = "0.1"
//! ```
//!
//! # EXAMPLES:
//!
//! ```rust
//! use crypt3::crypt;
//!
//! let digest = crypt(b"abcdefghijklmnop", b"$1$");
//! assert_eq!(digest.unwrap(), [36, 49, 36, 36, 29, 100, 220, 226, 57, 196, 67, 123, 119, 54, 4, 29, 176, 137, 225, 185]);
//! ```
//!

use md5::compute;
use md5::Digest;
use ring::digest::{digest, Digest as RingDigest, SHA256, SHA512};
use std::{error::Error, str};

const FORMATS: &[(&str, &str); 6] = &[
    ("md5", "$1$"),
    ("blf", "$2"),
    ("nth", "$3$"),
    ("sha256", "$5$"),
    ("sha512", "$6$"),
    ("des", ""),
];

/// This function is the entry point of the crate. It accepts 2 byte slices - a to-be-hashed
/// password and a salt. The first 3 bytes of the salt decide which algorithm is picked and
/// should be in the $id$ form (e.g. $1$ for MD5).

pub fn crypt<'a>(password: &'a [u8], salt: &'a [u8]) -> Result<Vec<u8>, Box<Error>> {
    if let Some(magic) = format_from_magic(salt) {
        delegate(*magic, password, salt)
    } else {
        Err("cant find algorithm".into())
    }
}

fn format_from_magic(salt: &[u8]) -> Option<&'static (&'static str, &'static str)> {
    FORMATS
        .iter()
        .find(|format| salt.starts_with(&format.1.as_bytes()))
}

fn delegate<'a>(
    algorithm: (&'a str, &'a str),
    password: &'a [u8],
    salt: &'a [u8],
) -> Result<Vec<u8>, Box<Error>> {
    let digest: Result<Encrypted, Box<Error>> = match algorithm.0 {
        "md5" => Ok(Encrypted::Md5(compute(password))),
        "sha256" => Ok(Encrypted::Sha256(digest(&SHA256, password))),
        "sha512" => Ok(Encrypted::Sha512(digest(&SHA512, password))),
        _ => Err("algorithm is not supported".into()),
    };

    Ok(digest?.fill(salt))
}

#[derive(Clone, Debug)]
enum Encrypted {
    Md5(Digest),
    Sha256(RingDigest),
    Sha512(RingDigest),
}

impl Encrypted {
    pub fn fill<'a>(&'a self, salt: &'a [u8]) -> Vec<u8> {
        let mut output = salt.to_vec();
        output.push(b'$');
        let digest = match *self {
            Encrypted::Md5(digest) => digest.to_vec(),
            Encrypted::Sha256(digest) | Encrypted::Sha512(digest) => digest.as_ref().to_vec(),
        };
        output.extend(digest.iter());

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn format_from_magic_returns_md5() {
        let x = format_from_magic(String::from("$1$").as_bytes());
        assert_eq!("md5", x.unwrap().0);
    }

    #[test]
    fn md5_works() {
        let password = b"abcdefghijklmnop";
        let salt = b"$1$";
        let digest = crypt(password, salt).unwrap();
        let md5 = compute("abcdefghijklmnop");
        let mut expected = salt.to_vec();
        expected.push(b'$');
        expected.extend(md5.to_vec().iter());
        println!("{:?}", &expected);
        assert_eq!(digest, expected);
    }

    #[test]
    fn sha256_works() {
        use ring::digest;

        let password = b"309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f
        989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76fc";
        let salt = b"$5$";
        let digest = crypt(password, salt).unwrap();
        let sha256 = digest::digest(&digest::SHA256, &password[..]);
        let mut expected = salt.to_vec();
        expected.push(b'$');
        expected.extend_from_slice(sha256.as_ref());
        assert_eq!(digest, expected);
    }

    #[test]
    fn sha512_works() {
        use ring::digest;
        let password = b"309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f
        989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76fc";
        let salt = b"$6$";
        let digest = crypt(password, salt).unwrap();
        let sha512 = digest::digest(&digest::SHA512, &password[..]);
        let mut expected = salt.to_vec();
        expected.push(b'$');
        expected.extend_from_slice(sha512.as_ref());
        assert_eq!(digest, expected);
    }
}

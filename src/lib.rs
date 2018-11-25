#![feature(try_from)]

use md5::{compute, Digest};
use blowfish::{Blowfish, BlockCipher, block_cipher_trait::generic_array::{GenericArray, typenum::U8}};
use std::{error::Error, str, fmt::Debug, convert::TryInto};

const FORMATS: &[(&str, &str); 6] = &[
    ("md5", "$1$"),
    ("blf", "$2"),
    ("nth", "$3$"),
    ("sha256", "$5$"),
    ("sha512", "$6$"),
    ("des", ""),
];

pub fn crypt(password: &mut [u8], salt: &mut[u8]) -> Result<Encrypted, Box<Error>> {
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

fn delegate(algorithm: &str, password: &mut [u8], salt: &mut [u8]) -> Result<Encrypted, Box<Error>> {
    match algorithm {
        "md5" => {
            Ok(Encrypted::Md5(compute(password)))
        },
//        "blf" => {
//            let blowfish = Blowfish::new(GenericArray::<u8, U8 >::from_mut_slice(salt.as_mut()));
//            blowfish.encrypt_block(GenericArray::<u8, U8>::from_mut_slice(password.as_mut()));
//
//            Ok(Box::new(blowfish))
//        },

        _ => Err("can't find algorithm".into()),
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Encrypted {
    Md5(Digest),
    Blowfish(GenericArray<u8, U8>)
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

            assert_eq!(digest.unwrap(), Encrypted::Md5(expected));
        }
    }

}

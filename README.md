# Crypt3
 This crate is a clone of the linux [crypt](http://man7.org/linux/man-pages/man3/crypt.3.html) command.
 It is a wrapper for the crypto algorithms used in crypt - Md5, blowfish, SHA256 and SHA512.
 The algorithm is chosen based on the first 3 characters of the secret. If it starts with `$x$` where x is one of
 1, 2, 3, 5 or 6.

 Till this release (0.1), only MD5($1$), SHA256 ($5$) and SHA512 ($6$) are supported.

 # SECURITY ALERT:
 The package is provided for the purposes of interoperability with protocols and systems that mandate the use of MD5.
 However, MD5 should be considered cryptographically broken and unsuitable for further use.
 Collision attacks against MD5 are both practical and trivial, and theoretical attacks against MD5 have been found.
 RFC6151 advises no new protocols to be designed with any MD5-based constructions, including HMAC-MD5.
 
 # INSTALLATION:
 To add crypt to your package, add this to your Cargo.toml:

 ```toml
 [dependencies]
 crypt3 = "0.1"
 ```

 # EXAMPLES:

 ```rust
 use crypt3::crypt;

pub fn foo() {
    let digest = crypt(b"abcdefghijklmnop", b"$1$");
}
 ```


# License

Licensed under either of

- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

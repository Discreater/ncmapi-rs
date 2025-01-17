mod key;
#[cfg(feature = "use-openssl")]
mod use_openssl;
#[cfg(feature = "use-rustls")]
mod use_rustls;

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
#[cfg(feature = "default-rustls")]
pub(crate) use use_rustls::*;

#[cfg(feature = "default-openssl")]
pub(crate) use use_openssl::*;

use rand::RngCore;
use serde::Serialize;

use key::{BASE62, EAPI_KEY, IV, LINUX_API_KEY, PRESET_KEY, PUBLIC_KEY};

#[derive(Serialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum Crypto {
    Weapi,
    Eapi,
    #[allow(unused)]
    Linuxapi,
}

pub struct WeapiForm {
    params: String,
    enc_sec_key: String,
}

pub struct EapiForm {
    params: String,
}
pub struct LinuxapiForm {
    eparams: String,
}

impl WeapiForm {
    pub fn into_vec(self) -> Vec<(String, String)> {
        vec![
            ("params".to_owned(), self.params),
            ("encSecKey".to_owned(), self.enc_sec_key),
        ]
    }
}

impl EapiForm {
    pub fn into_vec(self) -> Vec<(String, String)> {
        vec![("params".to_owned(), self.params)]
    }
}

impl LinuxapiForm {
    pub fn into_vec(self) -> Vec<(String, String)> {
        vec![("eparams".to_owned(), self.eparams)]
    }
}

pub fn weapi(text: &[u8]) -> WeapiForm {
    let mut rng = rand::thread_rng();
    let mut rand_buf = [0u8; 16];
    rng.fill_bytes(&mut rand_buf);

    let sk = rand_buf
        .iter()
        .map(|i| BASE62.as_bytes()[(i % 62) as usize])
        .collect::<Vec<u8>>();

    let params = {
        let p = BASE64_STANDARD.encode(aes_128_cbc(
            text,
            PRESET_KEY.as_bytes(),
            IV.as_bytes(),
        ));
        BASE64_STANDARD.encode(aes_128_cbc(p.as_bytes(), &sk, IV.as_bytes()))
    };

    let enc_sec_key = {
        let reversed_sk = sk.iter().rev().copied().collect::<Vec<u8>>();
        hex::encode(rsa(&reversed_sk, PUBLIC_KEY))
    };

    WeapiForm {
        params,
        enc_sec_key,
    }
}

pub fn eapi(url: &[u8], data: &[u8]) -> EapiForm {
    let msg = format!(
        "nobody{}use{}md5forencrypt",
        String::from_utf8_lossy(url),
        String::from_utf8_lossy(data)
    );
    let digest = md5_hex(msg.as_bytes());

    let text = {
        let d = "-36cd479b6b5-";
        [url, d.as_bytes(), data, d.as_bytes(), digest.as_bytes()].concat()
    };

    let params = {
        let p = aes_128_ecb(&text, EAPI_KEY.as_bytes());
        hex::encode_upper(p)
    };

    EapiForm { params }
}

pub fn linuxapi(text: &[u8]) -> LinuxapiForm {
    let ct = aes_128_ecb(text, LINUX_API_KEY.as_bytes());
    let eparams = hex::encode_upper(ct);

    LinuxapiForm { eparams }
}

#[cfg(test)]
mod tests {
    use super::key::EAPI_KEY;
    use super::{aes_128_ecb, weapi};
    use crate::crypto::{eapi, eapi_decrypt, linuxapi};

    #[test]
    fn test_weapi() {
        weapi(r#"{"username": "alex"}"#.as_bytes());
    }

    #[test]
    fn test_eapi() {
        let ct = eapi("/url".as_bytes(), "plain text".as_bytes());
        assert!(ct.params.ends_with("C3F3"));
    }

    #[test]
    fn test_eapi_decrypt() {
        let pt = "plain text";
        let ct = aes_128_ecb(pt.as_bytes(), EAPI_KEY.as_bytes());
        assert_eq!(pt.as_bytes(), &eapi_decrypt(&ct).unwrap())
    }

    #[test]
    fn test_linuxapi() {
        let ct = linuxapi(r#""plain text""#.as_bytes());
        assert!(ct.eparams.ends_with("2250"));
    }
}

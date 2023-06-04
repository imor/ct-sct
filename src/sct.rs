use std::{fmt::Display, time::Duration};

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{GeneralizedTime, OctetString, UtcTime};
use x509_cert::{ext::AsExtension, impl_newtype, time::Time};

// Remove this constant when the upstream PR is merged:
// https://github.com/RustCrypto/formats/pull/1094
pub const CT_PRECERT_SCTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

pub struct SctList(pub OctetString);

impl AssociatedOid for SctList {
    const OID: const_oid::ObjectIdentifier = CT_PRECERT_SCTS;
}

impl_newtype!(SctList, OctetString);

impl AsExtension for SctList {
    fn critical(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum Error {
    DecodeTlsSctListError,
    DecodeTlsSctError,
    DecodeVersionError,
    DecodeIntError,
    DecodeLogIdError,
    DecodeTimestampError,
    DecodeExtensionsError,
    DecodeDigitallySignedError,
    DecodeHashAlgoError,
    DecodeSignAlgoError,
}

fn decode_u8_be(bytes: &[u8]) -> Result<(u8, &[u8]), Error> {
    if bytes.is_empty() {
        return Err(Error::DecodeIntError);
    }
    let result = u8::from_be_bytes(bytes[..1].try_into().unwrap());

    Ok((result, &bytes[1..]))
}

fn decode_u16_be(bytes: &[u8]) -> Result<(u16, &[u8]), Error> {
    if bytes.len() < 2 {
        return Err(Error::DecodeIntError);
    }
    let result = u16::from_be_bytes(bytes[..2].try_into().unwrap());

    Ok((result, &bytes[2..]))
}

fn decode_u64_be(bytes: &[u8]) -> Result<(u64, &[u8]), Error> {
    if bytes.len() < 8 {
        return Err(Error::DecodeIntError);
    }
    let result = u64::from_be_bytes(bytes[..8].try_into().unwrap());

    Ok((result, &bytes[8..]))
}

pub struct TlsSctList {
    pub scts: Vec<TlsSct>,
}

impl TlsSctList {
    pub fn from_sct_list(sct_list: &SctList) -> Result<Self, Error> {
        let bytes = sct_list.0.as_bytes();
        TlsSctList::decode(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let (len, bytes) = decode_u16_be(bytes)?;
        let len = len as usize;
        if len != bytes.len() {
            return Err(Error::DecodeTlsSctListError);
        }
        let mut scts = Vec::new();
        let mut bytes = bytes;
        while !bytes.is_empty() {
            let (sct, rest) = TlsSct::decode(bytes)?;
            bytes = rest;
            scts.push(sct);
        }
        Ok(Self { scts })
    }
}

pub struct TlsSct {
    pub version: Version,
    pub log_id: [u8; 32],
    pub timestamp: Time,
    pub extensions: Vec<u8>,
    pub sign: DigitallySigned,
}

impl TlsSct {
    fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let (len, bytes) = decode_u16_be(bytes)?;
        let len = len as usize;
        if len > bytes.len() {
            return Err(Error::DecodeTlsSctError);
        }
        let (version, bytes) = Version::decode(bytes)?;
        let (log_id, bytes) = Self::decode_log_id(bytes)?;
        let (timestamp, bytes) = Self::decode_timestamp(bytes)?;
        let (extensions, bytes) = Self::decode_extensions(bytes)?;
        let (sign, bytes) = DigitallySigned::decode(bytes)?;

        Ok((
            Self {
                version,
                log_id,
                timestamp,
                extensions,
                sign,
            },
            bytes,
        ))
    }

    fn decode_log_id(bytes: &[u8]) -> Result<([u8; 32], &[u8]), Error> {
        if bytes.len() < 32 {
            return Err(Error::DecodeLogIdError);
        }
        let result = bytes[..32].try_into().unwrap();

        Ok((result, &bytes[32..]))
    }

    fn decode_timestamp(bytes: &[u8]) -> Result<(Time, &[u8]), Error> {
        let (timestamp, bytes) = decode_u64_be(bytes)?;
        let timestamp = Duration::from_millis(timestamp);
        let generalized_time = GeneralizedTime::from_unix_duration(timestamp);
        if let Ok(generalized_time) = generalized_time {
            Ok((generalized_time.into(), bytes))
        } else {
            let utc_time = UtcTime::from_unix_duration(timestamp);
            if let Ok(utc_time) = utc_time {
                Ok((utc_time.into(), bytes))
            } else {
                Err(Error::DecodeTimestampError)
            }
        }
    }

    fn decode_extensions(bytes: &[u8]) -> Result<(Vec<u8>, &[u8]), Error> {
        let (len, rest) = decode_u16_be(bytes)?;
        let len = len as usize;
        if len > bytes.len() {
            return Err(Error::DecodeExtensionsError);
        }
        let mut vec = Vec::with_capacity(len);
        vec.extend_from_slice(&rest[..len]);
        Ok((vec, &rest[len..]))
    }
}

#[derive(Debug)]
pub enum Version {
    V1 = 0,
}

impl Version {
    fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (version, bytes) = decode_u8_be(bytes)?;
        Ok((version.try_into()?, bytes))
    }
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Version::V1),
            _ => Err(Error::DecodeVersionError),
        }
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Version::V1 => write!(f, "v1"),
        }
    }
}

#[derive(Debug)]
pub struct DigitallySigned {
    pub sign_and_hash_algo: SignAndHashAlgo,
    pub sign: Vec<u8>,
}

impl DigitallySigned {
    fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (sign_and_hash_algo, bytes) = SignAndHashAlgo::decode(bytes)?;

        let (len, rest) = decode_u16_be(bytes)?;
        let len = len as usize;
        if len > bytes.len() {
            return Err(Error::DecodeDigitallySignedError);
        }
        let mut sign = Vec::with_capacity(len);
        sign.extend_from_slice(&rest[..len]);
        Ok((
            Self {
                sign_and_hash_algo,
                sign,
            },
            &rest[len..],
        ))
    }
}

#[derive(Debug)]
pub struct SignAndHashAlgo {
    pub sign: SignatureAlgo,
    pub hash: HashAlgo,
}

impl SignAndHashAlgo {
    fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (hash, bytes) = HashAlgo::decode(bytes)?;
        let (sign, bytes) = SignatureAlgo::decode(bytes)?;
        Ok((Self { sign, hash }, bytes))
    }
}

impl Display for SignAndHashAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-with-{}", self.sign, self.hash)
    }
}

/// Signature algorithms, as defined in [RFC5246] and [RFC8422]
#[derive(Debug)]
pub enum SignatureAlgo {
    Anonymous = 0,
    Rsa = 1,
    Dsa = 2,
    Ecdsa = 3,
    Ed25519 = 7,
    Ed448 = 8,
}

impl SignatureAlgo {
    fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (algo, bytes) = decode_u8_be(bytes)?;
        Ok((algo.try_into()?, bytes))
    }
}

impl TryFrom<u8> for SignatureAlgo {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SignatureAlgo::Anonymous),
            1 => Ok(SignatureAlgo::Rsa),
            2 => Ok(SignatureAlgo::Dsa),
            3 => Ok(SignatureAlgo::Ecdsa),
            7 => Ok(SignatureAlgo::Ed25519),
            8 => Ok(SignatureAlgo::Ed448),
            _ => Err(Error::DecodeSignAlgoError),
        }
    }
}

impl Display for SignatureAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureAlgo::Anonymous => write!(f, "anonymous"),
            SignatureAlgo::Rsa => write!(f, "rsa"),
            SignatureAlgo::Dsa => write!(f, "dsa"),
            SignatureAlgo::Ecdsa => write!(f, "ecdsa"),
            SignatureAlgo::Ed25519 => write!(f, "ed25519"),
            SignatureAlgo::Ed448 => write!(f, "ed448"),
        }
    }
}

/// Hash algorithms, as defined in [RFC5246] and [RFC8422]
#[derive(Debug)]
pub enum HashAlgo {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
    Intrinsic = 8,
}

impl HashAlgo {
    fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), Error> {
        let (algo, bytes) = decode_u8_be(bytes)?;
        Ok((algo.try_into()?, bytes))
    }
}

impl TryFrom<u8> for HashAlgo {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(HashAlgo::None),
            1 => Ok(HashAlgo::Md5),
            2 => Ok(HashAlgo::Sha1),
            3 => Ok(HashAlgo::Sha224),
            4 => Ok(HashAlgo::Sha256),
            5 => Ok(HashAlgo::Sha384),
            6 => Ok(HashAlgo::Sha512),
            8 => Ok(HashAlgo::Intrinsic),
            _ => Err(Error::DecodeHashAlgoError),
        }
    }
}

impl Display for HashAlgo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgo::None => write!(f, "NONE"),
            HashAlgo::Md5 => write!(f, "MD5"),
            HashAlgo::Sha1 => write!(f, "SHA1"),
            HashAlgo::Sha224 => write!(f, "SHA224"),
            HashAlgo::Sha256 => write!(f, "SHA256"),
            HashAlgo::Sha384 => write!(f, "SHA384"),
            HashAlgo::Sha512 => write!(f, "SHA512"),
            HashAlgo::Intrinsic => write!(f, "INTRINSIC"),
        }
    }
}

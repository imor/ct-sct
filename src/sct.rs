use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::OctetString;
use x509_cert::{ext::AsExtension, impl_newtype};

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

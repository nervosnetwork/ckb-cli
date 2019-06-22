// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! BIP32 Implementation
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

use std::default::Default;
use std::io::Write;
use std::str::FromStr;
use std::{error, fmt};

use bitcoin_hashes::{hash160, sha512, Hash, HashEngine, Hmac, HmacEngine};
use byteorder::{BigEndian, ByteOrder};
use secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use crate::NetworkType;

macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        impl<'a> From<&'a [$ty]> for $thing {
            fn from(data: &'a [$ty]) -> $thing {
                assert_eq!(data.len(), $len);
                let mut ret = [0; $len];
                ret.copy_from_slice(&data[..]);
                $thing(ret)
            }
        }

        impl ::std::ops::Index<usize> for $thing {
            type Output = $ty;

            #[inline]
            fn index(&self, index: usize) -> &$ty {
                let &$thing(ref dat) = self;
                &dat[index]
            }
        }

        impl_index_newtype!($thing, $ty);

        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool {
                &self[..] == &other[..]
            }
        }

        impl Eq for $thing {}

        impl PartialOrd for $thing {
            #[inline]
            fn partial_cmp(&self, other: &$thing) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(&other))
            }
        }

        impl Ord for $thing {
            #[inline]
            fn cmp(&self, other: &$thing) -> ::std::cmp::Ordering {
                // manually implement comparison to get little-endian ordering
                // (we need this for our numeric types; non-numeric ones shouldn't
                // be ordered anyway except to put them in BTrees or whatever, and
                // they don't care how we order as long as we're consistent).
                for i in 0..$len {
                    if self[$len - 1 - i] < other[$len - 1 - i] {
                        return ::std::cmp::Ordering::Less;
                    }
                    if self[$len - 1 - i] > other[$len - 1 - i] {
                        return ::std::cmp::Ordering::Greater;
                    }
                }
                ::std::cmp::Ordering::Equal
            }
        }

        impl ::std::hash::Hash for $thing {
            #[inline]
            fn hash<H>(&self, state: &mut H)
            where
                H: ::std::hash::Hasher,
            {
                (&self[..]).hash(state);
            }

            fn hash_slice<H>(data: &[$thing], state: &mut H)
            where
                H: ::std::hash::Hasher,
            {
                for d in data.iter() {
                    (&d[..]).hash(state);
                }
            }
        }
    };
}

macro_rules! impl_index_newtype {
    ($thing:ident, $ty:ty) => {
        impl ::std::ops::Index<::std::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::Range<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::std::ops::RangeFull) -> &[$ty] {
                &self.0[..]
            }
        }
    };
}

/// A chain code
#[derive(Debug, Clone, Copy)]
pub struct ChainCode(pub [u8; 32]);
impl_array_newtype!(ChainCode, u8, 32);

/// A fingerprint
#[derive(Debug, Clone, Copy)]
pub struct Fingerprint(pub [u8; 4]);
impl_array_newtype!(Fingerprint, u8, 4);

impl Default for Fingerprint {
    fn default() -> Fingerprint {
        Fingerprint([0; 4])
    }
}

/// Extended private key
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtendedPrivKey {
    /// The network this key is to be used on
    pub network: NetworkType,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key (0 for master)
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Private key
    pub private_key: SecretKey,
    /// Chain code
    pub chain_code: ChainCode,
}

/// Extended public key
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExtendedPubKey {
    /// The network this key is to be used on
    pub network: NetworkType,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Public key
    pub public_key: PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
}

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ChildNumber {
    /// Non-hardened key
    Normal {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
    /// Hardened key
    Hardened {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
}

impl ChildNumber {
    /// Create a [`Normal`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    pub fn from_normal_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Normal { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Create a [`Hardened`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn from_hardened_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Hardened { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Returns `true` if the child number is a [`Normal`] value.
    ///
    /// [`Normal`]: #variant.Normal
    pub fn is_normal(self) -> bool {
        !self.is_hardened()
    }

    /// Returns `true` if the child number is a [`Hardened`] value.
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn is_hardened(self) -> bool {
        match self {
            ChildNumber::Hardened { .. } => true,
            ChildNumber::Normal { .. } => false,
        }
    }

    /// Returns the child number that is a single increment from this one.
    pub fn increment(self) -> Result<ChildNumber, Error> {
        match self {
            ChildNumber::Normal { index: idx } => ChildNumber::from_normal_idx(idx + 1),
            ChildNumber::Hardened { index: idx } => ChildNumber::from_hardened_idx(idx + 1),
        }
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildNumber::Hardened {
                index: number ^ (1 << 31),
            }
        } else {
            ChildNumber::Normal { index: number }
        }
    }
}

impl From<ChildNumber> for u32 {
    fn from(cnum: ChildNumber) -> Self {
        match cnum {
            ChildNumber::Normal { index } => index,
            ChildNumber::Hardened { index } => index | (1 << 31),
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildNumber::Hardened { index } => write!(f, "{}'", index),
            ChildNumber::Normal { index } => write!(f, "{}", index),
        }
    }
}

impl FromStr for ChildNumber {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ChildNumber, Error> {
        let child_number = if inp.chars().last().map_or(false, |l| l == '\'' || l == 'h') {
            ChildNumber::from_hardened_idx(
                inp[0..inp.len() - 1]
                    .parse()
                    .map_err(|_| Error::InvalidChildNumberFormat)?,
            )?
        } else {
            ChildNumber::from_normal_idx(inp.parse().map_err(|_| Error::InvalidChildNumberFormat)?)?
        };
        Ok(child_number)
    }
}

/// A BIP-32 derivation path.
#[derive(Clone, PartialEq, Eq)]
pub struct DerivationPath(Vec<ChildNumber>);
impl_index_newtype!(DerivationPath, ChildNumber);

impl From<Vec<ChildNumber>> for DerivationPath {
    fn from(numbers: Vec<ChildNumber>) -> Self {
        DerivationPath(numbers)
    }
}

impl Into<Vec<ChildNumber>> for DerivationPath {
    fn into(self) -> Vec<ChildNumber> {
        self.0
    }
}

impl<'a> From<&'a [ChildNumber]> for DerivationPath {
    fn from(numbers: &'a [ChildNumber]) -> Self {
        DerivationPath(numbers.to_vec())
    }
}

impl ::std::iter::FromIterator<ChildNumber> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ChildNumber>,
    {
        DerivationPath(Vec::from_iter(iter))
    }
}

impl<'a> ::std::iter::IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = ::std::slice::Iter<'a, ChildNumber>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl AsRef<[ChildNumber]> for DerivationPath {
    fn as_ref(&self) -> &[ChildNumber] {
        &self.0
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<DerivationPath, Error> {
        let mut parts = path.split('/');
        // First parts must be `m`.
        if parts.next().unwrap() != "m" {
            return Err(Error::InvalidDerivationPathFormat);
        }

        let ret: Result<Vec<ChildNumber>, Error> = parts.map(str::parse).collect();
        Ok(DerivationPath(ret?))
    }
}

/// An iterator over children of a [DerivationPath].
///
/// It is returned by the methods [DerivationPath::children_since],
/// [DerivationPath::normal_children] and [DerivationPath::hardened_children].
pub struct DerivationPathIterator<'a> {
    base: &'a DerivationPath,
    next_child: Option<ChildNumber>,
}

impl<'a> DerivationPathIterator<'a> {
    /// Start a new [DerivationPathIterator] at the given child.
    pub fn start_from(path: &'a DerivationPath, start: ChildNumber) -> DerivationPathIterator<'a> {
        DerivationPathIterator {
            base: path,
            next_child: Some(start),
        }
    }
}

impl<'a> Iterator for DerivationPathIterator<'a> {
    type Item = DerivationPath;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next_child?;
        self.next_child = ret.increment().ok();
        Some(self.base.child(ret))
    }
}

impl DerivationPath {
    /// Create a new [DerivationPath] that is a child of this one.
    pub fn child(&self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0.clone();
        path.push(cn);
        DerivationPath(path)
    }

    /// Convert into a [DerivationPath] that is a child of this one.
    pub fn into_child(self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0;
        path.push(cn);
        DerivationPath(path)
    }

    /// Get an [Iterator] over the children of this [DerivationPath]
    /// starting with the given [ChildNumber].
    pub fn children_from(&self, cn: ChildNumber) -> DerivationPathIterator {
        DerivationPathIterator::start_from(&self, cn)
    }

    /// Get an [Iterator] over the unhardened children of this [DerivationPath].
    pub fn normal_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(&self, ChildNumber::Normal { index: 0 })
    }

    /// Get an [Iterator] over the hardened children of this [DerivationPath].
    pub fn hardened_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(&self, ChildNumber::Hardened { index: 0 })
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("m")?;
        for cn in self.0.iter() {
            f.write_str("/")?;
            fmt::Display::fmt(cn, f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

/// A BIP32 error
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,
    /// A secp256k1 error occurred
    Ecdsa(secp256k1::Error),
    /// A child number was provided that was out of range
    InvalidChildNumber(u32),
    /// Error creating a master seed --- for application use
    RngError(String),
    /// Invalid childnumber format.
    InvalidChildNumberFormat,
    /// Invalid derivation path format.
    InvalidDerivationPathFormat,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CannotDeriveFromHardenedKey => {
                f.write_str("cannot derive hardened key from public key")
            }
            Error::Ecdsa(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidChildNumber(ref n) => write!(
                f,
                "child number {} is invalid (not within [0, 2^31 - 1])",
                n
            ),
            Error::RngError(ref s) => write!(f, "rng error {}", s),
            Error::InvalidChildNumberFormat => f.write_str("invalid child number format"),
            Error::InvalidDerivationPathFormat => f.write_str("invalid derivation path format"),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        if let Error::Ecdsa(ref e) = *self {
            Some(e)
        } else {
            None
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::CannotDeriveFromHardenedKey => "cannot derive hardened key from public key",
            Error::Ecdsa(ref e) => error::Error::description(e),
            Error::InvalidChildNumber(_) => "child number is invalid",
            Error::RngError(_) => "rng error",
            Error::InvalidChildNumberFormat => "invalid child number format",
            Error::InvalidDerivationPathFormat => "invalid derivation path format",
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Ecdsa(e)
    }
}

impl ExtendedPrivKey {
    /// Construct a new master key from a seed value
    pub fn new_master(network: NetworkType, seed: &[u8]) -> Result<ExtendedPrivKey, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        Ok(ExtendedPrivKey {
            network,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            private_key: secp256k1::SecretKey::from_slice(&hmac_result[..32])
                .map_err(Error::Ecdsa)?,
            chain_code: ChainCode::from(&hmac_result[32..]),
        })
    }

    /// Attempts to derive an extended private key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_priv<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPrivKey, Error> {
        let mut sk: ExtendedPrivKey = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(secp, *cnum)?;
        }
        Ok(sk)
    }

    /// Private->Private child key derivation
    pub fn ckd_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<ExtendedPrivKey, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        let mut be_n = [0; 4];
        match i {
            ChildNumber::Normal { .. } => {
                // Non-hardened key: compute public data and use that
                hmac_engine
                    .input(&PublicKey::from_secret_key(secp, &self.private_key).serialize()[..]);
            }
            ChildNumber::Hardened { .. } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key[..]);
            }
        }
        BigEndian::write_u32(&mut be_n, u32::from(i));

        hmac_engine.input(&be_n);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let mut sk = secp256k1::SecretKey::from_slice(&hmac_result[..32]).map_err(Error::Ecdsa)?;
        sk.add_assign(&self.private_key[..]).map_err(Error::Ecdsa)?;

        Ok(ExtendedPrivKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp),
            child_number: i,
            private_key: sk,
            chain_code: ChainCode::from(&hmac_result[32..]),
        })
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> hash160::Hash {
        ExtendedPubKey::from_private(secp, self).identifier()
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        Fingerprint::from(&self.identifier(secp)[0..4])
    }
}

impl ExtendedPubKey {
    /// Derives a public key from a private key
    pub fn from_private<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: &ExtendedPrivKey,
    ) -> ExtendedPubKey {
        ExtendedPubKey {
            network: sk.network,
            depth: sk.depth,
            parent_fingerprint: sk.parent_fingerprint,
            child_number: sk.child_number,
            public_key: secp256k1::PublicKey::from_secret_key(secp, &sk.private_key),
            chain_code: sk.chain_code,
        }
    }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_pub<C: secp256k1::Verification, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<ExtendedPubKey, Error> {
        let mut pk: ExtendedPubKey = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(secp, *cnum)?
        }
        Ok(pk)
    }

    /// Compute the scalar tweak added to this key to get a child key
    pub fn ckd_pub_tweak(&self, i: ChildNumber) -> Result<(SecretKey, ChainCode), Error> {
        match i {
            ChildNumber::Hardened { .. } => Err(Error::CannotDeriveFromHardenedKey),
            ChildNumber::Normal { index: n } => {
                let mut hmac_engine: HmacEngine<sha512::Hash> =
                    HmacEngine::new(&self.chain_code[..]);
                hmac_engine.input(&self.public_key.serialize()[..]);
                let mut be_n = [0; 4];
                BigEndian::write_u32(&mut be_n, n);
                hmac_engine.input(&be_n);

                let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

                let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])?;
                let chain_code = ChainCode::from(&hmac_result[32..]);
                Ok((private_key, chain_code))
            }
        }
    }

    /// Public->Public child key derivation
    pub fn ckd_pub<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<ExtendedPubKey, Error> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let mut pk = self.public_key;
        pk.add_exp_assign(secp, &sk[..]).map_err(Error::Ecdsa)?;

        Ok(ExtendedPubKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: pk,
            chain_code,
        })
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> hash160::Hash {
        let mut engine = hash160::Hash::engine();
        engine
            .write_all(&self.public_key.serialize())
            .expect("write must ok");
        hash160::Hash::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from(&self.identifier()[0..4])
    }
}

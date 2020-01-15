//! This is a prototype for [PR #21], the RFC introducing the `Kerl` and `CurlP` hash functions
//! implemented in terms of a common `Sponge` trait.
//!
//! The main focus of this prototype are the [`Sponge`] trait, and the [`CurlP`], and [`Kerl`]
//! types. These are cryptographic hash functions that are sponge constructions implemented in
//! terms of the trait.
//!
//! [PR #21]: https://github.com/iotaledger/bee-rfcs/pull/21

use std::convert::TryFrom;
use std::default::Default;

mod utils;

/// The length of a hash as returned by the hash functions implemented in this RFC (in
/// units of binary-coded, balanced trits).
const HASH_LEN: usize = 243;

/// The length internal state of the `CurlP` sponge construction (in units of binary-coded,
/// balanced trits).
const CURLP_STATE_LEN: usize = HASH_LEN * 3;
const CURLP_HALF_STATE_LEN: usize = CURLP_STATE_LEN / 2;

const TRUTH_TABLE: [i8; 11] = [1, 0, -1, 2, 1, -1, 0, 2, -1, 1, 0];

/// An owned, mutable 
#[derive(Clone, Debug, PartialEq)]
pub struct TritsBuf(Vec<i8>);

pub enum ValidTrits {
    MinusOne,
    PlusOne,
    Zero,
}

impl From<ValidTrits> for i8 {
    fn from(v: ValidTrits) -> Self {
        use ValidTrits::*;

        match v {
            MinusOne => -1,
            PlusOne => 1,
            Zero => 0,
        }
    }
}

impl TritsBuf {
    /// Create a new `TritsBuf` with a number of `capacity` elements, all
    /// initialized to 0;
    pub fn with_capacity(capacity: usize) -> Self {
        Self(vec![0; capacity])
    }

    /// Return a read-only view of the buffer in form of a `Trits`.
    pub fn as_trits(&self) -> Trits<'_> {
        Trits(&self.0)
    }

    /// Return a read-write view of the buffer in form of a `TritsMut`.
    pub fn as_trits_mut(&mut self) -> TritsMut<'_> {
        TritsMut(&mut self.0)
    }

    pub fn fill(&mut self, v: ValidTrits) {
        let v = v.into();
        self.0
            .iter_mut()
            .for_each(|x| *x = v);
    }

    /// Create a `Trits` from a `&[i8]` slice without verifying that its bytes are
    /// correctly binary-coded balanced trits (-1, 0, and +1).
    ///
    /// This function is intended to be used in hot loops and relies on the user making sure that
    /// the bytes are set correctly.
    ///
    /// **NOTE:** Use the `TryFrom` trait if you want to check that the slice encodes trits
    /// correctly before creating `Trits`.
    ///
    /// **WARNING:** If used incorrectly (that is, if the bytes are not correctly encoding trits), the
    /// usage of `Trits` might lead to unexpected behaviour.
    pub fn from_i8_unchecked<T: Into<Vec<i8>>>(v: T) -> Self {
        Self(v.into())
    }

    /// Create a `Trits` from a `&[u8]` slice without verifying that its bytes are
    /// correctly binary-coded balanced trits (-1, 0, and +1 transmuted to unsigned bytes).
    ///
    /// This function is intended to be used in hot loops and relies on the user making sure that
    /// the bytes are set correctly.
    ///
    /// **NOTE:** Use the `TryFrom` trait if you want to check that the slice encodes trits
    /// correctly before creating `Trits`.
    ///
    /// **WARNING:** If used incorrectly (that is, if the bytes are not correctly encoding trits), the
    /// usage of `Trits` might lead to unexpected behaviour.
    pub fn from_u8_unchecked<T: Into<Vec<u8>>>(v: T) -> Self {
        let inner = v.into();
        let mut inner = std::mem::ManuallyDrop::new(inner);

        let p = inner.as_mut_ptr();
        let len = inner.len();
        let cap = inner.capacity();

        let reconstructed = unsafe {
            let p_as_i8 = p as *mut i8;
            Vec::from_raw_parts(p_as_i8, len, cap)
        };
        Self::from_i8_unchecked(reconstructed)
    }
}

impl TryFrom<Vec<i8>> for TritsBuf {
    type Error = FromI8Error;

    fn try_from(vs: Vec<i8>) -> Result<Self, Self::Error> {
        for v in &vs {
            match v {
                0 | -1 | 1 => {},
                _ => Err(FromI8Error)?,
            }
        }
        Ok(TritsBuf::from_i8_unchecked(vs))
    }
}

impl TryFrom<Vec<u8>> for TritsBuf {
    type Error = FromU8Error;

    fn try_from(vs: Vec<u8>) -> Result<Self, Self::Error> {
        for v in &vs {
            match v {
                0b0000_0000 | 0b1111_1111 | 0b0000_0001 => {},
                _ => Err(FromU8Error)?,
            }
        }

        Ok(Self::from_u8_unchecked(vs))
    }
}

#[derive(Debug, PartialEq)]
pub struct Trits<'a>(&'a [i8]);

#[derive(Debug, PartialEq)]
pub struct TritsMut<'a>(&'a mut [i8]);

pub struct FromU8Error;
pub struct FromI8Error;

/// Similar impls for `TritsMut` and `TritsBuf`
impl<'a> Trits<'a> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Create a `Trits` from a `&[i8]` slice without verifying that its bytes are
    /// correctly binary-coded balanced trits (-1, 0, and +1).
    ///
    /// This function is intended to be used in hot loops and relies on the user making sure that
    /// the bytes are set correctly.
    ///
    /// **NOTE:** Use the `TryFrom` trait if you want to check that the slice encodes trits
    /// correctly before creating `Trits`.
    ///
    /// **WARNING:** If used incorrectly (that is, if the bytes are not correctly encoding trits), the
    /// usage of `Trits` might lead to unexpected behaviour.
    pub fn from_i8_unchecked(v: &'a [i8]) -> Self {
        Self(v)
    }

    /// Create a `Trits` from a `&[u8]` slice without verifying that its bytes are
    /// correctly binary-coded balanced trits (-1, 0, and +1 transmuted to unsigned bytes).
    ///
    /// This function is intended to be used in hot loops and relies on the user making sure that
    /// the bytes are set correctly.
    ///
    /// **NOTE:** Use the `TryFrom` trait if you want to check that the slice encodes trits
    /// correctly before creating `Trits`.
    ///
    /// **WARNING:** If used incorrectly (that is, if the bytes are not correctly encoding trits), the
    /// usage of `Trits` might lead to unexpected behaviour.
    pub fn from_u8_unchecked(v: &[u8]) -> Self {
        Self::from_i8_unchecked(
            unsafe {
                &*(v as *const _ as *const [i8])
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Trits<'a> {
    type Error = FromU8Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        for byte in v {
            match byte {
                0b0000_0000 | 0b1111_1111 | 0b0000_0001 => {},
                _ => Err(FromU8Error)?,
            }
        }

        Ok( Self::from_u8_unchecked(v) )
    }
}

impl<'a> TryFrom<&'a [i8]> for Trits<'a> {
    type Error = FromI8Error;

    fn try_from(v: &'a [i8]) -> Result<Self, Self::Error> {
        for byte in v {
            match byte {
                0 | -1 | 1 => {},
                _ => Err(FromI8Error)?,
            }
        }

        Ok( Self::from_i8_unchecked(v) )
    }
}

impl<'a> TritsMut<'a> {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn from_i8_unchecked(v: &'a mut [i8]) -> Self {
        Self(v)
    }

    pub fn from_u8_unchecked(v: &mut [u8]) -> Self {
        Self::from_i8_unchecked(
            unsafe {
                &mut *(v as *mut _ as *mut [i8])
        })
    }
}

impl<'a> TryFrom<&'a mut [i8]> for TritsMut<'a> {
    type Error = FromI8Error;

    fn try_from(v: &'a mut [i8]) -> Result<Self, Self::Error> {
        for byte in v.iter() {
            match byte {
                0 | -1 | 1 => {},
                _ => Err(FromI8Error)?,
            }
        }

        Ok( Self::from_i8_unchecked(v) )
    }
}


impl<'a> TryFrom<&'a mut [u8]> for TritsMut<'a> {
    type Error = FromU8Error;

    fn try_from(v: &mut [u8]) -> Result<Self, Self::Error> {
        for byte in v.iter() {
            match byte {
                0b0000_0000 | 0b1111_1111 | 0b0000_0001 => {},
                _ => Err(FromU8Error)?,
            }
        }

        Ok( Self::from_u8_unchecked(v) )
    }
}

/// The common interface of cryptographic hash functions that follow the sponge construction,
/// and that absorb and return binary-coded, balanced ternary.
trait Sponge {
    const HASH_LEN: usize;

    /// Absorb `input` into the sponge.
    fn absorb(&mut self, input: &Trits);

    /// Reset the inner state of the sponge.
    fn reset(&mut self);

    /// Squeeze the sponge into a buffer
    fn squeeze_into(&mut self, buf: &mut TritsMut);

    /// Convenience function using `Sponge::squeeze_into` to to return an owned
    /// version of the hash.
    fn squeeze(&mut self) -> TritsBuf {
        let mut output = TritsBuf::with_capacity(Self::HASH_LEN);
        self.squeeze_into(&mut output.as_trits_mut());
        output
    }

    /// Convenience function to absorb `input`, squeeze the sponge into a
    /// buffer, and reset the sponge in one go.
    fn digest_into(&mut self, input: &Trits, buf: &mut TritsMut) {
        self.absorb(input);
        self.squeeze_into(buf);
        self.reset();
    }

    /// Convenience function to absorb `input`, squeeze the sponge, and reset the sponge in one go.
    /// Returns an owned versin of the hash.
    fn digest(&mut self, input: &Trits) -> TritsBuf {
        self.absorb(input);
        let output = self.squeeze();
        self.reset();
        output
    }
}

pub struct CurlP {
    /// The number of rounds of hashing to apply before a hash is squeezed.
    rounds: usize,

    /// The internal state.
    state: TritsBuf,
}

impl CurlP {
    /// Create a new `CurlP` sponge with `rounds` of iterations.
    pub fn new(rounds: usize) -> Self {
        Self {
            rounds,
            state: TritsBuf::with_capacity(CURLP_STATE_LEN),
        }
    }

    /// Return the number of rounds used in this `CurlP` instacnce.
    pub fn rounds(&self) -> usize {
        self.rounds
    }

    /// Transforms the internal state of the `CurlP` sponge after the input was copied
    /// into the internal state.
    ///
    /// The essence of this transformation is the application of a so-called substitution box to
    /// the internal state, which happens `round` number of times.
    fn transform(&mut self) {
        let mut local_state = TritsBuf::with_capacity(CURLP_STATE_LEN);
        local_state.0.copy_from_slice(&self.state.0);

        let mut s1 = self.state.0.as_mut_ptr();
        let mut s2 = local_state.0.as_mut_ptr();

        unsafe {
            for _ in 0..self.rounds {
                *s1 = TRUTH_TABLE[(*s2 + (*s2.offset(364) << 2) + 5) as usize];

                for i in 0..364 {
                    *s1.offset(2 * i + 1) = TRUTH_TABLE
                        [(*s2.offset(364 - i) + (*s2.offset(729 - (i + 1)) << 2) + 5) as usize];
                    *s1.offset(2 * i + 2) = TRUTH_TABLE
                        [(*s2.offset(729 - (i + 1)) + (*s2.offset(364 - (i + 1)) << 2) + 5) as usize];
                }

                core::mem::swap(&mut s1, &mut s2);
            }
        }
    }
}

impl Sponge for CurlP {
    const HASH_LEN: usize = HASH_LEN;

    /// Absorb `input` into the sponge by copying `HASH_LEN` chunks of it into its internal
    /// state and transforming the state before moving on to the next chunk.
    ///
    /// If `input` is not a multiple of `HASH_LEN` with the last chunk having `n < HASH_LEN` trits,
    /// the last chunk will be copied to the first `n` slots of the internal state. The remaining
    /// data in the internal state is then just the result of the last transformation before the
    /// data was copied, and will be reused for the next transformation.
    fn absorb(&mut self, input: &Trits) {
        for chunk in input.0.chunks(Self::HASH_LEN) {
            self.state
                .0[0..chunk.len()]
                .copy_from_slice(chunk);
            self.transform();
        }
    }

    /// Reset the internal state by overwriting it with zeros.
    fn reset(&mut self) {
        self
            .state
            .fill(ValidTrits::Zero);
    }

    /// Squeeze the sponge by copying the calculated hash into the provided `buf`. This will fill
    /// the buffer in chunks of `HASH_LEN` at a time.
    ///
    /// If the last chunk is smaller than `HASH_LEN`, then only the fraction that fits is written
    /// into it.
    fn squeeze_into(&mut self, buf: &mut TritsMut) {
        let trit_count = buf.0.len();
        let hash_count = trit_count / Self::HASH_LEN;

        for chunk in buf.0.chunks_mut(Self::HASH_LEN) {
            chunk.copy_from_slice(
                &self.state
                    .0[0..chunk.len()]
            );
            self.transform()
        }

        let last = trit_count - hash_count * Self::HASH_LEN;
        buf.0[trit_count - last..].copy_from_slice(&self.state.0[0..last]);
        if trit_count % Self::HASH_LEN != 0 {
            self.transform();
        }
    }
}

/// `CurlP` with a fixed number of 27 rounds.
pub struct CurlP27(CurlP);

impl CurlP27 {
    pub fn new() -> Self {
        Self(CurlP::new(27))
    }
}

impl Default for CurlP27 {
    fn default() -> Self {
        CurlP27::new()
    }
}

/// `CurlP` with a fixed number of 81 rounds.
pub struct CurlP81(CurlP);

impl CurlP81 {
    pub fn new() -> Self {
        Self(CurlP::new(81))
    }
}

impl Default for CurlP81 {
    fn default() -> Self {
        CurlP81::new()
    }
}

macro_rules! forward_sponge_impl {
    ($($t:ty),+) => {

    $(
        impl $t {
            /// Return the number of rounds used in this `CurlP` instacnce.
            pub fn rounds(&self) -> usize {
                self.0.rounds
            }
        }

        impl Sponge for $t {
            const HASH_LEN: usize = 243;

            fn absorb(&mut self, input: &Trits) {
                self.0.absorb(input)
            }

            fn reset(&mut self) {
                self.0.reset()
            }

            fn squeeze_into(&mut self, buf: &mut TritsMut) {
                self.0.squeeze_into(buf);
            }
        }
    )+
    }
}

forward_sponge_impl!(CurlP27, CurlP81);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_curlp81_hash() {
        let input = vec![-1, 1, -1, -1, 1, -1, 1, 1, 0, -1, 0, 0, 1, 0, 1, 0, 0, 0, -1, -1, -1, -1, 0, 0, -1, 0, 0, 1, 0, 0, -1, 0, 0, 1, -1, 
        -1, 1, -1, 1, -1, -1, 1, 0, 1, 0, 0, 0, 1, -1, 0, -1, 1, -1, -1, 0, 0, 0, -1, 0, 0, 1, -1, -1, 0, 0, 0, -1, 0, 
        0, 0, -1, -1, 0, 1, 1, -1, 1, 1, 1, 1, -1, 0, -1, 0, -1, 0, -1, 0, -1, -1, -1, -1, 0, 1, -1, 0, -1, -1, 0, 0, 0, 
        0, 0, 1, 1, 0, 1, -1, 0, -1, -1, -1, 0, 0, 1, 0, -1, -1, -1, -1, 0, -1, -1, -1, 0, -1, 0, 0, -1, 1, 1, -1, -1,   
        1, 1, -1, 1, -1, 1, 0, -1, 1, -1, -1, -1, 0, 1, 1, 0, -1, 0, 1, 0, 0, 1, 1, 0, 0, -1, -1, 1, 0, 0, 0, 0, -1, 1,  
        0, 1, 0, 0, 0, 1, -1, 1, -1, 0, 0, -1, 1, 1, -1, 0, 0, 1, -1, 0, 1, 0, -1, 1, -1, 0, 0, 1, -1, -1, -1, 0, 1, 0,  
        -1, -1, 0, 1, 0, 0, 0, 1, -1, 1, -1, 0, 1, -1, -1, 0, 0, 0, -1, -1, 1, 1, 0, 1, -1, 0, 0, 0, -1, 0, -1, 0, -1,   
        -1, -1, -1, 0, 1, -1, -1, 0, 1];

        let exp = vec![1, 1, 1, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1, -1, 1, -1, -1, -1, 1, 1, 0, 0, 1, 0, 0, 1, 0, -1, 1, 0, 1, -1, 0, 1, 
        0, -1, 0, -1, 1, -1, -1, -1, -1, 0, 1, 0, 1, -1, 1, 0, 0, 0, 1, -1, 1, -1, -1, -1, 1, 0, 1, 1, 0, -1, 0, 0, 0,   
        0, -1, 0, -1, 1, 1, 0, -1, 0, 1, 0, -1, 0, 1, -1, 1, -1, 0, -1, 0, -1, 0, 0, -1, 1, -1, 1, 0, 1, 1, 1, 1, 0, 0,  
        -1, 1, 1, 0, 0, 1, 0, -1, -1, 1, -1, 0, 1, 1, 0, -1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, -1, 1, -1, -1, -1, 1, 1,   
        0, 0, -1, -1, 1, -1, -1, -1, -1, -1, -1, 0, 0, 0, -1, 0, 1, 1, -1, -1, 1, 0, 1, 1, 1, 0, 1, 0, -1, 1, 0, -1, 0,  
        1, 1, 1, 0, 1, 0, -1, 1, 1, -1, -1, -1, -1, 0, 1, -1, 0, 1, -1, 1, 1, 0, -1, 0, 1, -1, 0, 1, 0, 0, 1, 0, 1, -1,  
        1, -1, 0, -1, 1, 0, -1, 0, -1, 0, -1, 0, 1, 0, 1, 0, -1, -1, 1, -1, 0, 1, 0, -1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1,   
        -1, 1, 1, -1, 1];

        let mut curlp81 = CurlP81::new();
        let input_trits = TritsBuf::from_i8_unchecked(input);
        let expected_hash = TritsBuf::from_i8_unchecked(exp);
        let calculated_hash = curlp81.digest(&input_trits.as_trits());
        assert_eq!(expected_hash, calculated_hash);
    }
}

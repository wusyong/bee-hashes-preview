use std::convert::TryFrom;

const HASH_LENGTH: usize = 243;
const STATE_LENGTH: usize = HASH_LENGTH * 3;

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

    pub fn borrow(&self) -> Trits<'_> {
        Trits(&self.0)
    }

    pub fn borrow_mut(&mut self) -> TritsMut<'_> {
        TritsMut(&mut self.0)
    }

    pub fn fill(&mut self, v: ValidTrits) {
        let v = v.into();
        self.0
            .iter_mut()
            .for_each(|x| *x = v);
    }
}

pub struct Trits<'a>(&'a [i8]);
pub struct TritsMut<'a>(&'a mut [i8]);

pub struct FromU8Error;
pub struct FromI8Error;

/// Similar impls for `TritsMut` and `TritsBuf`
impl<'a> Trits<'a> {
    pub fn from_i8_unchecked(v: &'a [i8]) -> Self {
        Self(v)
    }

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

/// The common interface of cryptographic hash functions that follow the sponge construction and that
/// act on ternary.
trait Sponge {
    /// Absorb `input` into the sponge
    fn absorb(&mut self, input: &Trits);

    /// Reset the inner state of the sponge
    fn reset(&mut self);

    /// Squeeze the sponge into a buffer
    fn squeeze_into(&mut self, buf: &mut TritsMut);

    /// Squeeze the sponge and construct a new output
    fn squeeze(&mut self) -> TritsBuf {
        let mut output = TritsBuf::with_capacity(HASH_LENGTH);
        self.squeeze_into(&mut output.borrow_mut());
        output
    }

    // Convenience function to absorb `input`, squeeze the sponge into a
    // buffer, and reset the sponge.
    fn digest_into(&mut self, input: &Trits, buf: &mut TritsMut) {
        self.absorb(input);
        self.squeeze_into(buf);
        self.reset();
    }

    // Convenience function to absorb `input`, squeeze the sponge constructing
    // a new output, and reseting the sponge.
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
            state: TritsBuf::with_capacity(STATE_LENGTH),
        }
    }

    /// Return the number of rounds used in this `CurlP` instacnce.
    pub fn rounds(&self) -> usize {
        self.rounds
    }

    fn transform(&mut self) {
        todo!()
    }
}

impl Sponge for CurlP {
     fn absorb(&mut self, input: &Trits) {
        for chunk in input.0.chunks(HASH_LENGTH) {
            self
                .state
                .0[0..chunk.len()]
                .copy_from_slice(chunk);
            self.transform();
        }
    }

    fn reset(&mut self) {
        self
            .state
            .fill(ValidTrits::Zero);
    }

    fn squeeze_into(&mut self, buf: &mut TritsMut) {
        todo!()
    }
}

pub struct CurlP27(CurlP);

impl CurlP27 {
    pub fn new() -> Self {
        Self(CurlP::new(27))
    }
}

pub struct CurlP81(CurlP);

impl CurlP81 {
    pub fn new() -> Self {
        Self(CurlP::new(81))
    }
}

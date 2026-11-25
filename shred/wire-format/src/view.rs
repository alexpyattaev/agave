//! Borrowed views over a shred's sections.
//!
//! Not expressible with wincode traits alone: some sections overlap (the Merkle leaf and the
//! erasure shard span others).

use {
    crate::{
        constants::{
            MERKLE_PROOF_ENTRIES, MerkleProofEntry, SIZE_OF_MERKLE_ROOT, Section, Sections,
            sections,
        },
        error::WriteError,
        headers::CommonHeader,
        kind::ShredLayout,
        shred_variant::ShredVariant,
    },
    std::marker::PhantomData,
};

/// Mutable access to the sections of one shred of kind `K`.
///
/// Holds the payload whole and borrows sections on request, since the Merkle leaf and erasure shard
/// overlap other sections.
pub struct ShredViewMut<'a, K: ShredLayout> {
    payload: &'a mut [u8],
    variant: ShredVariant,
    sections: Sections,
    _kind: PhantomData<K>,
}

impl<'a, K: ShredLayout> ShredViewMut<'a, K> {
    /// Takes `payload`, exactly one shred long, laid out as `variant` selects. Contents are not read.
    pub fn new(payload: &'a mut [u8], variant: ShredVariant) -> Result<Self, WriteError> {
        let kind = variant.shred_kind();
        if kind != K::SHRED_KIND {
            return Err(WriteError::UnexpectedKind {
                expected: K::SHRED_KIND,
                found: kind,
            });
        }
        if payload.len() != K::SIZE_OF_PAYLOAD {
            return Err(WriteError::InvalidPayloadSize {
                len: payload.len(),
                expected: K::SIZE_OF_PAYLOAD,
            });
        }
        Ok(Self {
            payload,
            variant,
            sections: sections::<K>(variant.resigned()),
            _kind: PhantomData,
        })
    }

    /// Writes the headers, variant byte included. `common.variant` must match this view's variant.
    pub fn write_headers(
        &mut self,
        common: &CommonHeader,
        header: &K::Header,
    ) -> Result<(), WriteError> {
        if common.variant != self.variant {
            return Err(WriteError::VariantMismatch {
                expected: self.variant,
                found: common.variant,
            });
        }
        let dst = section_mut(self.payload, self.sections.headers);
        Ok(wincode::serialize_into(dst, &(*common, *header))?)
    }

    #[inline]
    pub fn chained_merkle_root_mut(&mut self) -> &mut [u8; SIZE_OF_MERKLE_ROOT] {
        section_mut(self.payload, self.sections.chained_merkle_root)
            .try_into()
            .expect("chained Merkle root section is one root long")
    }

    #[inline]
    pub fn merkle_proof_mut(&mut self) -> &mut [MerkleProofEntry; MERKLE_PROOF_ENTRIES] {
        let (entries, _) = section_mut(self.payload, self.sections.merkle_proof).as_chunks_mut();
        entries
            .try_into()
            .expect("Merkle proof section is MERKLE_PROOF_ENTRIES entries long")
    }

    #[inline]
    pub fn erasure_shard_mut(&mut self) -> &mut [u8] {
        section_mut(self.payload, self.sections.erasure_shard)
    }

    /// Meaningful only once everything before the proof has been written.
    #[inline]
    pub fn merkle_leaf(&self) -> &[u8] {
        self.payload
            .get(self.sections.merkle_leaf.as_range())
            .expect("every section of a fixed-size layout is inside a payload of that size")
    }
}

#[inline]
fn section_mut(payload: &mut [u8], section: Section) -> &mut [u8] {
    payload
        .get_mut(section.as_range())
        .expect("every section of a fixed-size layout is inside a payload of that size")
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            constants::{
                OFFSET_OF_DATA_SIZE, OFFSET_OF_FEC_SET_INDEX, OFFSET_OF_FLAGS, OFFSET_OF_INDEX,
                OFFSET_OF_NUM_CODE_SHREDS, OFFSET_OF_NUM_DATA_SHREDS, OFFSET_OF_PARENT_OFFSET,
                OFFSET_OF_POSITION, OFFSET_OF_SLOT, OFFSET_OF_VARIANT, OFFSET_OF_VERSION,
            },
            headers::{CodeHeader, DataHeader, ShredFlags},
            kind::{Code, Data},
        },
    };

    fn common_header(variant: ShredVariant) -> CommonHeader {
        CommonHeader {
            variant,
            slot: 0x0102_0304_0506_0708,
            index: 0x1112_1314,
            version: 0x2122,
            fec_set_index: 0x1112_1300,
        }
    }

    fn field<const N: usize>(payload: &[u8], offset: usize) -> [u8; N] {
        payload[offset..][..N]
            .try_into()
            .expect("slice has length N")
    }

    fn check_common_offsets(payload: &[u8], common: &CommonHeader) {
        assert_eq!(payload[OFFSET_OF_VARIANT], common.variant as u8);
        assert_eq!(field(payload, OFFSET_OF_SLOT), common.slot.to_le_bytes());
        assert_eq!(field(payload, OFFSET_OF_INDEX), common.index.to_le_bytes());
        assert_eq!(
            field(payload, OFFSET_OF_VERSION),
            common.version.to_le_bytes()
        );
        assert_eq!(
            field(payload, OFFSET_OF_FEC_SET_INDEX),
            common.fec_set_index.to_le_bytes()
        );
    }

    #[test]
    fn test_data_header_field_offsets() {
        for resigned in [false, true] {
            let common = common_header(ShredVariant::data(resigned));
            let flags = 0b0100_0101;
            let header = DataHeader {
                parent_offset: 0x3132,
                flags: ShredFlags::from(flags),
                size: 0x4142,
            };
            let mut payload = vec![0u8; Data::SIZE_OF_PAYLOAD];
            let mut view = ShredViewMut::<Data>::new(&mut payload, common.variant)
                .expect("buffer is one data shred long");
            view.write_headers(&common, &header)
                .expect("headers fit their section");

            check_common_offsets(&payload, &common);
            assert_eq!(
                field(&payload, OFFSET_OF_PARENT_OFFSET),
                header.parent_offset.to_le_bytes()
            );
            assert_eq!(payload[OFFSET_OF_FLAGS], flags);
            assert_eq!(
                field(&payload, OFFSET_OF_DATA_SIZE),
                header.size.to_le_bytes()
            );
        }
    }

    #[test]
    fn test_code_header_field_offsets() {
        for resigned in [false, true] {
            let common = common_header(ShredVariant::code(resigned));
            let header = CodeHeader {
                num_data_shreds: 0x4142,
                num_code_shreds: 0x5152,
                position: 0x6162,
            };
            let mut payload = vec![0u8; Code::SIZE_OF_PAYLOAD];
            let mut view = ShredViewMut::<Code>::new(&mut payload, common.variant)
                .expect("buffer is one code shred long");
            view.write_headers(&common, &header)
                .expect("headers fit their section");

            check_common_offsets(&payload, &common);
            assert_eq!(
                field(&payload, OFFSET_OF_NUM_DATA_SHREDS),
                header.num_data_shreds.to_le_bytes()
            );
            assert_eq!(
                field(&payload, OFFSET_OF_NUM_CODE_SHREDS),
                header.num_code_shreds.to_le_bytes()
            );
            assert_eq!(
                field(&payload, OFFSET_OF_POSITION),
                header.position.to_le_bytes()
            );
        }
    }
}

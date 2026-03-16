/// Operation types encoded in the upper 4 bits of user_data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpType {
    /// RecvMsgMulti on the main listening socket.
    MainRecvMulti = 0,
    /// Single-shot RecvMsg on an ephemeral socket.
    EphRecv = 1,
    /// SendMsg on the main socket (return path: backend → client).
    MainSend = 2,
    /// SendMsg on an ephemeral socket (forward path: client → backend).
    EphSend = 3,
    /// ProvideBuffers acknowledgement.
    ProvideBuffer = 4,
    /// AsyncCancel acknowledgement.
    Cancel = 5,
}

/// Packed 64-bit tag stored in each SQE's `user_data` field.
///
/// Layout:
/// - bits [63:60] — `OpType` (4 bits, up to 16 op types)
/// - bits [59:32] — `context_id` (28 bits, e.g. ephemeral socket index)
/// - bits [31:0]  — `buffer_index` (32 bits, for send buffer recycling)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserDataTag {
    pub op_type: OpType,
    pub context_id: u32,
    pub buffer_index: u32,
}

impl UserDataTag {
    pub fn new(op_type: OpType, context_id: u32, buffer_index: u32) -> Self {
        debug_assert!(context_id < (1 << 28), "context_id exceeds 28 bits");
        Self {
            op_type,
            context_id,
            buffer_index,
        }
    }

    pub fn encode(&self) -> u64 {
        let op = (self.op_type as u64) << 60;
        let ctx = (self.context_id as u64 & 0x0FFF_FFFF) << 32;
        let buf = self.buffer_index as u64;
        op | ctx | buf
    }

    pub fn decode(raw: u64) -> Self {
        let op_bits = ((raw >> 60) & 0xF) as u8;
        let context_id = ((raw >> 32) & 0x0FFF_FFFF) as u32;
        let buffer_index = (raw & 0xFFFF_FFFF) as u32;

        let op_type = match op_bits {
            0 => OpType::MainRecvMulti,
            1 => OpType::EphRecv,
            2 => OpType::MainSend,
            3 => OpType::EphSend,
            4 => OpType::ProvideBuffer,
            5 => OpType::Cancel,
            _ => OpType::Cancel, // fallback for unknown
        };

        Self {
            op_type,
            context_id,
            buffer_index,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_op_types() {
        let ops = [
            OpType::MainRecvMulti,
            OpType::EphRecv,
            OpType::MainSend,
            OpType::EphSend,
            OpType::ProvideBuffer,
            OpType::Cancel,
        ];
        for op in ops {
            let tag = UserDataTag::new(op, 0, 0);
            let decoded = UserDataTag::decode(tag.encode());
            assert_eq!(decoded.op_type, op);
        }
    }

    #[test]
    fn round_trip_with_values() {
        let tag = UserDataTag::new(OpType::EphRecv, 0x0ABC_DEF0, 0xDEAD_BEEF);
        let encoded = tag.encode();
        let decoded = UserDataTag::decode(encoded);
        assert_eq!(decoded.op_type, OpType::EphRecv);
        assert_eq!(decoded.context_id, 0x0ABC_DEF0);
        assert_eq!(decoded.buffer_index, 0xDEAD_BEEF);
    }

    #[test]
    fn max_context_id() {
        let tag = UserDataTag::new(OpType::MainSend, (1 << 28) - 1, u32::MAX);
        let decoded = UserDataTag::decode(tag.encode());
        assert_eq!(decoded.context_id, (1 << 28) - 1);
        assert_eq!(decoded.buffer_index, u32::MAX);
    }

    #[test]
    fn zero_tag() {
        let tag = UserDataTag::new(OpType::MainRecvMulti, 0, 0);
        assert_eq!(tag.encode(), 0);
        let decoded = UserDataTag::decode(0);
        assert_eq!(decoded.op_type, OpType::MainRecvMulti);
        assert_eq!(decoded.context_id, 0);
        assert_eq!(decoded.buffer_index, 0);
    }
}

use anyhow::{Context, Result, bail};
use aws_lc_rs::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{self, HKDF_SHA256, Salt};

use crate::tls::SniParser;

// QUIC v1 (RFC 9001) Initial salt
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

// QUIC v2 (RFC 9369) Initial salt
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

pub struct QuicInitialDecryptor;

impl QuicInitialDecryptor {
    /// Extract SNI from a QUIC Initial packet.
    pub fn extract_sni(packet: &[u8]) -> Result<String> {
        // Must be a Long Header packet (first bit = 1)
        if packet.is_empty() || packet[0] & 0x80 == 0 {
            bail!("not a long header packet");
        }

        // Version (bytes 1..5)
        if packet.len() < 5 {
            bail!("packet too short for version");
        }
        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

        let salt = match version {
            0x00000001 => &QUIC_V1_SALT,
            0x6b3343cf => &QUIC_V2_SALT,
            _ => bail!("unsupported QUIC version: 0x{version:08x}"),
        };

        // DCID: length at byte 5, data follows
        if packet.len() < 6 {
            bail!("packet too short for DCID length");
        }
        let dcid_len = packet[5] as usize;
        if packet.len() < 6 + dcid_len {
            bail!("packet too short for DCID");
        }
        let dcid = &packet[6..6 + dcid_len];

        // SCID: length after DCID
        let scid_offset = 6 + dcid_len;
        if packet.len() < scid_offset + 1 {
            bail!("packet too short for SCID length");
        }
        let scid_len = packet[scid_offset] as usize;
        let mut pos = scid_offset + 1 + scid_len;

        // Token (varint length + data) — only present in Initial packets
        if packet.len() < pos + 1 {
            bail!("packet too short for token");
        }
        let (token_len, token_len_size) =
            Self::read_varint(&packet[pos..]).context("failed to read token length")?;
        pos += token_len_size + token_len as usize;

        // Payload length (varint)
        if packet.len() < pos + 1 {
            bail!("packet too short for payload length");
        }
        let (payload_len, payload_len_size) =
            Self::read_varint(&packet[pos..]).context("failed to read payload length")?;
        pos += payload_len_size;

        let header_end = pos; // end of header (before packet number)
        let payload_end = pos + payload_len as usize;
        if packet.len() < payload_end {
            bail!(
                "packet too short for payload: need {payload_end}, have {}",
                packet.len()
            );
        }

        // Derive keys from DCID
        let (key, iv, hp_key) = Self::derive_initial_keys(salt, dcid, version)?;

        // Remove header protection
        // Sample starts 4 bytes after the start of the packet number field
        // (we don't know pn length yet, so sample is at header_end + 4)
        if packet.len() < header_end + 4 + 16 {
            bail!("packet too short for header protection sample");
        }
        let sample = &packet[header_end + 4..header_end + 4 + 16];

        // AES-ECB encrypt the sample to get the mask
        let mask = Self::aes_ecb_encrypt(&hp_key, sample)?;

        // First byte: remove protection (lower 4 bits for long header)
        let mut header = packet[..payload_end].to_vec();
        header[0] ^= mask[0] & 0x0f;

        // Packet number length is in the lower 2 bits of the first byte + 1
        let pn_len = ((header[0] & 0x03) + 1) as usize;

        // Remove protection from packet number bytes
        for i in 0..pn_len {
            header[header_end + i] ^= mask[1 + i];
        }

        // Reconstruct packet number
        let mut pn: u32 = 0;
        for i in 0..pn_len {
            pn = (pn << 8) | header[header_end + i] as u32;
        }

        // Build nonce: packet number left-padded to 12 bytes, XOR with IV
        let mut nonce_bytes = [0u8; 12];
        let pn_bytes = pn.to_be_bytes();
        nonce_bytes[8..12].copy_from_slice(&pn_bytes);
        for i in 0..12 {
            nonce_bytes[i] ^= iv[i];
        }

        // AAD is the header bytes (with protection removed) up to and including packet number
        let aad_end = header_end + pn_len;
        let aad = &header[..aad_end];

        // Ciphertext is everything after the packet number up to payload_end
        let ciphertext_start = header_end + pn_len;
        let mut ciphertext = header[ciphertext_start..payload_end].to_vec();

        // Decrypt
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|e| anyhow::anyhow!("nonce error: {e}"))?;
        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &key).map_err(|e| anyhow::anyhow!("key error: {e}"))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let plaintext = less_safe_key
            .open_in_place(nonce, Aad::from(aad), &mut ciphertext)
            .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?;

        // Walk frames to find CRYPTO frame (type 0x06)
        match Self::extract_sni_from_frames(plaintext) {
            Ok(sni) => Ok(sni),
            Err(e) => {
                tracing::debug!(
                    plaintext_len = plaintext.len(),
                    first_bytes = ?&plaintext[..plaintext.len().min(32)],
                    "frame parse failed"
                );
                Err(e)
            }
        }
    }

    /// Decrypt a QUIC Initial packet and return the DCID + CRYPTO frame fragments.
    /// Used for reassembly when the ClientHello is fragmented across packets.
    pub fn decrypt_crypto_frames(packet: &[u8]) -> Result<(Vec<u8>, Vec<CryptoFragment>)> {
        if packet.is_empty() || packet[0] & 0x80 == 0 {
            bail!("not a long header packet");
        }
        if packet.len() < 6 {
            bail!("packet too short");
        }

        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
        let salt = match version {
            0x00000001 => &QUIC_V1_SALT,
            0x6b3343cf => &QUIC_V2_SALT,
            _ => bail!("unsupported QUIC version"),
        };

        let dcid_len = packet[5] as usize;
        if packet.len() < 6 + dcid_len {
            bail!("packet too short for DCID");
        }
        let dcid = packet[6..6 + dcid_len].to_vec();

        let scid_offset = 6 + dcid_len;
        if packet.len() < scid_offset + 1 {
            bail!("packet too short for SCID");
        }
        let scid_len = packet[scid_offset] as usize;
        let mut pos = scid_offset + 1 + scid_len;

        let (token_len, token_len_size) =
            Self::read_varint(&packet[pos..]).context("token length")?;
        pos += token_len_size + token_len as usize;

        let (payload_len, payload_len_size) =
            Self::read_varint(&packet[pos..]).context("payload length")?;
        pos += payload_len_size;

        let header_end = pos;
        let payload_end = pos + payload_len as usize;
        if packet.len() < payload_end {
            bail!("packet too short for payload");
        }

        let (key, iv, hp_key) = Self::derive_initial_keys(salt, &dcid, version)?;

        if packet.len() < header_end + 4 + 16 {
            bail!("packet too short for HP sample");
        }
        let sample = &packet[header_end + 4..header_end + 4 + 16];
        let mask = Self::aes_ecb_encrypt(&hp_key, sample)?;

        let mut header = packet[..payload_end].to_vec();
        header[0] ^= mask[0] & 0x0f;
        let pn_len = ((header[0] & 0x03) + 1) as usize;
        for i in 0..pn_len {
            header[header_end + i] ^= mask[1 + i];
        }

        let mut pn: u32 = 0;
        for i in 0..pn_len {
            pn = (pn << 8) | header[header_end + i] as u32;
        }

        let mut nonce_bytes = [0u8; 12];
        let pn_bytes = pn.to_be_bytes();
        nonce_bytes[8..12].copy_from_slice(&pn_bytes);
        for i in 0..12 {
            nonce_bytes[i] ^= iv[i];
        }

        let aad_end = header_end + pn_len;
        let aad = &header[..aad_end];
        let ciphertext_start = header_end + pn_len;
        let mut ciphertext = header[ciphertext_start..payload_end].to_vec();

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|e| anyhow::anyhow!("nonce: {e}"))?;
        let unbound_key =
            UnboundKey::new(&AES_128_GCM, &key).map_err(|e| anyhow::anyhow!("key: {e}"))?;
        let less_safe_key = LessSafeKey::new(unbound_key);
        let plaintext = less_safe_key
            .open_in_place(nonce, Aad::from(aad), &mut ciphertext)
            .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;

        let fragments = Self::extract_crypto_fragments(plaintext)?;
        Ok((dcid, fragments))
    }

    /// Derive Initial client keys from DCID (RFC 9001 §5.2)
    fn derive_initial_keys(
        salt: &[u8; 20],
        dcid: &[u8],
        version: u32,
    ) -> Result<([u8; 16], [u8; 12], [u8; 16])> {
        let hkdf_salt = Salt::new(HKDF_SHA256, salt);
        let initial_secret = hkdf_salt.extract(dcid);

        let client_label = match version {
            0x6b3343cf => "client in",
            _ => "client in",
        };

        let client_initial_secret =
            Self::hkdf_expand_label(&initial_secret, client_label, &[], 32)?;

        // Re-import client_initial_secret as PRK for further expansion
        let client_prk = hkdf::Prk::new_less_safe(HKDF_SHA256, &client_initial_secret);

        let key_label = "quic key";
        let iv_label = "quic iv";
        let hp_label = "quic hp";

        let key = Self::hkdf_expand_label(&client_prk, key_label, &[], 16)?;
        let iv = Self::hkdf_expand_label(&client_prk, iv_label, &[], 12)?;
        let hp = Self::hkdf_expand_label(&client_prk, hp_label, &[], 16)?;

        let mut key_bytes = [0u8; 16];
        let mut iv_bytes = [0u8; 12];
        let mut hp_bytes = [0u8; 16];
        key_bytes.copy_from_slice(&key);
        iv_bytes.copy_from_slice(&iv);
        hp_bytes.copy_from_slice(&hp);

        Ok((key_bytes, iv_bytes, hp_bytes))
    }

    fn hkdf_expand_label(
        prk: &hkdf::Prk,
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        // Build HkdfLabel structure
        let full_label = format!("tls13 {label}");
        let full_label_bytes = full_label.as_bytes();

        let mut info = Vec::with_capacity(2 + 1 + full_label_bytes.len() + 1 + context.len());
        info.push((length >> 8) as u8);
        info.push((length & 0xFF) as u8);
        info.push(full_label_bytes.len() as u8);
        info.extend_from_slice(full_label_bytes);
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        let info_refs: &[&[u8]] = &[&info];
        let okm = prk
            .expand(info_refs, HkdfLen(length))
            .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;

        let mut out = vec![0u8; length];
        okm.fill(&mut out)
            .map_err(|e| anyhow::anyhow!("HKDF fill failed: {e}"))?;

        Ok(out)
    }

    /// AES-ECB encrypt a single 16-byte block (for header protection).
    fn aes_ecb_encrypt(key: &[u8; 16], input: &[u8]) -> Result<[u8; 16]> {
        use aws_lc_rs::cipher::{AES_128, PaddedBlockEncryptingKey, UnboundCipherKey};

        let cipher_key = UnboundCipherKey::new(&AES_128, key)
            .map_err(|e| anyhow::anyhow!("AES key error: {e}"))?;
        let encrypting_key = PaddedBlockEncryptingKey::ecb_pkcs7(cipher_key)
            .map_err(|e| anyhow::anyhow!("ECB key error: {e}"))?;

        // ECB+PKCS7 on 16 bytes produces 32 bytes (16 data + 16 padding block).
        // We only need the first 16 bytes (one encrypted block).
        let mut block = input[..16].to_vec();
        encrypting_key
            .encrypt(&mut block)
            .map_err(|e| anyhow::anyhow!("AES-ECB encrypt failed: {e}"))?;

        let mut result = [0u8; 16];
        result.copy_from_slice(&block[..16]);
        Ok(result)
    }

    /// Read a QUIC variable-length integer. Returns (value, bytes_consumed).
    fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
        if data.is_empty() {
            return None;
        }

        let first = data[0];
        let prefix = first >> 6;

        match prefix {
            0 => Some((first as u64 & 0x3F, 1)),
            1 => {
                if data.len() < 2 {
                    return None;
                }
                let val = ((data[0] as u64 & 0x3F) << 8) | data[1] as u64;
                Some((val, 2))
            }
            2 => {
                if data.len() < 4 {
                    return None;
                }
                let val = ((data[0] as u64 & 0x3F) << 24)
                    | ((data[1] as u64) << 16)
                    | ((data[2] as u64) << 8)
                    | data[3] as u64;
                Some((val, 4))
            }
            3 => {
                if data.len() < 8 {
                    return None;
                }
                let val = ((data[0] as u64 & 0x3F) << 56)
                    | ((data[1] as u64) << 48)
                    | ((data[2] as u64) << 40)
                    | ((data[3] as u64) << 32)
                    | ((data[4] as u64) << 24)
                    | ((data[5] as u64) << 16)
                    | ((data[6] as u64) << 8)
                    | data[7] as u64;
                Some((val, 8))
            }
            _ => unreachable!(),
        }
    }

    /// Extract all CRYPTO frame fragments from decrypted Initial plaintext.
    fn extract_crypto_fragments(plaintext: &[u8]) -> Result<Vec<CryptoFragment>> {
        let mut pos = 0;
        let mut fragments = Vec::new();

        while pos < plaintext.len() {
            let (frame_type, ft_size) = Self::read_varint(&plaintext[pos..]).unwrap_or((0xFF, 1));
            pos += ft_size;

            match frame_type {
                0x00 => continue,
                0x01 => continue,
                0x02 | 0x03 => {
                    // ACK — skip
                    let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK")?;
                    pos += s;
                    let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK")?;
                    pos += s;
                    let (range_count, s) = Self::read_varint(&plaintext[pos..]).context("ACK")?;
                    pos += s;
                    let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK")?;
                    pos += s;
                    for _ in 0..range_count {
                        let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK")?;
                        pos += s;
                        let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK")?;
                        pos += s;
                    }
                    if frame_type == 0x03 {
                        for _ in 0..3 {
                            let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK ECN")?;
                            pos += s;
                        }
                    }
                }
                0x06 => {
                    let (offset, s) =
                        Self::read_varint(&plaintext[pos..]).context("CRYPTO offset")?;
                    pos += s;
                    let (data_len, s) =
                        Self::read_varint(&plaintext[pos..]).context("CRYPTO len")?;
                    pos += s;
                    let data_len = data_len as usize;
                    if pos + data_len > plaintext.len() {
                        break;
                    }
                    fragments.push(CryptoFragment {
                        offset,
                        data: plaintext[pos..pos + data_len].to_vec(),
                    });
                    pos += data_len;
                }
                _ => break,
            }
        }

        Ok(fragments)
    }

    /// Walk decrypted QUIC frames and extract SNI from a CRYPTO frame.
    fn extract_sni_from_frames(plaintext: &[u8]) -> Result<String> {
        let mut pos = 0;

        while pos < plaintext.len() {
            // Frame type is a varint
            let (frame_type, ft_size) =
                Self::read_varint(&plaintext[pos..]).context("failed to read frame type")?;
            pos += ft_size;

            match frame_type {
                0x00 => {
                    // PADDING — skip single byte (already consumed by varint read)
                    continue;
                }
                0x01 => {
                    // PING — no payload
                    continue;
                }
                0x02 | 0x03 => {
                    // ACK frame — must parse to skip correctly
                    // Largest Acknowledged (varint)
                    let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK largest_ack")?;
                    pos += s;
                    // ACK Delay (varint)
                    let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK delay")?;
                    pos += s;
                    // ACK Range Count (varint)
                    let (range_count, s) =
                        Self::read_varint(&plaintext[pos..]).context("ACK range_count")?;
                    pos += s;
                    // First ACK Range (varint)
                    let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK first_range")?;
                    pos += s;
                    // Additional ACK Ranges: each is Gap(varint) + Range(varint)
                    for _ in 0..range_count {
                        let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK gap")?;
                        pos += s;
                        let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK range")?;
                        pos += s;
                    }
                    // ACK type 0x03 has ECN counts (3 varints)
                    if frame_type == 0x03 {
                        for _ in 0..3 {
                            let (_, s) = Self::read_varint(&plaintext[pos..]).context("ACK ECN")?;
                            pos += s;
                        }
                    }
                }
                0x06 => {
                    // CRYPTO frame: offset(varint) + length(varint) + data
                    let (_, offset_size) = Self::read_varint(&plaintext[pos..])
                        .context("failed to read CRYPTO offset")?;
                    pos += offset_size;

                    let (data_len, data_len_size) = Self::read_varint(&plaintext[pos..])
                        .context("failed to read CRYPTO data length")?;
                    pos += data_len_size;

                    let data_len = data_len as usize;
                    if pos + data_len > plaintext.len() {
                        bail!("CRYPTO frame data extends past plaintext");
                    }

                    let crypto_data = &plaintext[pos..pos + data_len];
                    if let Some(sni) = SniParser::extract_sni(crypto_data) {
                        return Ok(sni);
                    }

                    pos += data_len;
                }
                0x1c | 0x1d => {
                    // CONNECTION_CLOSE — reason_phrase_length(varint) + reason
                    let (_, s) = Self::read_varint(&plaintext[pos..]).context("CC error_code")?;
                    pos += s;
                    if frame_type == 0x1c {
                        let (_, s) =
                            Self::read_varint(&plaintext[pos..]).context("CC frame_type")?;
                        pos += s;
                    }
                    let (reason_len, s) =
                        Self::read_varint(&plaintext[pos..]).context("CC reason_len")?;
                    pos += s;
                    pos += reason_len as usize;
                }
                _ => {
                    // Unknown frame — can't safely skip, stop parsing
                    tracing::debug!(frame_type, pos, "unknown frame type, stopping parse");
                    break;
                }
            }
        }

        bail!("no CRYPTO frame with SNI found in Initial packet")
    }
}

/// A CRYPTO frame fragment with its offset and data.
pub struct CryptoFragment {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Custom length type for HKDF output.
#[derive(Debug)]
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_varint() {
        // 1-byte: value 37 (0x25)
        assert_eq!(QuicInitialDecryptor::read_varint(&[0x25]), Some((37, 1)));

        // 2-byte: value 15293 (0x7bbd)
        assert_eq!(
            QuicInitialDecryptor::read_varint(&[0x7b, 0xbd]),
            Some((15293, 2))
        );

        // 4-byte: value 494878333 (0x9d7f3e7d)
        assert_eq!(
            QuicInitialDecryptor::read_varint(&[0x9d, 0x7f, 0x3e, 0x7d]),
            Some((494878333, 4))
        );

        // Empty
        assert_eq!(QuicInitialDecryptor::read_varint(&[]), None);
    }

    #[test]
    fn test_hkdf_expand_label() {
        // Test with RFC 9001 Appendix A values
        // DCID = 0x8394c8f03e515708
        let dcid = hex_to_bytes("8394c8f03e515708");

        // QUIC v1 salt
        let salt = Salt::new(HKDF_SHA256, &QUIC_V1_SALT);
        let initial_secret = salt.extract(&dcid);

        // client_initial_secret
        let client_secret =
            QuicInitialDecryptor::hkdf_expand_label(&initial_secret, "client in", &[], 32).unwrap();

        assert_eq!(
            bytes_to_hex(&client_secret),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );

        // Derive key, iv, hp from client_initial_secret
        let client_prk = hkdf::Prk::new_less_safe(HKDF_SHA256, &client_secret);

        let key =
            QuicInitialDecryptor::hkdf_expand_label(&client_prk, "quic key", &[], 16).unwrap();
        assert_eq!(bytes_to_hex(&key), "1f369613dd76d5467730efcbe3b1a22d");

        let iv = QuicInitialDecryptor::hkdf_expand_label(&client_prk, "quic iv", &[], 12).unwrap();
        assert_eq!(bytes_to_hex(&iv), "fa044b2f42a3fd3b46fb255c");

        let hp = QuicInitialDecryptor::hkdf_expand_label(&client_prk, "quic hp", &[], 16).unwrap();
        assert_eq!(bytes_to_hex(&hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn test_aes_ecb_encrypt() {
        // RFC 9001 Appendix A.5 header protection
        // HP key = 9f50449e04a0e810283a1e9933adedd2
        // Sample = d1b1c98dd7689fb8ec11d242b123dc9b
        // Expected mask first 5 bytes = 437b9aec36
        let hp_key: [u8; 16] = hex_to_bytes_fixed("9f50449e04a0e810283a1e9933adedd2");
        let sample = hex_to_bytes("d1b1c98dd7689fb8ec11d242b123dc9b");

        let mask = QuicInitialDecryptor::aes_ecb_encrypt(&hp_key, &sample).unwrap();
        assert_eq!(bytes_to_hex(&mask[..5]), "437b9aec36");
    }

    #[test]
    fn test_malformed_packet_too_short() {
        assert!(QuicInitialDecryptor::extract_sni(&[]).is_err());
        assert!(QuicInitialDecryptor::extract_sni(&[0x80]).is_err());
        assert!(QuicInitialDecryptor::extract_sni(&[0xC0, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn test_short_header_rejected() {
        // Short header (first bit = 0)
        assert!(QuicInitialDecryptor::extract_sni(&[0x40, 0x00, 0x00, 0x00, 0x01]).is_err());
    }

    #[test]
    fn test_unsupported_version() {
        let mut packet = vec![0xC0]; // Long header, Initial type
        packet.extend_from_slice(&[0xFF, 0x00, 0x00, 0x01]); // Unknown version
        packet.push(8); // DCID length
        packet.extend_from_slice(&[0; 8]); // DCID
        packet.push(0); // SCID length
        packet.push(0); // token length (varint: 0)
        packet.extend_from_slice(&[0x40, 0x20]); // payload length (varint: 32)
        packet.extend_from_slice(&[0; 32]); // dummy payload

        assert!(QuicInitialDecryptor::extract_sni(&packet).is_err());
    }

    // Helper functions for tests
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_to_bytes_fixed<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex_to_bytes(hex);
        let mut result = [0u8; N];
        result.copy_from_slice(&bytes);
        result
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

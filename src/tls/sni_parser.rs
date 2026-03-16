/// Extracts SNI hostname from TLS ClientHello messages.
///
/// Two entry points:
/// - `extract_sni`: from raw Handshake layer bytes (starts at HandshakeType)
/// - `extract_sni_from_record`: from a TLS record (skips 5-byte record header)
pub struct SniParser;

impl SniParser {
    /// Extract SNI from a TLS Handshake message (starts at HandshakeType byte).
    pub fn extract_sni(client_hello: &[u8]) -> Option<String> {
        let mut pos = 0;

        // HandshakeType: must be 0x01 (ClientHello)
        if *client_hello.first()? != 0x01 {
            return None;
        }
        pos += 1;

        // Length: 3 bytes
        pos = checked_add(pos, 3, client_hello.len())?;

        // ProtocolVersion: 2 bytes
        pos = checked_add(pos, 2, client_hello.len())?;

        // Random: 32 bytes
        pos = checked_add(pos, 32, client_hello.len())?;

        // SessionID: 1 byte length + data
        let session_id_len = *client_hello.get(pos)? as usize;
        pos = checked_add(pos + 1, session_id_len, client_hello.len())?;

        // CipherSuites: 2 byte length + data
        let cipher_suites_len = read_u16(client_hello, pos)? as usize;
        pos = checked_add(pos + 2, cipher_suites_len, client_hello.len())?;

        // CompressionMethods: 1 byte length + data
        let compression_len = *client_hello.get(pos)? as usize;
        pos = checked_add(pos + 1, compression_len, client_hello.len())?;

        // Extensions: 2 byte total length
        let extensions_len = read_u16(client_hello, pos)? as usize;
        pos += 2;
        let extensions_end = pos.checked_add(extensions_len)?;

        // Walk extensions — all bounds checked against actual buffer length
        while pos + 4 <= extensions_end && pos + 4 <= client_hello.len() {
            let ext_type = read_u16(client_hello, pos)?;
            let ext_len = read_u16(client_hello, pos + 2)? as usize;
            pos += 4;

            let ext_data_end = pos.checked_add(ext_len)?;
            if ext_data_end > extensions_end || ext_data_end > client_hello.len() {
                return None;
            }

            if ext_type == 0x0000 {
                // SNI extension — parse ServerNameList
                return parse_sni_extension(&client_hello[pos..ext_data_end]);
            }

            pos = ext_data_end;
        }

        None
    }

    /// Extract SNI from a TLS record (skips 5-byte record header).
    pub fn extract_sni_from_record(record: &[u8]) -> Option<String> {
        // TLS record header: ContentType(1) + Version(2) + Length(2)
        if record.len() < 5 {
            return None;
        }

        // ContentType must be 0x16 (Handshake)
        if record[0] != 0x16 {
            return None;
        }

        Self::extract_sni(&record[5..])
    }
}

/// Parse the SNI extension payload to extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let list_len = read_u16(data, 0)? as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut pos = 2;
    let end = 2 + list_len;

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = read_u16(data, pos + 1)? as usize;
        pos += 3;

        if pos + name_len > end {
            return None;
        }

        if name_type == 0x00 {
            // host_name type
            let hostname = std::str::from_utf8(&data[pos..pos + name_len]).ok()?;
            return Some(hostname.to_string());
        }

        pos += name_len;
    }

    None
}

fn read_u16(data: &[u8], pos: usize) -> Option<u16> {
    let hi = *data.get(pos)? as u16;
    let lo = *data.get(pos + 1)? as u16;
    Some((hi << 8) | lo)
}

fn checked_add(pos: usize, add: usize, limit: usize) -> Option<usize> {
    let result = pos.checked_add(add)?;
    if result > limit {
        None
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();

        // SNI extension payload:
        // ServerNameList length (2B)
        //   NameType (1B = 0x00) + HostName length (2B) + hostname
        let sni_entry_len = 1 + 2 + hostname_bytes.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len; // list length field + list

        // Extensions block:
        // ExtType(2B) + ExtLen(2B) + ExtData
        let ext_block_len = 2 + 2 + sni_ext_data_len;

        // ClientHello body (after HandshakeType + Length):
        // Version(2) + Random(32) + SessionID(1+0) + CipherSuites(2+2) + Compression(1+1) + Extensions(2+ext_block)
        let body_len = 2 + 32 + 1 + (2 + 2) + (1 + 1) + 2 + ext_block_len;

        let mut buf = Vec::with_capacity(4 + body_len);

        // HandshakeType = ClientHello (0x01)
        buf.push(0x01);
        // Length (3 bytes, big-endian)
        buf.push(((body_len >> 16) & 0xFF) as u8);
        buf.push(((body_len >> 8) & 0xFF) as u8);
        buf.push((body_len & 0xFF) as u8);

        // ProtocolVersion: TLS 1.2 (0x0303)
        buf.extend_from_slice(&[0x03, 0x03]);
        // Random: 32 zero bytes
        buf.extend_from_slice(&[0u8; 32]);
        // SessionID: length 0
        buf.push(0x00);
        // CipherSuites: length 2, one suite (TLS_AES_128_GCM_SHA256)
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        // CompressionMethods: length 1, null
        buf.extend_from_slice(&[0x01, 0x00]);

        // Extensions total length
        buf.push(((ext_block_len >> 8) & 0xFF) as u8);
        buf.push((ext_block_len & 0xFF) as u8);

        // SNI Extension: type 0x0000
        buf.extend_from_slice(&[0x00, 0x00]);
        // Extension data length
        buf.push(((sni_ext_data_len >> 8) & 0xFF) as u8);
        buf.push((sni_ext_data_len & 0xFF) as u8);
        // ServerNameList length
        buf.push(((sni_list_len >> 8) & 0xFF) as u8);
        buf.push((sni_list_len & 0xFF) as u8);
        // NameType = host_name (0x00)
        buf.push(0x00);
        // HostName length
        buf.push(((hostname_bytes.len() >> 8) & 0xFF) as u8);
        buf.push((hostname_bytes.len() & 0xFF) as u8);
        // HostName
        buf.extend_from_slice(hostname_bytes);

        buf
    }

    /// Wrap a handshake message in a TLS record.
    fn wrap_in_record(handshake: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + handshake.len());
        record.push(0x16); // ContentType: Handshake
        record.extend_from_slice(&[0x03, 0x01]); // Version: TLS 1.0
        record.push(((handshake.len() >> 8) & 0xFF) as u8);
        record.push((handshake.len() & 0xFF) as u8);
        record.extend_from_slice(handshake);
        record
    }

    #[test]
    fn test_extract_sni_from_client_hello() {
        let hello = build_client_hello("server1.example.com");
        let sni = SniParser::extract_sni(&hello).unwrap();
        assert_eq!(sni, "server1.example.com");
    }

    #[test]
    fn test_extract_sni_from_record() {
        let hello = build_client_hello("test.bedrockvoicechat.com");
        let record = wrap_in_record(&hello);
        let sni = SniParser::extract_sni_from_record(&record).unwrap();
        assert_eq!(sni, "test.bedrockvoicechat.com");
    }

    #[test]
    fn test_no_sni_extension() {
        // ClientHello with no extensions
        let mut buf = Vec::new();
        buf.push(0x01); // HandshakeType
        // We'll fill length after
        let body_len = 2 + 32 + 1 + 4 + 2 + 2; // version+random+sessionid+ciphers+compression+ext_len
        buf.push(0x00);
        buf.push(((body_len >> 8) & 0xFF) as u8);
        buf.push((body_len & 0xFF) as u8);
        buf.extend_from_slice(&[0x03, 0x03]); // version
        buf.extend_from_slice(&[0u8; 32]); // random
        buf.push(0x00); // session id len
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        buf.extend_from_slice(&[0x01, 0x00]); // compression
        buf.extend_from_slice(&[0x00, 0x00]); // extensions length = 0

        assert!(SniParser::extract_sni(&buf).is_none());
    }

    #[test]
    fn test_multiple_extensions_before_sni() {
        let hostname = "multi-ext.example.com";
        let hostname_bytes = hostname.as_bytes();

        let sni_entry_len = 1 + 2 + hostname_bytes.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len;

        // Dummy extension: type 0x0010 (ALPN), 4 bytes of data
        let dummy_ext_len = 2 + 2 + 4; // type + len + data

        let ext_block_len = dummy_ext_len + 2 + 2 + sni_ext_data_len;
        let body_len = 2 + 32 + 1 + 4 + 2 + 2 + ext_block_len;

        let mut buf = Vec::new();
        buf.push(0x01);
        buf.push(((body_len >> 16) & 0xFF) as u8);
        buf.push(((body_len >> 8) & 0xFF) as u8);
        buf.push((body_len & 0xFF) as u8);
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0x00);
        buf.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        buf.extend_from_slice(&[0x01, 0x00]);

        // Extensions total length
        buf.push(((ext_block_len >> 8) & 0xFF) as u8);
        buf.push((ext_block_len & 0xFF) as u8);

        // Dummy ALPN extension
        buf.extend_from_slice(&[0x00, 0x10]); // type
        buf.extend_from_slice(&[0x00, 0x04]); // length
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // data

        // SNI extension
        buf.extend_from_slice(&[0x00, 0x00]);
        buf.push(((sni_ext_data_len >> 8) & 0xFF) as u8);
        buf.push((sni_ext_data_len & 0xFF) as u8);
        buf.push(((sni_list_len >> 8) & 0xFF) as u8);
        buf.push((sni_list_len & 0xFF) as u8);
        buf.push(0x00);
        buf.push(((hostname_bytes.len() >> 8) & 0xFF) as u8);
        buf.push((hostname_bytes.len() & 0xFF) as u8);
        buf.extend_from_slice(hostname_bytes);

        let sni = SniParser::extract_sni(&buf).unwrap();
        assert_eq!(sni, "multi-ext.example.com");
    }

    #[test]
    fn test_truncated_input() {
        // Various truncation points — none should panic
        let hello = build_client_hello("test.example.com");
        for i in 0..hello.len() {
            let _ = SniParser::extract_sni(&hello[..i]);
        }
    }

    #[test]
    fn test_empty_input() {
        assert!(SniParser::extract_sni(&[]).is_none());
        assert!(SniParser::extract_sni_from_record(&[]).is_none());
    }

    #[test]
    fn test_wrong_handshake_type() {
        let mut hello = build_client_hello("test.example.com");
        hello[0] = 0x02; // ServerHello instead of ClientHello
        assert!(SniParser::extract_sni(&hello).is_none());
    }

    #[test]
    fn test_wrong_record_content_type() {
        let hello = build_client_hello("test.example.com");
        let mut record = wrap_in_record(&hello);
        record[0] = 0x17; // Application Data instead of Handshake
        assert!(SniParser::extract_sni_from_record(&record).is_none());
    }

    #[test]
    fn test_random_bytes_no_panic() {
        // Fuzz-style: various random-ish byte patterns should never panic
        let patterns: Vec<Vec<u8>> = vec![
            vec![0xFF; 100],
            vec![0x01; 200],
            vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0xFF, 0xFF, 0xFF, 0xFF],
            (0..256).map(|i| i as u8).collect(),
        ];

        for pattern in &patterns {
            let _ = SniParser::extract_sni(pattern);
            let _ = SniParser::extract_sni_from_record(pattern);
        }
    }
}

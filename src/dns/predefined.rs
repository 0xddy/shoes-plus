//! Parsing for sing-box compatible predefined DNS resource records.
//!
//! ACP transports every record as either its zone-file text representation or
//! a base64 encoded, standalone wire-format RR.  The runtime resolver only
//! exposes an address lookup API, so records are fully validated here while
//! only A and AAAA records from the answer section are projected to addresses.

use std::io;
use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hickory_resolver::proto::rr::rdata::NULL;
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_resolver::proto::serialize::binary::{
    BinDecodable, BinDecoder, BinEncodable, BinEncoder,
};
use hickory_resolver::proto::serialize::txt::Parser;

/// A DNS message cannot carry more than 65,535 bytes.  Text/base64 has a
/// modest allowance for encoding overhead, while the aggregate cap prevents a
/// policy update from using unbounded memory before the record-count check.
const MAX_PREDEFINED_RECORDS: usize = 256;
const MAX_RECORD_INPUT_BYTES: usize = 96 * 1024;
const MAX_RECORD_WIRE_BYTES: usize = u16::MAX as usize;
const MAX_TOTAL_RECORD_INPUT_BYTES: usize = 1024 * 1024;

/// Validate predefined DNS sections and return the A/AAAA subset visible to
/// the address-only lookup API.
///
/// Records in `authority` and `additional` are validated but intentionally do
/// not affect the returned addresses, matching sing-box's `Lookup` behavior.
pub fn parse_predefined_lookup_addresses(
    answer: &[String],
    authority: &[String],
    additional: &[String],
) -> io::Result<Vec<IpAddr>> {
    let record_count = answer
        .len()
        .checked_add(authority.len())
        .and_then(|count| count.checked_add(additional.len()))
        .ok_or_else(|| invalid_record("predefined DNS record count overflow"))?;
    if record_count > MAX_PREDEFINED_RECORDS {
        return Err(invalid_record(format!(
            "predefined DNS response has {record_count} records; limit is {MAX_PREDEFINED_RECORDS}"
        )));
    }

    let mut total_input_bytes = 0usize;
    let mut addresses = Vec::new();
    for (section, records, extract_addresses) in [
        ("answer", answer, true),
        ("ns", authority, false),
        ("extra", additional, false),
    ] {
        for (index, value) in records.iter().enumerate() {
            total_input_bytes = total_input_bytes
                .checked_add(value.len())
                .ok_or_else(|| invalid_record("predefined DNS record size overflow"))?;
            if total_input_bytes > MAX_TOTAL_RECORD_INPUT_BYTES {
                return Err(invalid_record(format!(
                    "predefined DNS response exceeds {MAX_TOTAL_RECORD_INPUT_BYTES} input bytes"
                )));
            }
            let record = parse_record(value).map_err(|error| {
                invalid_record(format!(
                    "invalid {section}[{index}] resource record: {error}"
                ))
            })?;
            if extract_addresses {
                match &record.data {
                    RData::A(address) => addresses.push(IpAddr::V4(address.0)),
                    RData::AAAA(address) => addresses.push(IpAddr::V6(address.0)),
                    _ => {}
                }
            }
        }
    }
    Ok(addresses)
}

fn parse_record(value: &str) -> io::Result<Record> {
    if value.is_empty() {
        return Err(invalid_record("record must not be empty"));
    }
    if value.len() > MAX_RECORD_INPUT_BYTES {
        return Err(invalid_record(format!(
            "record is {} bytes; limit is {MAX_RECORD_INPUT_BYTES}",
            value.len()
        )));
    }

    // Go's StdEncoding ignores CR/LF but no other whitespace. sing-box then
    // calls dns.UnpackRR and intentionally ignores the returned next offset,
    // so a bounded suffix after the first complete RR is compatible input.
    let normalized_base64 = value
        .bytes()
        .filter(|byte| !matches!(byte, b'\r' | b'\n'))
        .collect::<Vec<_>>();
    if let Ok(wire) = BASE64.decode(normalized_base64) {
        let mut decoder = BinDecoder::new(&wire);
        let record = Record::read(&mut decoder)
            .map_err(|error| invalid_record(format!("invalid base64 wire RR: {error}")))?;
        validate_miekg_known_wire_record(&record)?;
        return Ok(record);
    }

    // Keep the pre-policy Rust configuration's bare-IP shorthand compatible.
    // ACP/sing-box emits full RRs, so this is an additive local extension.
    if let Ok(address) = value.parse::<IpAddr>() {
        let data = match address {
            IpAddr::V4(address) => RData::A(address.into()),
            IpAddr::V6(address) => RData::AAAA(address.into()),
        };
        return Ok(Record::from_rdata(Name::root(), 0, data));
    }

    let (_, sets) = match Parser::new(value, None, Some(Name::root())).parse() {
        Ok(parsed) => parsed,
        Err(hickory_error) => {
            return match parse_miekg_compatible_text_record(value)? {
                Some(record) => Ok(record),
                None => Err(invalid_record(format!(
                    "invalid textual RR: {hickory_error}"
                ))),
            };
        }
    };
    let mut records = sets.values().flat_map(|set| set.records_without_rrsigs());
    let record = records
        .next()
        .cloned()
        .ok_or_else(|| invalid_record("text form did not contain a resource record"))?;
    if records.next().is_some() {
        return Err(invalid_record(
            "text form must contain exactly one resource record",
        ));
    }
    Ok(record)
}

/// Text RR forms accepted by miekg/dns but not by Hickory's zone parser.
///
/// These records are retained as Hickory `Unknown` RDATA because Shoes exposes
/// only address lookup. RFC 3597 records are decoded through Hickory's wire
/// decoder so `TYPE1`/`TYPE28` still become strict, projectable A/AAAA records.
fn parse_miekg_compatible_text_record(value: &str) -> io::Result<Option<Record>> {
    let tokens = tokenize_zone_record(value)?;
    if tokens.len() < 2 {
        return Ok(None);
    }

    let name = parse_zone_name(&tokens[0], "owner name")?;
    // dns.NewRR uses the library's default TTL when the field is omitted.
    let mut ttl = 3600;
    let mut ttl_seen = false;
    let mut dns_class = DNSClass::IN;
    let mut class_seen = false;
    let mut index = 1;
    let kind = loop {
        let Some(token) = tokens.get(index) else {
            return Ok(None);
        };
        if token.quoted {
            return Ok(None);
        }
        let text = token.as_plain_ascii("RR header")?;
        if let Some(kind) = UnsupportedTextKind::parse(text) {
            index += 1;
            break kind;
        }
        if !class_seen && let Some(class) = parse_dns_class(text)? {
            dns_class = class;
            class_seen = true;
            index += 1;
            continue;
        }
        if !ttl_seen && let Some(parsed_ttl) = parse_zone_ttl(text)? {
            ttl = parsed_ttl;
            ttl_seen = true;
            index += 1;
            continue;
        }
        return Ok(None);
    };

    let header = TextRecordHeader {
        name,
        dns_class,
        ttl,
    };
    let rdata = &tokens[index..];
    let record = match kind {
        UnsupportedTextKind::Uri => unknown_record(header, 256, parse_uri_rdata(rdata)?)?,
        UnsupportedTextKind::Loc => unknown_record(header, 29, parse_loc_rdata(rdata)?)?,
        UnsupportedTextKind::Apl => unknown_record(header, 42, parse_apl_rdata(rdata)?)?,
        UnsupportedTextKind::Hip => unknown_record(header, 55, parse_hip_rdata(rdata)?)?,
        UnsupportedTextKind::Rfc3597(record_type) => {
            parse_rfc3597_record(header, record_type, rdata)?
        }
    };
    validate_miekg_known_wire_record(&record)?;
    Ok(Some(record))
}

#[derive(Debug)]
struct ZoneToken {
    raw: Vec<u8>,
    value: Vec<u8>,
    quoted: bool,
    rfc3597_marker: bool,
}

impl ZoneToken {
    fn as_ascii(&self, context: &str) -> io::Result<&str> {
        if !self.value.is_ascii() {
            return Err(invalid_record(format!("{context} must be ASCII")));
        }
        std::str::from_utf8(&self.value)
            .map_err(|_| invalid_record(format!("{context} is not valid text")))
    }

    fn as_utf8(&self, context: &str) -> io::Result<&str> {
        std::str::from_utf8(&self.value)
            .map_err(|_| invalid_record(format!("{context} contains non-UTF-8 escaped octets")))
    }

    fn as_plain_ascii(&self, context: &str) -> io::Result<&str> {
        if self.quoted || self.raw != self.value {
            return Err(invalid_record(format!(
                "{context} must be an unquoted, unescaped token"
            )));
        }
        self.as_ascii(context)
    }
}

#[derive(Debug, Clone, Copy)]
enum UnsupportedTextKind {
    Uri,
    Loc,
    Apl,
    Hip,
    Rfc3597(u16),
}

impl UnsupportedTextKind {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_uppercase().as_str() {
            "URI" => Some(Self::Uri),
            "LOC" => Some(Self::Loc),
            "APL" => Some(Self::Apl),
            "HIP" => Some(Self::Hip),
            value => value
                .strip_prefix("TYPE")
                .and_then(|value| value.parse::<u16>().ok())
                .map(Self::Rfc3597),
        }
    }
}

struct TextRecordHeader {
    name: Name,
    dns_class: DNSClass,
    ttl: u32,
}

fn tokenize_zone_record(value: &str) -> io::Result<Vec<ZoneToken>> {
    let input = value.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut parentheses = 0usize;

    while index < input.len() {
        match input[index] {
            b'\r' | b'\n' if parentheses > 0 => {
                // miekg's zone lexer ignores a physical newline inside
                // parentheses. With no indentation, a long base64/hex token
                // therefore continues on the next line (notably HIP keys).
                index += 1;
                continue;
            }
            b'\r' | b'\n' => {
                if input[index..].iter().all(u8::is_ascii_whitespace) {
                    break;
                }
                return Err(invalid_record(
                    "text form must contain exactly one logical RR",
                ));
            }
            byte if byte.is_ascii_whitespace() => {
                index += 1;
                continue;
            }
            b';' => {
                while input
                    .get(index)
                    .is_some_and(|byte| !matches!(byte, b'\r' | b'\n'))
                {
                    index += 1;
                }
                if parentheses == 0 {
                    if input[index..]
                        .iter()
                        .any(|byte| !byte.is_ascii_whitespace())
                    {
                        return Err(invalid_record(
                            "text form must contain exactly one logical RR",
                        ));
                    }
                    break;
                }
                continue;
            }
            b'(' => {
                parentheses = parentheses
                    .checked_add(1)
                    .ok_or_else(|| invalid_record("text RR parentheses nesting overflow"))?;
                index += 1;
                continue;
            }
            b')' => {
                if parentheses == 0 {
                    return Err(invalid_record("text RR has an unmatched ')'"));
                }
                parentheses -= 1;
                index += 1;
                continue;
            }
            _ => {}
        }

        let start = index;
        let quoted = input[index] == b'"';
        let mut decoded = Vec::new();
        if quoted {
            index += 1;
            loop {
                let Some(&byte) = input.get(index) else {
                    return Err(invalid_record("text RR has an unterminated quoted string"));
                };
                match byte {
                    b'"' => {
                        index += 1;
                        break;
                    }
                    b'\\' => decode_zone_escape(input, &mut index, &mut decoded)?,
                    byte => {
                        decoded.push(byte);
                        index += 1;
                    }
                }
            }
            if input.get(index).is_some_and(|byte| {
                !byte.is_ascii_whitespace() && !matches!(byte, b';' | b'(' | b')')
            }) {
                return Err(invalid_record(
                    "quoted text RR token must be followed by whitespace",
                ));
            }
        } else {
            while let Some(&byte) = input.get(index) {
                if matches!(byte, b'\r' | b'\n') && parentheses > 0 {
                    index += 1;
                    continue;
                }
                if byte.is_ascii_whitespace() || matches!(byte, b';' | b'(' | b')') {
                    break;
                }
                if byte == b'"' {
                    return Err(invalid_record(
                        "quoted text RR token must start after whitespace",
                    ));
                }
                if byte == b'\\' {
                    decode_zone_escape(input, &mut index, &mut decoded)?;
                } else {
                    decoded.push(byte);
                    index += 1;
                }
            }
        }

        let source = &input[start..index];
        let raw = if quoted {
            source.to_vec()
        } else {
            source
                .iter()
                .copied()
                .filter(|byte| !matches!(byte, b'\r' | b'\n'))
                .collect()
        };
        tokens.push(ZoneToken {
            rfc3597_marker: raw == b"\\#",
            raw,
            value: decoded,
            quoted,
        });
    }

    if parentheses != 0 {
        return Err(invalid_record("text RR has unclosed parentheses"));
    }
    Ok(tokens)
}

fn decode_zone_escape(input: &[u8], index: &mut usize, output: &mut Vec<u8>) -> io::Result<()> {
    debug_assert_eq!(input[*index], b'\\');
    let Some(&escaped) = input.get(*index + 1) else {
        return Err(invalid_record("text RR ends with an incomplete escape"));
    };
    if input
        .get(*index + 1..*index + 4)
        .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit))
    {
        let digits = &input[*index + 1..*index + 4];
        let value = u16::from(digits[0] - b'0') * 100
            + u16::from(digits[1] - b'0') * 10
            + u16::from(digits[2] - b'0');
        if value > u16::from(u8::MAX) {
            return Err(invalid_record("text RR decimal escape exceeds 255"));
        }
        output.push(value as u8);
        *index += 4;
    } else {
        output.push(escaped);
        *index += 2;
    }
    Ok(())
}

fn parse_zone_name(token: &ZoneToken, context: &str) -> io::Result<Name> {
    if token.quoted {
        return Err(invalid_record(format!("{context} must not be quoted")));
    }
    if token.raw == b"@" || token.raw == b"." {
        return Ok(Name::root());
    }

    // Parse label separators from the presentation form rather than the
    // already-decoded token. Otherwise `escaped\.label.example.` would be
    // silently changed into three labels instead of two.
    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut index = 0;
    while index < token.raw.len() {
        match token.raw[index] {
            b'.' => {
                if label.is_empty() {
                    return Err(invalid_record(format!(
                        "invalid {context}: empty DNS label"
                    )));
                }
                labels.push(std::mem::take(&mut label));
                index += 1;
                if index == token.raw.len() {
                    break;
                }
            }
            b'\\' => decode_zone_escape(&token.raw, &mut index, &mut label)?,
            byte => {
                label.push(byte);
                index += 1;
            }
        }
    }
    if !label.is_empty() {
        labels.push(label);
    }
    let mut name = Name::from_labels(labels).map_err(|error| {
        invalid_record(format!(
            "invalid {context} {:?}: {error}",
            token.as_utf8(context).unwrap_or("<escaped octets>")
        ))
    })?;
    name.set_fqdn(true);
    Ok(name)
}

fn parse_dns_class(value: &str) -> io::Result<Option<DNSClass>> {
    let value = value.to_ascii_uppercase();
    let code = match value.as_str() {
        "IN" => Some(1),
        "CS" => Some(2),
        "CH" => Some(3),
        "HS" => Some(4),
        "NONE" => Some(254),
        "ANY" => Some(255),
        value if value.starts_with("CLASS") => Some(
            value[5..]
                .parse::<u16>()
                .map_err(|_| invalid_record(format!("invalid DNS class {value:?}")))?,
        ),
        _ => None,
    };
    Ok(code.map(DNSClass::from))
}

fn parse_zone_ttl(value: &str) -> io::Result<Option<u32>> {
    if !value.as_bytes().first().is_some_and(u8::is_ascii_digit) {
        return Ok(None);
    }
    let mut total = 0u64;
    let mut current = 0u64;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            current = current
                .checked_mul(10)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                .ok_or_else(|| invalid_record(format!("DNS TTL {value:?} overflows")))?;
            continue;
        }
        let multiplier = match byte.to_ascii_lowercase() {
            b's' => 1,
            b'm' => 60,
            b'h' => 60 * 60,
            b'd' => 60 * 60 * 24,
            b'w' => 60 * 60 * 24 * 7,
            _ => return Err(invalid_record(format!("invalid DNS TTL {value:?}"))),
        };
        total = total
            .checked_add(
                current
                    .checked_mul(multiplier)
                    .ok_or_else(|| invalid_record(format!("DNS TTL {value:?} overflows")))?,
            )
            .ok_or_else(|| invalid_record(format!("DNS TTL {value:?} overflows")))?;
        current = 0;
    }
    total = total
        .checked_add(current)
        .ok_or_else(|| invalid_record(format!("DNS TTL {value:?} overflows")))?;
    Ok(Some(u32::try_from(total).map_err(|_| {
        invalid_record(format!("DNS TTL {value:?} exceeds uint32"))
    })?))
}

fn unknown_record(
    header: TextRecordHeader,
    record_type: u16,
    rdata: Vec<u8>,
) -> io::Result<Record> {
    if rdata.len() > MAX_RECORD_WIRE_BYTES {
        return Err(invalid_record(format!(
            "text RR RDATA is {} bytes; limit is {MAX_RECORD_WIRE_BYTES}",
            rdata.len()
        )));
    }
    let null = if rdata.is_empty() {
        NULL::new()
    } else {
        NULL::with(rdata)
    };
    let mut record = Record::from_rdata(
        header.name,
        header.ttl,
        RData::Unknown {
            code: RecordType::Unknown(record_type),
            rdata: null,
        },
    );
    record.dns_class = header.dns_class;
    Ok(record)
}

/// Hickory intentionally stores unsupported RR types as opaque `Unknown`
/// bytes. miekg/dns instead has concrete decoders for these four types, so
/// validate the same wire boundaries before accepting either base64 or RFC
/// 3597 input. Zero-length known records remain valid dynamic-update records;
/// Hickory represents those as `Update0`, which is deliberately not projected
/// as an A/AAAA lookup result.
fn validate_miekg_known_wire_record(record: &Record) -> io::Result<()> {
    let RData::Unknown { code, rdata } = &record.data else {
        return Ok(());
    };
    let code = u16::from(*code);
    let result = match code {
        29 => validate_loc_wire_rdata(&rdata.anything),
        42 => validate_apl_wire_rdata(&rdata.anything),
        55 => validate_hip_wire_rdata(&rdata.anything),
        256 => validate_uri_wire_rdata(&rdata.anything),
        _ => Ok(()),
    };
    result.map_err(|error| invalid_record(format!("invalid TYPE{code} wire RDATA: {error}")))
}

fn validate_uri_wire_rdata(rdata: &[u8]) -> io::Result<()> {
    // The generated miekg decoder may stop after either fixed-width field;
    // once both are present, every remaining octet belongs to Target.
    if matches!(rdata.len(), 0 | 2 | 4) || rdata.len() > 4 {
        Ok(())
    } else {
        Err(invalid_record(
            "URI RDATA must be empty, 2 bytes, or at least 4 bytes",
        ))
    }
}

fn validate_loc_wire_rdata(rdata: &[u8]) -> io::Result<()> {
    // miekg's generated decoder accepts termination after each LOC field.
    if matches!(rdata.len(), 0 | 1 | 2 | 3 | 4 | 8 | 12 | 16) {
        Ok(())
    } else {
        Err(invalid_record(
            "LOC RDATA ends in the middle of a fixed-width field",
        ))
    }
}

fn validate_apl_wire_rdata(rdata: &[u8]) -> io::Result<()> {
    let mut offset = 0usize;
    while offset < rdata.len() {
        let header = rdata
            .get(offset..offset + 4)
            .ok_or_else(|| invalid_record("APL prefix header is truncated"))?;
        let family = u16::from_be_bytes([header[0], header[1]]);
        let prefix = header[2];
        let address_length = usize::from(header[3] & 0x7f);
        let (maximum_prefix, maximum_address_length) = match family {
            1 => (32, 4),
            2 => (128, 16),
            _ => return Err(invalid_record("APL address family must be 1 or 2")),
        };
        if prefix > maximum_prefix {
            return Err(invalid_record(
                "APL prefix length exceeds its address family",
            ));
        }
        if address_length > maximum_address_length {
            return Err(invalid_record(
                "APL address length exceeds its address family",
            ));
        }
        offset += 4;
        let address = rdata
            .get(offset..offset + address_length)
            .ok_or_else(|| invalid_record("APL address is truncated"))?;
        if address.last() == Some(&0) {
            return Err(invalid_record(
                "APL address must not contain a trailing zero octet",
            ));
        }
        offset += address_length;
    }
    Ok(())
}

fn validate_hip_wire_rdata(rdata: &[u8]) -> io::Result<()> {
    match rdata.len() {
        0 | 1 | 2 | 4 => return Ok(()),
        3 => return Err(invalid_record("HIP public-key length is truncated")),
        _ => {}
    }

    let hit_length = usize::from(rdata[0]);
    let public_key_length = usize::from(u16::from_be_bytes([rdata[2], rdata[3]]));
    let rendezvous_offset = 4usize
        .checked_add(hit_length)
        .and_then(|offset| offset.checked_add(public_key_length))
        .filter(|offset| *offset <= rdata.len())
        .ok_or_else(|| invalid_record("HIP HIT or public key exceeds RDLENGTH"))?;

    let mut decoder = BinDecoder::new(rdata);
    decoder
        .read_slice(rendezvous_offset)
        .map_err(|error| invalid_record(format!("HIP fixed data is truncated: {error}")))?;
    while !decoder.is_empty() {
        let start = decoder.index();
        Name::read(&mut decoder)
            .map_err(|error| invalid_record(format!("invalid HIP rendezvous name: {error}")))?;
        if decoder.index() <= start {
            return Err(invalid_record("HIP rendezvous name made no progress"));
        }
    }
    Ok(())
}

fn parse_rfc3597_record(
    header: TextRecordHeader,
    record_type: u16,
    tokens: &[ZoneToken],
) -> io::Result<Record> {
    if tokens.len() < 2 || !tokens[0].rfc3597_marker || tokens[0].quoted {
        return Err(invalid_record(
            "RFC3597 RDATA must start with the escaped marker \\#",
        ));
    }
    let declared_length = tokens[1]
        .as_plain_ascii("RFC3597 RDLENGTH")?
        .parse::<u16>()
        .map_err(|_| invalid_record("RFC3597 RDLENGTH must be a uint16"))?;
    let mut hexadecimal = Vec::new();
    for token in &tokens[2..] {
        if token.quoted {
            return Err(invalid_record(
                "RFC3597 hexadecimal RDATA must not be quoted",
            ));
        }
        if token.raw != token.value {
            return Err(invalid_record(
                "RFC3597 hexadecimal RDATA must not contain escapes",
            ));
        }
        hexadecimal.extend_from_slice(&token.raw);
    }
    let expected_hex_length = usize::from(declared_length) * 2;
    if hexadecimal.len() != expected_hex_length {
        return Err(invalid_record(format!(
            "RFC3597 RDLENGTH is {declared_length}, but hexadecimal RDATA has {} digits",
            hexadecimal.len()
        )));
    }
    let rdata = decode_hex(&hexadecimal, "RFC3597 RDATA")?;

    // Emit an Unknown record and decode it again. Hickory then validates known
    // TYPE codes and turns TYPE1/TYPE28 into the same A/AAAA variants used by
    // ordinary textual records.
    let unknown = unknown_record(header, record_type, rdata)?;
    let mut wire = Vec::new();
    unknown
        .emit(&mut BinEncoder::new(&mut wire))
        .map_err(|error| invalid_record(format!("cannot encode RFC3597 RR: {error}")))?;
    let mut decoder = BinDecoder::new(&wire);
    let record = Record::read(&mut decoder)
        .map_err(|error| invalid_record(format!("invalid RFC3597 RR wire data: {error}")))?;
    if !decoder.is_empty() {
        return Err(invalid_record("RFC3597 RR decoder left trailing bytes"));
    }
    Ok(record)
}

fn parse_uri_rdata(tokens: &[ZoneToken]) -> io::Result<Vec<u8>> {
    if tokens.len() != 3 {
        return Err(invalid_record(
            "URI RDATA requires priority, weight, and exactly one target",
        ));
    }
    let priority = parse_decimal::<u16>(&tokens[0], "URI priority")?;
    let weight = parse_decimal::<u16>(&tokens[1], "URI weight")?;
    if tokens[2].value.len() > usize::from(u8::MAX) {
        return Err(invalid_record(format!(
            "URI text target is {} decoded bytes; limit is 255",
            tokens[2].value.len()
        )));
    }
    let mut rdata = Vec::with_capacity(4 + tokens[2].value.len());
    rdata.extend_from_slice(&priority.to_be_bytes());
    rdata.extend_from_slice(&weight.to_be_bytes());
    rdata.extend_from_slice(&tokens[2].value);
    Ok(rdata)
}

fn parse_loc_rdata(tokens: &[ZoneToken]) -> io::Result<Vec<u8>> {
    let mut index = 0;
    let latitude = parse_loc_coordinate(tokens, &mut index, 90, b'n', b's', "latitude")?;
    let longitude = parse_loc_coordinate(tokens, &mut index, 180, b'e', b'w', "longitude")?;
    let altitude_token = tokens
        .get(index)
        .ok_or_else(|| invalid_record("LOC RDATA is missing altitude"))?;
    let altitude = parse_loc_altitude(altitude_token)?;
    index += 1;

    let mut precision = [0x12, 0x16, 0x13];
    let optional = &tokens[index..];
    if optional.len() > precision.len() {
        return Err(invalid_record(
            "LOC RDATA has more than size, horizontal precision, and vertical precision",
        ));
    }
    for (target, token) in precision.iter_mut().zip(optional) {
        *target = parse_loc_centimeters(token)?;
    }

    let mut rdata = Vec::with_capacity(16);
    rdata.extend_from_slice(&[0, precision[0], precision[1], precision[2]]);
    rdata.extend_from_slice(&latitude.to_be_bytes());
    rdata.extend_from_slice(&longitude.to_be_bytes());
    rdata.extend_from_slice(&altitude.to_be_bytes());
    Ok(rdata)
}

fn parse_loc_coordinate(
    tokens: &[ZoneToken],
    index: &mut usize,
    maximum_degrees: u32,
    positive: u8,
    negative: u8,
    context: &str,
) -> io::Result<u32> {
    let degrees = parse_decimal::<u32>(
        tokens
            .get(*index)
            .ok_or_else(|| invalid_record(format!("LOC {context} is missing")))?,
        &format!("LOC {context} degrees"),
    )?;
    *index += 1;
    if degrees > maximum_degrees {
        return Err(invalid_record(format!(
            "LOC {context} degrees exceed {maximum_degrees}"
        )));
    }

    let mut thousandths = u64::from(degrees) * 60 * 60 * 1000;
    let mut direction = direction_token(tokens.get(*index), positive, negative);
    if direction.is_none() {
        let minutes = parse_decimal::<u32>(
            tokens
                .get(*index)
                .ok_or_else(|| invalid_record(format!("LOC {context} minutes are missing")))?,
            &format!("LOC {context} minutes"),
        )?;
        if minutes > 59 {
            return Err(invalid_record(format!(
                "LOC {context} minutes must be in 0..=59"
            )));
        }
        *index += 1;
        let seconds_token = tokens
            .get(*index)
            .ok_or_else(|| invalid_record(format!("LOC {context} seconds are missing")))?;
        let seconds = parse_f64(seconds_token, &format!("LOC {context} seconds"))?;
        if !(0.0..60.0).contains(&seconds) {
            return Err(invalid_record(format!(
                "LOC {context} seconds must be in [0, 60)"
            )));
        }
        thousandths += u64::from(minutes) * 60 * 1000 + (seconds * 1000.0) as u64;
        *index += 1;
        direction = direction_token(tokens.get(*index), positive, negative);
    }
    let direction =
        direction.ok_or_else(|| invalid_record(format!("LOC {context} direction is invalid")))?;
    *index += 1;

    let maximum = u64::from(maximum_degrees) * 60 * 60 * 1000;
    if thousandths > maximum {
        return Err(invalid_record(format!(
            "LOC {context} exceeds {maximum_degrees} degrees"
        )));
    }
    let offset = u32::try_from(thousandths)
        .map_err(|_| invalid_record(format!("LOC {context} overflows wire format")))?;
    const EQUATOR: u32 = 1 << 31;
    Ok(if direction {
        EQUATOR + offset
    } else {
        EQUATOR - offset
    })
}

fn direction_token(token: Option<&ZoneToken>, positive: u8, negative: u8) -> Option<bool> {
    let token = token?;
    if token.quoted || token.raw != token.value || token.value.len() != 1 {
        return None;
    }
    let direction = token.value[0].to_ascii_lowercase();
    if direction == positive {
        Some(true)
    } else if direction == negative {
        Some(false)
    } else {
        None
    }
}

fn parse_loc_altitude(token: &ZoneToken) -> io::Result<u32> {
    let value = strip_meter_suffix(token.as_plain_ascii("LOC altitude")?);
    let meters = value
        .parse::<f64>()
        .map_err(|_| invalid_record(format!("invalid LOC altitude {value:?}")))?;
    if !meters.is_finite() {
        return Err(invalid_record("LOC altitude must be finite"));
    }
    let encoded = meters.mul_add(100.0, 10_000_000.5).floor();
    if !(0.0..=f64::from(u32::MAX)).contains(&encoded) {
        return Err(invalid_record("LOC altitude is outside the wire range"));
    }
    Ok(encoded as u32)
}

fn parse_loc_centimeters(token: &ZoneToken) -> io::Result<u8> {
    let value = strip_meter_suffix(token.as_plain_ascii("LOC precision")?);
    let (meters, centimeters) = match value.split_once('.') {
        Some((meters, centimeters)) => {
            if centimeters.is_empty()
                || centimeters.len() > 2
                || !centimeters.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid_record(format!("invalid LOC precision {value:?}")));
            }
            let centimeters = centimeters
                .parse::<u32>()
                .map_err(|_| invalid_record(format!("invalid LOC precision {value:?}")))?
                * if centimeters.len() == 1 { 10 } else { 1 };
            let meters = if meters.is_empty() {
                0
            } else {
                parse_unsigned_decimal::<u32>(meters, "LOC precision")?
            };
            (meters, centimeters)
        }
        None => (parse_unsigned_decimal::<u32>(value, "LOC precision")?, 0),
    };
    if meters > 90_000_000 || (meters == 90_000_000 && centimeters != 0) {
        return Err(invalid_record("LOC precision exceeds 90000000m"));
    }

    let (mut exponent, mut mantissa) = if meters > 0 {
        (2u8, meters)
    } else {
        (0u8, centimeters)
    };
    while mantissa >= 10 {
        exponent = exponent
            .checked_add(1)
            .ok_or_else(|| invalid_record("LOC precision exponent overflow"))?;
        mantissa /= 10;
    }
    if exponent > 9 || mantissa > 9 {
        return Err(invalid_record("LOC precision cannot be represented"));
    }
    Ok((mantissa as u8) << 4 | exponent)
}

fn strip_meter_suffix(value: &str) -> &str {
    value
        .strip_suffix('m')
        .or_else(|| value.strip_suffix('M'))
        .unwrap_or(value)
}

fn parse_apl_rdata(tokens: &[ZoneToken]) -> io::Result<Vec<u8>> {
    let mut rdata = Vec::new();
    for token in tokens {
        if token.quoted {
            return Err(invalid_record("APL prefixes must not be quoted"));
        }
        let value = token.as_plain_ascii("APL prefix")?;
        let (family, network) = value
            .split_once(':')
            .ok_or_else(|| invalid_record(format!("APL prefix {value:?} is missing ':'")))?;
        if network.contains(':') && !network.contains('/') {
            return Err(invalid_record(format!(
                "APL prefix {value:?} is missing '/'"
            )));
        }
        let (negated, family) = family
            .strip_prefix('!')
            .map_or((false, family), |family| (true, family));
        let family = parse_unsigned_decimal::<u16>(family, "APL address family")?;
        let (address, prefix) = network
            .rsplit_once('/')
            .ok_or_else(|| invalid_record(format!("APL prefix {value:?} is missing '/'")))?;
        if address.is_empty() || prefix.is_empty() || prefix.contains('/') {
            return Err(invalid_record(format!("invalid APL prefix {value:?}")));
        }
        let address = address
            .parse::<IpAddr>()
            .map_err(|error| invalid_record(format!("invalid APL address {address:?}: {error}")))?;
        let prefix = parse_unsigned_decimal::<u8>(prefix, "APL prefix length")?;

        let (expected_family, maximum_prefix, mut bytes) = match address {
            IpAddr::V4(address) => (1, 32, address.octets().to_vec()),
            IpAddr::V6(address) => (2, 128, address.octets().to_vec()),
        };
        if family != expected_family {
            return Err(invalid_record(format!(
                "APL family {family} does not match address {address}"
            )));
        }
        if prefix > maximum_prefix {
            return Err(invalid_record(format!(
                "APL prefix length {prefix} exceeds {maximum_prefix}"
            )));
        }
        if !ip_has_zero_host_bits(address, prefix) {
            return Err(invalid_record(format!(
                "APL address {address}/{prefix} contains host bits"
            )));
        }
        while bytes.last() == Some(&0) {
            bytes.pop();
        }
        let address_length = u8::try_from(bytes.len())
            .map_err(|_| invalid_record("APL address encoding is too long"))?;
        rdata.extend_from_slice(&family.to_be_bytes());
        rdata.push(prefix);
        rdata.push(address_length | if negated { 0x80 } else { 0 });
        rdata.extend_from_slice(&bytes);
    }
    Ok(rdata)
}

fn ip_has_zero_host_bits(address: IpAddr, prefix: u8) -> bool {
    match address {
        IpAddr::V4(address) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(address) & mask == u32::from(address)
        }
        IpAddr::V6(address) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            u128::from(address) & mask == u128::from(address)
        }
    }
}

fn parse_hip_rdata(tokens: &[ZoneToken]) -> io::Result<Vec<u8>> {
    if tokens.len() < 3 {
        return Err(invalid_record(
            "HIP RDATA requires algorithm, HIT, and public key",
        ));
    }
    let algorithm = parse_decimal::<u8>(&tokens[0], "HIP public-key algorithm")?;
    if tokens[1].quoted || tokens[2].quoted {
        return Err(invalid_record("HIP HIT and public key must not be quoted"));
    }
    let hit = decode_hex(tokens[1].as_plain_ascii("HIP HIT")?.as_bytes(), "HIP HIT")?;
    if hit.is_empty() {
        return Err(invalid_record("HIP HIT must not be empty"));
    }
    let hit_length =
        u8::try_from(hit.len()).map_err(|_| invalid_record("HIP HIT exceeds 255 bytes"))?;
    let public_key = BASE64
        .decode(tokens[2].as_plain_ascii("HIP public key")?)
        .map_err(|error| invalid_record(format!("invalid HIP public key base64: {error}")))?;
    if tokens[2].raw.is_empty() {
        return Err(invalid_record("HIP public key must not be empty"));
    }
    let public_key_length = u16::try_from(public_key.len())
        .map_err(|_| invalid_record("HIP public key exceeds 65535 bytes"))?;

    let mut rdata = Vec::new();
    rdata.push(hit_length);
    rdata.push(algorithm);
    rdata.extend_from_slice(&public_key_length.to_be_bytes());
    rdata.extend_from_slice(&hit);
    rdata.extend_from_slice(&public_key);
    for token in &tokens[3..] {
        let name = parse_zone_name(token, "HIP rendezvous server")?;
        let mut encoded = Vec::new();
        name.emit(&mut BinEncoder::new(&mut encoded))
            .map_err(|error| {
                invalid_record(format!("invalid HIP rendezvous server wire name: {error}"))
            })?;
        rdata.extend_from_slice(&encoded);
    }
    Ok(rdata)
}

fn parse_decimal<T>(token: &ZoneToken, context: &str) -> io::Result<T>
where
    T: std::str::FromStr,
{
    if token.quoted {
        return Err(invalid_record(format!("{context} must not be quoted")));
    }
    parse_unsigned_decimal(token.as_plain_ascii(context)?, context)
}

fn parse_unsigned_decimal<T>(value: &str, context: &str) -> io::Result<T>
where
    T: std::str::FromStr,
{
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_record(format!(
            "{context} must be an unsigned decimal"
        )));
    }
    value
        .parse::<T>()
        .map_err(|_| invalid_record(format!("{context} is out of range")))
}

fn parse_f64(token: &ZoneToken, context: &str) -> io::Result<f64> {
    if token.quoted {
        return Err(invalid_record(format!("{context} must not be quoted")));
    }
    let value = token.as_plain_ascii(context)?;
    value
        .parse::<f64>()
        .map_err(|_| invalid_record(format!("invalid {context} {value:?}")))
}

fn decode_hex(value: &[u8], context: &str) -> io::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(invalid_record(format!(
            "{context} must contain an even number of hexadecimal digits"
        )));
    }
    value
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0]).ok_or_else(|| {
                invalid_record(format!("{context} contains non-hexadecimal data"))
            })?;
            let low = hex_digit(pair[1]).ok_or_else(|| {
                invalid_record(format!("{context} contains non-hexadecimal data"))
            })?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn invalid_record(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_resolver::proto::rr::rdata::{A, AAAA};
    use hickory_resolver::proto::serialize::binary::{BinEncodable, BinEncoder};

    use super::*;

    fn wire_record(record: &Record) -> String {
        let mut bytes = Vec::new();
        record.emit(&mut BinEncoder::new(&mut bytes)).unwrap();
        BASE64.encode(bytes)
    }

    fn unknown_wire_record(record_type: u16, rdata: Vec<u8>) -> String {
        let record = unknown_record(
            TextRecordHeader {
                name: Name::from_ascii("wire.example.").unwrap(),
                dns_class: DNSClass::IN,
                ttl: 60,
            },
            record_type,
            rdata,
        )
        .unwrap();
        wire_record(&record)
    }

    #[test]
    fn extracts_only_supported_answer_addresses_from_full_text_records() {
        let answers = vec![
            "example.test. 60 IN A 192.0.2.8".to_string(),
            "example.test. 60 IN TXT \"ignored\"".to_string(),
            "example.test. 60 IN AAAA 2001:db8::8".to_string(),
        ];
        let authority = vec!["example.test. 60 IN NS ns.example.test.".to_string()];
        let additional = vec!["ns.example.test. 60 IN A 192.0.2.53".to_string()];

        assert_eq!(
            parse_predefined_lookup_addresses(&answers, &authority, &additional).unwrap(),
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)),
                IpAddr::V6("2001:db8::8".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn validates_https_address_hints_without_projecting_them() {
        let answers = vec![
            "example.test. 60 IN HTTPS 1 . ipv4hint=192.0.2.10,192.0.2.11 ipv6hint=2001:db8::10,2001:db8::11"
                .to_string(),
        ];

        assert!(
            parse_predefined_lookup_addresses(&answers, &[], &[])
                .unwrap()
                .is_empty(),
            "sing-box's predefined Lookup path projects only A and AAAA"
        );
    }

    #[test]
    fn parses_base64_wire_records_with_crlf_and_ignores_bounded_trailing_bytes() {
        let a = Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 7))),
        );
        let aaaa = Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            60,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        );
        let answers = vec![wire_record(&a), wire_record(&aaaa)];
        assert_eq!(
            parse_predefined_lookup_addresses(&answers, &[], &[]).unwrap(),
            [
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]
        );

        let mut with_trailing = BASE64.decode(&answers[0]).unwrap();
        with_trailing.extend_from_slice(&[0xde, 0xad, 0xbe]);
        let encoded = BASE64.encode(with_trailing);
        let wrapped = format!("{}\r\n{}\n", &encoded[..20], &encoded[20..]);
        assert_eq!(
            parse_predefined_lookup_addresses(&[wrapped], &[], &[]).unwrap(),
            [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))]
        );
    }

    #[test]
    fn accepts_strict_miekg_compatible_text_records() {
        let ignored_records = [
            "svcb.example. 60 IN SVCB 1 . ipv4hint=192.0.2.44 ipv6hint=2001:db8::44",
            r#"uri.example. 1h IN URI 10 20 "https://example.test/a b""#,
            "loc.example. 60 IN LOC 37 47 0.0 N 122 23 0.0 W 10m 1m 10000m 10m",
            "apl.example. 60 IN APL 1:192.0.2.0/24 !2:2001:db8::/32",
            "hip.example. 60 IN HIP 2 200100107B1A74DF365639CC39F1D578 AQID rvs.example.test.",
            "hip-multiline.example. IN HIP ( 2 200100107B1A74DF365639CC39F1D578 AQ\nID\n rvs.example.test. )",
            r"unknown.example. 60 IN TYPE65400 \# 4 DEADBEEF",
            r"generic-uri.example. 60 IN TYPE256 \# 5 000A001478",
            r"generic-loc.example. 60 IN TYPE29 \# 16 00121613800000008000000000989680",
            r"generic-apl.example. 60 IN TYPE42 \# 7 00011803C00002",
            r"generic-hip.example. 60 IN TYPE55 \# 23 10020003200100107B1A74DF365639CC39F1D578010203",
            r"empty-a.example. 60 IN TYPE1 \# 0",
        ];
        for record in ignored_records {
            assert_eq!(
                parse_predefined_lookup_addresses(&[record.to_string()], &[], &[]).unwrap(),
                Vec::<IpAddr>::new(),
                "record should validate without projecting an address: {record}"
            );
        }

        assert_eq!(
            parse_predefined_lookup_addresses(
                &[
                    r"a.example. 60 IN TYPE1 \# 4 C0000209".to_string(),
                    r"aaaa.example. 60 IN TYPE28 \# 16 20010DB8000000000000000000000009"
                        .to_string(),
                ],
                &[],
                &[],
            )
            .unwrap(),
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
                IpAddr::V6("2001:db8::9".parse().unwrap()),
            ]
        );

        assert_eq!(
            parse_predefined_lookup_addresses(&[unknown_wire_record(1, Vec::new())], &[], &[])
                .unwrap(),
            Vec::<IpAddr>::new(),
            "zero-RDLENGTH A is an update record, not a lookup address"
        );
    }

    #[test]
    fn validates_known_unknown_wire_rdata_for_base64_and_rfc3597() {
        let mut valid_hip = vec![16, 2, 0, 3];
        valid_hip
            .extend_from_slice(&decode_hex(b"200100107B1A74DF365639CC39F1D578", "test").unwrap());
        valid_hip.extend_from_slice(&[1, 2, 3]);
        let valid = [
            (256, vec![0, 10, 0, 20, b'x']),
            (
                29,
                vec![
                    0, 0x12, 0x16, 0x13, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x98, 0x96, 0x80,
                ],
            ),
            (42, vec![0, 1, 24, 3, 192, 0, 2]),
            (55, valid_hip),
        ];
        for (record_type, rdata) in valid {
            assert_eq!(
                parse_predefined_lookup_addresses(
                    &[unknown_wire_record(record_type, rdata)],
                    &[],
                    &[],
                )
                .unwrap(),
                Vec::<IpAddr>::new(),
                "valid TYPE{record_type} wire RDATA"
            );
        }

        for (record_type, rdata) in [
            (256, vec![0]),
            (29, vec![0; 5]),
            (42, vec![0, 1, 24, 3, 192, 0, 0]),
            (55, vec![2, 2, 0, 0, 0]),
        ] {
            let hexadecimal = rdata
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            let values = [
                unknown_wire_record(record_type, rdata.clone()),
                format!(
                    "bad.example. 60 IN TYPE{record_type} \\# {} {hexadecimal}",
                    rdata.len()
                ),
            ];
            for value in values {
                let error = parse_predefined_lookup_addresses(&[value], &[], &[]).unwrap_err();
                assert!(
                    error.to_string().contains(&format!("TYPE{record_type}")),
                    "unexpected error for malformed TYPE{record_type}: {error}"
                );
            }
        }
    }

    #[test]
    fn uri_text_target_is_255_bytes_but_wire_target_is_not_character_string_limited() {
        let text_255 = format!("uri.example. IN URI 1 1 \"{}\"", "x".repeat(255));
        assert!(
            parse_predefined_lookup_addresses(&[text_255], &[], &[])
                .unwrap()
                .is_empty()
        );

        let text_256 = format!("uri.example. IN URI 1 1 \"{}\"", "x".repeat(256));
        let error = parse_predefined_lookup_addresses(&[text_256], &[], &[]).unwrap_err();
        assert!(error.to_string().contains("limit is 255"), "{error}");

        let mut wire_rdata = vec![0, 1, 0, 1];
        wire_rdata.extend(std::iter::repeat_n(b'x', 256));
        assert!(
            parse_predefined_lookup_addresses(&[unknown_wire_record(256, wire_rdata)], &[], &[],)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn miekg_fallback_preserves_default_header_and_escaped_owner_labels() {
        let record =
            parse_record(r#"escaped\.owner.example. CS URI 10 20 "https://example.test/""#)
                .unwrap();

        assert_eq!(record.ttl, 3600);
        assert_eq!(record.dns_class, DNSClass::from(2));
        assert_eq!(
            record.name.iter().collect::<Vec<_>>(),
            [b"escaped.owner".as_slice(), b"example".as_slice()]
        );
    }

    #[test]
    fn rejects_malformed_miekg_compatible_text_records() {
        for record in [
            r#"uri.example. 60 IN URI 65536 1 "https://example.test/""#,
            r#"uri.example. 60 IN URI \061 1 "https://example.test/""#,
            r#"uri.example. 60 IN URI 1 1 "one" "two""#,
            "loc.example. 60 IN LOC 91 0 0 N 0 0 0 E 0m",
            "loc.example. 60 IN LOC 1 0 0 X 0 0 0 E 0m",
            "apl.example. 60 IN APL 1:192.0.2.1/24",
            "apl.example. 60 IN APL 2:192.0.2.0/24",
            "hip.example. 60 IN HIP 2 ABC AQID",
            "hip.example. 60 IN HIP 2 200100107B1A74DF365639CC39F1D578 not-base64",
            r"unknown.example. 60 IN TYPE65400 \# 5 DEADBEEF",
            r"unknown.example. 60 IN TYPE65400 \# 2 ZZZZ",
            r"a.example. 60 IN TYPE1 \# 5 C000020900",
        ] {
            let error =
                parse_predefined_lookup_addresses(&[record.to_string()], &[], &[]).unwrap_err();
            assert!(
                error.to_string().contains("resource record"),
                "unexpected error for {record}: {error}"
            );
        }
    }

    #[test]
    fn preserves_bare_ip_compatibility_and_bounds_record_count() {
        let answers = vec!["203.0.113.9".to_string(), "2001:db8::9".to_string()];
        assert_eq!(
            parse_predefined_lookup_addresses(&answers, &[], &[]).unwrap(),
            [
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                IpAddr::V6("2001:db8::9".parse().unwrap()),
            ]
        );

        let too_many = vec!["example.test. 0 IN TXT \"x\"".to_string(); 257];
        let error = parse_predefined_lookup_addresses(&too_many, &[], &[]).unwrap_err();
        assert!(error.to_string().contains("limit is 256"));
    }
}

//! Exercise Apple's packet framing without changing host routes or using root.
use crate::dispatcher::{read_utun_packet, write_utun_packet};
use std::os::{fd::AsRawFd, unix::net::UnixDatagram};

#[test]
fn utun_read_strips_address_family_without_truncating_ip_packet() {
    let (reader, writer) = UnixDatagram::pair().unwrap();
    let packet = [0x45, 0, 0, 20, 1, 2, 3, 4];
    let mut framed = (libc::AF_INET as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&packet);
    writer.send(&framed).unwrap();
    let mut output = [0u8; 32];
    let count = read_utun_packet(reader.as_raw_fd(), &mut output).unwrap();
    assert_eq!(&output[..count], &packet);
}

#[test]
fn utun_write_emits_one_datagram_with_ipv4_or_ipv6_family() {
    for (version, family) in [(0x45, libc::AF_INET), (0x60, libc::AF_INET6)] {
        let (reader, writer) = UnixDatagram::pair().unwrap();
        let packet = [version, 0, 0, 20, 1, 2, 3, 4];
        let count = write_utun_packet(writer.as_raw_fd(), &packet).unwrap();
        assert_eq!(count, packet.len());
        let mut output = [0u8; 32];
        let received = reader.recv(&mut output).unwrap();
        assert_eq!(received, packet.len() + 4);
        assert_eq!(&output[..4], &(family as u32).to_be_bytes());
        assert_eq!(&output[4..received], &packet);
    }
}

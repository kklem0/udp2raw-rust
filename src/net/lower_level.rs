//! `--lower-level auto`: find the interface and next-hop MAC for a destination from
//! `/proc/net/route` and `/proc/net/arp` — `find_lower_level_info`.

use super::addr::interface_has_arp;
use std::net::Ipv4Addr;

struct Route {
    if_name: String,
    dest: u32,
    mask: u32,
    gw: u32,
    flags: u32,
}

fn parse_hex_addr(s: &str) -> Option<u32> {
    // /proc/net/route prints the in_addr bytes as a little-endian hex number.
    let v = u32::from_str_radix(s, 16).ok()?;
    Some(u32::from(Ipv4Addr::from(v.to_le_bytes())))
}

fn parse_routes(text: &str) -> Result<Vec<Route>, String> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        if f.len() != 11 {
            return Err(format!("route coloum {} !=11", f.len()));
        }
        out.push(Route {
            if_name: f[0].to_string(),
            dest: parse_hex_addr(f[1]).ok_or("bad dest")?,
            gw: parse_hex_addr(f[2]).ok_or("bad gw")?,
            flags: u32::from_str_radix(f[3], 16).map_err(|_| "bad flags")?,
            mask: parse_hex_addr(f[7]).ok_or("bad mask")?,
        });
    }
    Ok(out)
}

/// Longest-prefix match, then follow gateways until a directly reachable address.
fn find_direct_dest(routes: &[Route], mut ip: u32) -> Result<(u32, String), String> {
    for _ in 0..1000 {
        let mut hits: Vec<&Route> = Vec::new();
        for i in 0..=32u32 {
            let mask = if i == 32 { 0 } else { 0xffff_ffffu32 << i };
            hits = routes.iter().filter(|r| r.mask == mask && (r.dest & mask) == (ip & mask)).collect();
            if !hits.is_empty() {
                break;
            }
        }
        if hits.is_empty() {
            return Err("cant find route entry".into());
        }
        if hits.len() > 1 {
            return Err("found duplicated entries".into());
        }
        let r = hits[0];
        if r.flags & 2 == 0 {
            return Ok((ip, r.if_name.clone()));
        }
        ip = r.gw;
    }
    Err("dead loop in find_direct_dest".into())
}

fn find_arp(text: &str, ip: Ipv4Addr, if_name: &str) -> Result<[u8; 6], String> {
    let mut found: Vec<[u8; 6]> = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        if f.len() != 6 {
            return Err(format!("arp coloum {} !=6", f.len()));
        }
        if f[5] != if_name {
            continue;
        }
        let Ok(a) = f[0].parse::<Ipv4Addr>() else { continue };
        if a == ip {
            found.push(parse_mac(f[3])?);
        }
    }
    match found.len() {
        0 => Err(format!("cant find arp entry for {ip} {if_name}")),
        1 => Ok(found[0]),
        _ => Err(format!("find multiple arp entry for {ip} {if_name}")),
    }
}

fn parse_mac(s: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("bad mac {s}"));
    }
    let mut m = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        m[i] = u8::from_str_radix(p, 16).map_err(|_| format!("bad mac {s}"))?;
    }
    Ok(m)
}

/// Returns (next-hop ip, interface name, next-hop mac).
pub fn find_lower_level_info(ip: Ipv4Addr) -> Result<(Ipv4Addr, String, [u8; 6]), String> {
    if ip == Ipv4Addr::LOCALHOST {
        return Ok((ip, "lo".into(), [0; 6]));
    }
    let route_text = std::fs::read_to_string("/proc/net/route").map_err(|e| format!("read_file /proc/net/route fail: {e}"))?;
    let arp_text = std::fs::read_to_string("/proc/net/arp").map_err(|e| format!("read_file /proc/net/arp fail: {e}"))?;
    let routes = parse_routes(&route_text)?;
    let (dest, if_name) = find_direct_dest(&routes, u32::from(ip)).map_err(|e| format!("find_direct_dest failed for ip {ip}: {e}"))?;
    let dest = Ipv4Addr::from(dest);
    let has_arp = interface_has_arp(&if_name).map_err(|e| format!("SIOCGIFFLAGS failed for {if_name}: {e}"))?;
    let mac = if !has_arp {
        log::info!("{if_name} is a noarp interface,using 00:00:00:00:00:00");
        [0; 6]
    } else {
        find_arp(&arp_text, dest, &if_name)?
    };
    Ok((dest, if_name, mac))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
    const ARP: &str = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.0.1      0x1         0x2         00:23:45:67:89:b9     *        eth0\n";

    #[test]
    fn default_route_via_gateway() {
        let routes = parse_routes(ROUTE).unwrap();
        let (dest, ifn) = find_direct_dest(&routes, u32::from(Ipv4Addr::new(8, 8, 8, 8))).unwrap();
        assert_eq!(Ipv4Addr::from(dest), Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(ifn, "eth0");
        let (dest, _) = find_direct_dest(&routes, u32::from(Ipv4Addr::new(192, 168, 0, 7))).unwrap();
        assert_eq!(Ipv4Addr::from(dest), Ipv4Addr::new(192, 168, 0, 7));
        assert_eq!(find_arp(ARP, Ipv4Addr::new(192, 168, 0, 1), "eth0").unwrap(), [0x00, 0x23, 0x45, 0x67, 0x89, 0xb9]);
        assert!(find_arp(ARP, Ipv4Addr::new(192, 168, 0, 2), "eth0").is_err());
    }
}

use zerocopy::{byteorder::little_endian as le, *};

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes)]
#[repr(C)]
pub struct TcbVersionMilanGenoa {
    pub boot_loader: u8,
    pub tee: u8,
    reserved: [u8; 4],
    pub snp: u8,
    pub microcode: u8,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes)]
#[repr(C)]
pub struct TcbVersionTurin {
    pub fmc: u8,
    pub boot_loader: u8,
    pub tee: u8,
    pub snp: u8,
    reserved: [u8; 3],
    pub microcode: u8,
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Default, Immutable)]
#[repr(C)]
pub struct TcbVersionRaw {
    pub raw: le::U64,
}
impl TcbVersionRaw {
    pub fn as_milan_genoa(&self) -> TcbVersionMilanGenoa {
        try_transmute!(*self).unwrap()
    }
    pub fn as_turin(&self) -> TcbVersionTurin {
        try_transmute!(*self).unwrap()
    }
}

#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct Signature {
    pub r: [u8; 72],
    pub s: [u8; 72],
    reserved: [u8; 512 - 144],
}

/// SNP Attestation Report (0x4A0 = 1184 bytes).
#[derive(Debug, Clone, Copy, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct AttestationReport {
    pub version: le::U32,                // 0x000
    pub guest_svn: le::U32,              // 0x004
    pub policy: le::U64,                 // 0x008
    pub family_id: [u8; 16],             // 0x010
    pub image_id: [u8; 16],              // 0x020
    pub vmpl: le::U32,                   // 0x030
    pub signature_algo: le::U32,         // 0x034
    pub platform_version: TcbVersionRaw, // 0x038
    pub platform_info: le::U64,          // 0x040
    pub flags: le::U32,                  // 0x048
    pub reserved0: le::U32,              // 0x04C
    pub report_data: [u8; 64],           // 0x050
    pub measurement: [u8; 48],           // 0x090
    pub host_data: [u8; 32],             // 0x0C0
    pub id_key_digest: [u8; 48],         // 0x0E0
    pub author_key_digest: [u8; 48],     // 0x110
    pub report_id: [u8; 32],             // 0x140
    pub report_id_ma: [u8; 32],          // 0x160
    pub reported_tcb: TcbVersionRaw,     // 0x180
    pub cpuid_fam_id: u8,                // 0x188
    pub cpuid_mod_id: u8,                // 0x189
    pub cpuid_step: u8,                  // 0x18A
    pub reserved1: [u8; 21],             // 0x18B
    pub chip_id: [u8; 64],               // 0x1A0
    pub committed_tcb: TcbVersionRaw,    // 0x1E0
    pub current_minor: u8,               // 0x1E8
    pub current_build: u8,               // 0x1E9
    pub current_major: u8,               // 0x1EA
    pub reserved2: u8,                   // 0x1EB
    pub committed_build: u8,             // 0x1EC
    pub committed_minor: u8,             // 0x1ED
    pub committed_major: u8,             // 0x1EE
    pub reserved3: u8,                   // 0x1EF
    pub launch_tcb: TcbVersionRaw,       // 0x1F0
    pub reserved4: [u8; 168],            // 0x1F8
    pub signature: Signature,            // 0x2A0
}

impl AttestationReport {
    /// Returns the signed portion of the report (everything before the signature).
    pub fn signed_bytes(&self) -> &[u8] {
        let bytes = self.as_bytes();
        &bytes[..0x2A0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn attestation_report_size() {
        assert_eq!(size_of::<AttestationReport>(), 0x4A0);
    }

    #[test]
    fn signature_size() {
        assert_eq!(size_of::<Signature>(), 512);
    }

    #[test]
    fn field_offsets() {
        use std::mem::offset_of;

        assert_eq!(offset_of!(AttestationReport, version), 0x000);
        assert_eq!(offset_of!(AttestationReport, guest_svn), 0x004);
        assert_eq!(offset_of!(AttestationReport, policy), 0x008);
        assert_eq!(offset_of!(AttestationReport, family_id), 0x010);
        assert_eq!(offset_of!(AttestationReport, image_id), 0x020);
        assert_eq!(offset_of!(AttestationReport, vmpl), 0x030);
        assert_eq!(offset_of!(AttestationReport, signature_algo), 0x034);
        assert_eq!(offset_of!(AttestationReport, platform_version), 0x038);
        assert_eq!(offset_of!(AttestationReport, platform_info), 0x040);
        assert_eq!(offset_of!(AttestationReport, flags), 0x048);
        assert_eq!(offset_of!(AttestationReport, reserved0), 0x04C);
        assert_eq!(offset_of!(AttestationReport, report_data), 0x050);
        assert_eq!(offset_of!(AttestationReport, measurement), 0x090);
        assert_eq!(offset_of!(AttestationReport, host_data), 0x0C0);
        assert_eq!(offset_of!(AttestationReport, id_key_digest), 0x0E0);
        assert_eq!(offset_of!(AttestationReport, author_key_digest), 0x110);
        assert_eq!(offset_of!(AttestationReport, report_id), 0x140);
        assert_eq!(offset_of!(AttestationReport, report_id_ma), 0x160);
        assert_eq!(offset_of!(AttestationReport, reported_tcb), 0x180);
        assert_eq!(offset_of!(AttestationReport, cpuid_fam_id), 0x188);
        assert_eq!(offset_of!(AttestationReport, cpuid_mod_id), 0x189);
        assert_eq!(offset_of!(AttestationReport, cpuid_step), 0x18A);
        assert_eq!(offset_of!(AttestationReport, reserved1), 0x18B);
        assert_eq!(offset_of!(AttestationReport, chip_id), 0x1A0);
        assert_eq!(offset_of!(AttestationReport, committed_tcb), 0x1E0);
        assert_eq!(offset_of!(AttestationReport, current_minor), 0x1E8);
        assert_eq!(offset_of!(AttestationReport, current_build), 0x1E9);
        assert_eq!(offset_of!(AttestationReport, current_major), 0x1EA);
        assert_eq!(offset_of!(AttestationReport, reserved2), 0x1EB);
        assert_eq!(offset_of!(AttestationReport, committed_build), 0x1EC);
        assert_eq!(offset_of!(AttestationReport, committed_minor), 0x1ED);
        assert_eq!(offset_of!(AttestationReport, committed_major), 0x1EE);
        assert_eq!(offset_of!(AttestationReport, reserved3), 0x1EF);
        assert_eq!(offset_of!(AttestationReport, launch_tcb), 0x1F0);
        assert_eq!(offset_of!(AttestationReport, reserved4), 0x1F8);
        assert_eq!(offset_of!(AttestationReport, signature), 0x2A0);
    }
}

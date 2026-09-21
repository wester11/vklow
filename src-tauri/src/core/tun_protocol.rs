use crate::core::system_vpn::SystemVpnSessionSpec;
use serde::{Deserialize, Serialize};

pub const IPC_PROTOCOL_VERSION: u8 = 1;
pub const MAX_IPC_MESSAGE_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunOperation {
    StartScopedTunSession,
    StartFullIpv4Experimental,
    StartSystemVpnSession,
    StopTunSession,
    QueryTunSession,
    RecoverTunSession,
    /// Development controller only; the helper terminates its own tracked child.
    TestCrashOwnedCore,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TunRequest {
    pub protocol_version: u8,
    pub session_id: String,
    pub nonce: String,
    pub controller_pid: u32,
    pub helper_pid: u32,
    pub operation: TunOperation,
    #[serde(default)]
    pub system_vpn: Option<SystemVpnSessionSpec>,
}

impl TunRequest {
    pub fn decode(
        bytes: &[u8],
        expected_session: &str,
        expected_nonce: &str,
    ) -> Result<Self, String> {
        if bytes.len() > MAX_IPC_MESSAGE_BYTES {
            return Err("Tun IPC message exceeds limit".into());
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| "Malformed Tun IPC message".to_owned())?;
        if request.protocol_version != IPC_PROTOCOL_VERSION {
            return Err("Unsupported Tun IPC protocol version".into());
        }
        if request.session_id != expected_session {
            return Err("Tun IPC session mismatch".into());
        }
        if request.nonce != expected_nonce {
            return Err("Tun IPC nonce mismatch".into());
        }
        if request.controller_pid == 0 || request.helper_pid == 0 {
            return Err("Invalid TUN IPC process identity".into());
        }
        match request.operation {
            TunOperation::StartSystemVpnSession => request
                .system_vpn
                .as_ref()
                .ok_or("MissingSystemVpnSessionSpec")?
                .validate()?,
            _ if request.system_vpn.is_some() => {
                return Err("UnexpectedSystemVpnSessionSpec".into())
            }
            _ => {}
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TunResponse {
    pub protocol_version: u8,
    pub session_id: String,
    pub controller_pid: u32,
    pub helper_pid: u32,
    pub ok: bool,
    pub state: String,
    pub message: Option<String>,
}

impl TunResponse {
    pub fn accepted(
        session_id: String,
        controller_pid: u32,
        helper_pid: u32,
        state: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            session_id,
            controller_pid,
            helper_pid,
            ok: true,
            state: state.into(),
            message: None,
        }
    }
    pub fn rejected(
        session_id: String,
        controller_pid: u32,
        helper_pid: u32,
        message: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: IPC_PROTOCOL_VERSION,
            session_id,
            controller_pid,
            helper_pid,
            ok: false,
            state: "rejected".into(),
            message: Some(message.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION: &str = "2b7e4251-3328-4470-8708-e19084073cb3";
    const NONCE: &str = "Kzf4TeYHAb29qVi1_6vm5VH9mqNUJM60BaVGFvYp9Hk";

    fn request(operation: TunOperation) -> Vec<u8> {
        serde_json::to_vec(&TunRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            session_id: SESSION.into(),
            nonce: NONCE.into(),
            controller_pid: 42,
            helper_pid: 43,
            operation,
            system_vpn: None,
        })
        .unwrap()
    }

    #[test]
    fn accepts_only_known_authenticated_operations() {
        let decoded = TunRequest::decode(
            &request(TunOperation::StartScopedTunSession),
            SESSION,
            NONCE,
        )
        .unwrap();
        assert_eq!(decoded.operation, TunOperation::StartScopedTunSession);
    }

    #[test]
    fn rejects_malformed_unknown_and_oversized_messages() {
        assert!(TunRequest::decode(b"not json", SESSION, NONCE).is_err());
        assert!(TunRequest::decode(
            br#"{"protocolVersion":1,"sessionId":"2b7e4251-3328-4470-8708-e19084073cb3","nonce":"Kzf4TeYHAb29qVi1_6vm5VH9mqNUJM60BaVGFvYp9Hk","operation":"execute"}"#,
            SESSION,
            NONCE,
        )
        .is_err());
        assert!(
            TunRequest::decode(&vec![b'x'; MAX_IPC_MESSAGE_BYTES + 1], SESSION, NONCE).is_err()
        );
    }

    #[test]
    fn rejects_wrong_session_nonce_and_arbitrary_path_fields() {
        let wrong_session = request(TunOperation::StopTunSession);
        assert!(TunRequest::decode(&wrong_session, "other", NONCE).is_err());
        assert!(TunRequest::decode(&wrong_session, SESSION, "other").is_err());
        assert!(TunRequest::decode(
            br#"{"protocolVersion":1,"sessionId":"2b7e4251-3328-4470-8708-e19084073cb3","nonce":"Kzf4TeYHAb29qVi1_6vm5VH9mqNUJM60BaVGFvYp9Hk","operation":"start_scoped_tun_session","binaryPath":"C:\\evil.exe"}"#,
            SESSION,
            NONCE,
        )
        .is_err());
    }

    #[test]
    fn rejects_system_vpn_start_without_a_valid_typed_spec() {
        let bytes = serde_json::to_vec(&TunRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            session_id: SESSION.into(),
            nonce: NONCE.into(),
            controller_pid: 42,
            helper_pid: 43,
            operation: TunOperation::StartSystemVpnSession,
            system_vpn: None,
        })
        .unwrap();
        assert_eq!(
            TunRequest::decode(&bytes, SESSION, NONCE).err().unwrap(),
            "MissingSystemVpnSessionSpec"
        );
    }

    #[test]
    fn typed_system_vpn_request_fits_the_bounded_pipe() {
        let spec = SystemVpnSessionSpec {
            spec_version: 1,
            session_id: SESSION.into(),
            selected_server_id: "11111111-1111-1111-1111-111111111111".into(),
            mode: crate::core::system_vpn::SystemVpnMode::SystemIpv4Experimental,
            outbound: crate::core::system_vpn::SystemVpnOutbound::VlessRealityTcp(
                crate::core::system_vpn::VlessRealityTcpSpec {
                    address: "edge.example".into(),
                    port: 443,
                    uuid: "22222222-2222-2222-2222-222222222222".into(),
                    flow: Some("xtls-rprx-vision".into()),
                    server_name: "www.example.com".into(),
                    fingerprint: "chrome".into(),
                    public_key: "public-fixture".into(),
                    short_id: "aabb".into(),
                },
            ),
        };
        let bytes = serde_json::to_vec(&TunRequest {
            protocol_version: IPC_PROTOCOL_VERSION,
            session_id: SESSION.into(),
            nonce: NONCE.into(),
            controller_pid: 42,
            helper_pid: 43,
            operation: TunOperation::StartSystemVpnSession,
            system_vpn: Some(spec),
        })
        .unwrap();
        assert!(bytes.len() < MAX_IPC_MESSAGE_BYTES);
        assert!(TunRequest::decode(&bytes, SESSION, NONCE).is_ok());
    }
}

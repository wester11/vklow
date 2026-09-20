use serde::{Deserialize, Serialize};

pub const IPC_PROTOCOL_VERSION: u8 = 1;
pub const MAX_IPC_MESSAGE_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunOperation {
    StartScopedTunSession,
    StopTunSession,
    QueryTunSession,
    RecoverTunSession,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TunRequest {
    pub protocol_version: u8,
    pub session_id: String,
    pub nonce: String,
    pub controller_pid: u32,
    pub helper_pid: u32,
    pub operation: TunOperation,
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
}

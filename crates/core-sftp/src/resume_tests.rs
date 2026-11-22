use std::sync::Mutex;

use russh_sftp::protocol::{Attrs, Data, Handle, Status};
use russh_sftp::server::{self, Handler};

use super::*;

#[derive(Default)]
struct RemoteFile {
    data: Vec<u8>,
    fail_at: Option<u64>,
    writes: Vec<u64>,
}

struct FileServer(Arc<Mutex<RemoteFile>>);

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    }
}

impl Handler for FileServer {
    type Error = StatusCode;

    fn unimplemented(&self) -> StatusCode {
        StatusCode::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        path: String,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, StatusCode> {
        if flags.contains(OpenFlags::TRUNCATE) {
            self.0.lock().unwrap().data.clear();
        }
        Ok(Handle { id, handle: path })
    }

    async fn close(&mut self, id: u32, _: String) -> Result<Status, StatusCode> {
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        _: String,
        offset: u64,
        length: u32,
    ) -> Result<Data, StatusCode> {
        let file = self.0.lock().unwrap();
        if file.fail_at.is_some_and(|limit| offset >= limit) {
            return Err(StatusCode::Failure);
        }
        let start = offset as usize;
        if start >= file.data.len() {
            return Err(StatusCode::Eof);
        }
        let end = (start + length as usize).min(file.data.len());
        Ok(Data {
            id,
            data: file.data[start..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        _: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, StatusCode> {
        let mut file = self.0.lock().unwrap();
        if file.fail_at.is_some_and(|limit| offset >= limit) {
            return Err(StatusCode::Failure);
        }
        file.writes.push(offset);
        let start = offset as usize;
        let end = start + data.len();
        if file.data.len() < end {
            file.data.resize(end, 0);
        }
        file.data[start..end].copy_from_slice(&data);
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, handle: String) -> Result<Attrs, StatusCode> {
        self.fstat(id, handle).await
    }

    async fn fstat(&mut self, id: u32, _: String) -> Result<Attrs, StatusCode> {
        Ok(Attrs {
            id,
            attrs: FileAttributes {
                size: Some(self.0.lock().unwrap().data.len() as u64),
                ..Default::default()
            },
        })
    }
}

async fn attach_test_session(
    manager: &SftpManager,
    id: &str,
    state: Arc<Mutex<RemoteFile>>,
    peer: SshPeer,
) {
    let (client, server_stream) = tokio::io::duplex(256 * 1024);
    tokio::spawn(server::run(server_stream, FileServer(state)));
    let client = SftpSession::new(client).await.unwrap();
    manager.sessions.insert(id.into(), (Arc::new(client), peer));
}

#[tokio::test]
async fn retries_only_the_missing_suffix_and_rejects_corrupt_partials() {
    let manager = SftpManager::new();
    let state = Arc::new(Mutex::new(RemoteFile {
        fail_at: Some(CHUNK_SIZE as u64),
        ..RemoteFile::default()
    }));
    let peer = SshPeer {
        hostname: "test".into(),
        port: 22,
        username: "tester".into(),
        host_key_fingerprint: "SHA256:original".into(),
    };
    attach_test_session(&manager, "initial", Arc::clone(&state), peer.clone()).await;
    let contents: Vec<_> = (0..CHUNK_SIZE * 3).map(|i| (i % 251) as u8).collect();
    let local = std::env::temp_dir().join(format!("sterm-sftp-test-{}", Uuid::now_v7()));
    tokio::fs::write(&local, &contents).await.unwrap();

    let mut progress = None;
    assert!(manager
        .upload_file("initial", &local, "/file", |p| progress = Some(p))
        .await
        .is_err());
    let failed = progress.take().unwrap();
    assert!(matches!(failed.status, TransferStatus::Failed));
    let prefix = {
        let mut file = state.lock().unwrap();
        let prefix = file.data.len();
        assert!(prefix > 0 && prefix < contents.len());
        assert_eq!(file.data, contents[..prefix]);
        file.fail_at = None;
        file.writes.clear();
        prefix as u64
    };
    manager.close("initial").await;
    let other_peer = SshPeer {
        host_key_fingerprint: "SHA256:other".into(),
        ..peer.clone()
    };
    attach_test_session(&manager, "other", Arc::clone(&state), other_peer).await;
    assert!(manager
        .retry_file("other", failed.clone(), |_| {})
        .await
        .is_err());
    attach_test_session(&manager, "reconnected", Arc::clone(&state), peer).await;
    manager
        .retry_file("reconnected", failed.clone(), |p| progress = Some(p))
        .await
        .unwrap();
    let completed = progress.take().unwrap();
    assert_eq!(completed.transfer_id, failed.transfer_id);
    assert!(matches!(completed.status, TransferStatus::Completed));
    {
        let mut file = state.lock().unwrap();
        assert_eq!(file.writes.first(), Some(&prefix));
        assert_eq!(file.data, contents);
        file.fail_at = Some(CHUNK_SIZE as u64);
    }

    assert!(manager
        .download_file("reconnected", "/file", &local, |p| progress = Some(p))
        .await
        .is_err());
    let failed = progress.take().unwrap();
    let mut partial = tokio::fs::read(&local).await.unwrap();
    assert!(!partial.is_empty() && partial.len() < contents.len());
    assert_eq!(partial, contents[..partial.len()]);
    state.lock().unwrap().fail_at = None;
    partial[0] ^= 1;
    tokio::fs::write(&local, &partial).await.unwrap();
    assert!(manager
        .retry_file("reconnected", failed.clone(), |_| {})
        .await
        .is_err());
    assert_eq!(tokio::fs::read(&local).await.unwrap(), partial);
    partial[0] ^= 1;
    tokio::fs::write(&local, &partial).await.unwrap();

    let mut offsets = Vec::new();
    manager
        .retry_file("reconnected", failed, |p| offsets.push(p.bytes_transferred))
        .await
        .unwrap();
    assert!(offsets.contains(&(partial.len() as u64)));
    assert_eq!(tokio::fs::read(&local).await.unwrap(), contents);
    tokio::fs::remove_file(local).await.unwrap();
}

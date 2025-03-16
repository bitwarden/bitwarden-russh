use std::collections::HashMap;
use std::marker::Sync;
use std::sync::{Arc, RwLock};

use crate::encoding::{Encoding, Position, Reader};
use byteorder::{BigEndian, ByteOrder};
use futures::stream::{Stream, StreamExt};
use rsa::sha2::Digest;
use rsa::{sha2, BigUint, Pkcs1v15Sign};
use russh_cryptovec::CryptoVec;
use ssh_key::public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey};
use ssh_key::{EcdsaCurve, HashAlg, SigningKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio_util::sync::CancellationToken;

use crate::msg::{self, EXTENSION};
use anyhow::Error;

use super::msg::{REQUEST_IDENTITIES, SIGN_REQUEST};
use std::result::Result;

#[derive(Clone)]
pub struct Key {
    pub private_key: Option<ssh_key::private::PrivateKey>,
    pub name: String,
    pub cipher_uuid: String,
}

#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct KeyStore(pub Arc<RwLock<HashMap<Vec<u8>, Key>>>);

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ServerError<E> {
    E(E),
    Error(Error),
}

pub trait Agent<I>: Clone + Send + 'static {
    fn confirm(
        &self,
        _pk: Key,
        _data: &[u8],
        _connection_info: &I,
    ) -> impl std::future::Future<Output = bool> + Send {
        async { true }
    }

    fn can_list(&self, _connection_info: &I) -> impl std::future::Future<Output = bool> + Send {
        async { true }
    }

    fn set_sessionbind_info(
        &self,
        _is_forwarding: bool,
        _hostkey: &[u8],
        _session_identifier: &[u8],
        _connection_info: &I,
    ) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }
}

pub async fn serve<S, L, A, I>(
    mut listener: L,
    agent: A,
    keys: KeyStore,
    cancellation_token: CancellationToken,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    L: Stream<Item = tokio::io::Result<(S, I)>> + Unpin,
    A: Agent<I> + Send + Sync + 'static,
    I: Send + Sync + 'static,
{
    loop {
        select! {
            _ = cancellation_token.cancelled() => {
                break;
            }
            Some(Ok((stream, info))) = listener.next() => {
                let mut buf = CryptoVec::new();
                buf.resize(4);
                let keys = keys.clone();
                let agent = agent.clone();

                tokio::spawn(async move {
                    let _ = Connection {
                        keys,
                        agent: Some(agent),
                        s: stream,
                        buf: CryptoVec::new(),
                        connection_info: info,
                    }
                    .run()
                    .await;
                });
            }
        }
    }

    Ok(())
}

struct Connection<S: AsyncRead + AsyncWrite + Send + 'static, A: Agent<I>, I> {
    keys: KeyStore,
    agent: Option<A>,
    s: S,
    buf: CryptoVec,
    connection_info: I,
}

impl<
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        A: Agent<I> + Send + Sync + 'static,
        I,
    > Connection<S, A, I>
{
    async fn run(mut self) -> Result<(), Error> {
        let mut writebuf = CryptoVec::new();
        loop {
            // Reading the length
            self.buf.clear();
            self.buf.resize(4);
            self.s.read_exact(&mut self.buf).await?;

            // Reading the rest of the buffer
            let len = BigEndian::read_u32(&self.buf) as usize;
            self.buf.clear();
            self.buf.resize(len);
            self.s.read_exact(&mut self.buf).await?;

            // respond
            writebuf.clear();
            self.respond(&mut writebuf).await?;
            self.s.write_all(&writebuf).await?;
            self.s.flush().await?
        }
    }

    async fn respond(&mut self, writebuf: &mut CryptoVec) -> Result<(), Error> {
        writebuf.extend(&[0, 0, 0, 0]);
        let mut r = self.buf.reader(0);
        match r.read_byte() {
            Ok(REQUEST_IDENTITIES) => {
                let agent = self.agent.take().ok_or(SSHAgentError::AgentFailure)?;
                self.agent = Some(agent.clone());
                if !agent.can_list(&self.connection_info).await {
                    writebuf.push(msg::FAILURE);
                } else if let Ok(keys) = self.keys.0.read() {
                    writebuf.push(msg::IDENTITIES_ANSWER);
                    writebuf.push_u32_be(keys.len() as u32);
                    for (public_key_bytes, key) in keys.iter() {
                        writebuf.extend_ssh_string(public_key_bytes);
                        writebuf.extend_ssh_string(key.name.as_bytes());
                    }
                } else {
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(SIGN_REQUEST) => {
                let agent = self.agent.take().ok_or(SSHAgentError::AgentFailure)?;
                let (agent, signed) = self.try_sign(agent, r, writebuf).await?;
                self.agent = Some(agent);
                if signed {
                    return Ok(());
                } else {
                    writebuf.resize(4);
                    writebuf.push(msg::FAILURE)
                }
            }
            Ok(EXTENSION) => {
                let extension_name = r.read_string()?;
                let extension_name = String::from_utf8(extension_name.to_vec())
                    .map_err(|_| SSHAgentError::AgentFailure)?;

                // https://raw.githubusercontent.com/openssh/openssh-portable/refs/heads/master/PROTOCOL.agent
                if extension_name == "session-bind@openssh.com" {
                    let hostkey_bytes = r.read_string()?;
                    let hostkey = ssh_key::PublicKey::from_bytes(&hostkey_bytes)
                        .map_err(|_| SSHAgentError::AgentFailure)?;
                    let session_identifier = r.read_string()?;

                    let signature_bytes = r.read_string()?;
                    let binding = CryptoVec::from_slice(&signature_bytes);
                    let mut signature = binding.reader(0);
                    let alg = String::from_utf8(signature.read_string()?.to_vec())
                        .map_err(|_| SSHAgentError::AgentFailure)?;
                    let signature = signature.read_string()?.to_vec();

                    let is_forwarding = r.read_byte()? == 1;

                    let signature_verification = match hostkey.key_data() {
                        KeyData::Ed25519(key) => {
                            verify_ed25519_signature(key, &signature, alg, session_identifier)
                        }
                        KeyData::Rsa(key) => {
                            verify_rsa_signature(key, &signature, alg, session_identifier)
                        }
                        KeyData::Ecdsa(key) => {
                            verify_ecdsa_signature(key, &signature, alg, session_identifier)
                        }
                        _ => Ok(()),
                    };
                    println!("signature_verification {:?}", signature_verification);
                    if !signature_verification.is_ok() {
                        writebuf.push(msg::FAILURE);
                        return Ok(());
                    }

                    let agent = self.agent.take().ok_or(SSHAgentError::AgentFailure)?;
                    agent
                        .set_sessionbind_info(
                            is_forwarding,
                            hostkey_bytes,
                            session_identifier,
                            &self.connection_info,
                        )
                        .await;
                    self.agent = Some(agent);
                    writebuf.push(msg::SUCCESS);
                } else {
                    writebuf.push(msg::FAILURE);
                }
            }
            _ => writebuf.push(msg::FAILURE),
        }
        let len = writebuf.len() - 4;
        BigEndian::write_u32(&mut writebuf[..], len as u32);
        Ok(())
    }

    async fn try_sign(
        &self,
        agent: A,
        mut r: Position<'_>,
        writebuf: &mut CryptoVec,
    ) -> Result<(A, bool), Error> {
        let blob = r.read_string()?;
        let key = {
            let k = self.keys.0.read().or(Err(SSHAgentError::AgentFailure))?;
            if let Some(key) = k.get(blob) {
                key.clone()
            } else {
                return Ok((agent, false));
            }
        };

        let data = r.read_string()?;

        let ok = agent.confirm(key, data, &self.connection_info).await;
        if !ok {
            return Ok((agent, false));
        }

        let key = {
            let k = self.keys.0.read().or(Err(SSHAgentError::AgentFailure))?;
            if let Some(key) = k.get(blob) {
                key.clone()
            } else {
                return Ok((agent, false));
            }
        };

        match key.private_key {
            Some(private_key) => {
                writebuf.push(msg::SIGN_RESPONSE);
                let signer: &dyn SigningKey = &private_key;
                let sig = signer.try_sign(data).or(Err(SSHAgentError::AgentFailure));
                let sig = match sig {
                    Ok(sig) => sig,
                    Err(err) => {
                        println!("Error signing: {:?}", err);
                        writebuf.push(msg::FAILURE);
                        return Ok((agent, false));
                    }
                };

                let sig_name = match sig.algorithm() {
                    ssh_key::Algorithm::Ed25519 => "ssh-ed25519",
                    ssh_key::Algorithm::Rsa { hash: None } => "ssh-rsa",
                    ssh_key::Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    } => "rsa-sha2-256",
                    ssh_key::Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    } => "rsa-sha2-512",
                    _ => {
                        println!("Unsupported signing algorithm");
                        writebuf.push(msg::FAILURE);
                        return Ok((agent, false));
                    }
                };

                writebuf.push_u32_be(sig_name.len() as u32 + sig.as_bytes().len() as u32 + 8);
                writebuf.extend_ssh_string(sig_name.as_bytes());
                writebuf.extend_ssh_string(sig.as_bytes());

                let len = writebuf.len();
                BigEndian::write_u32(writebuf, (len - 4) as u32);

                Ok((agent, true))
            }
            None => {
                writebuf.push(msg::FAILURE);
                Ok((agent, false))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SSHAgentError {
    #[error("Agent failure")]
    AgentFailure,
}

fn verify_ed25519_signature(
    key: &Ed25519PublicKey,
    signature: &[u8],
    _alg: String,
    session_identifier: &[u8],
) -> Result<(), Error> {
    ed25519_dalek::VerifyingKey::from_bytes(&key.0)?
        .verify_strict(
            session_identifier,
            &ed25519_dalek::Signature::from_slice(signature)?,
        )
        .map_err(Into::into)
}

fn verify_rsa_signature(
    key: &RsaPublicKey,
    signature: &[u8],
    alg: String,
    session_identifier: &[u8],
) -> Result<(), Error> {
    let n = key
        .n
        .as_positive_bytes()
        .map(BigUint::from_bytes_be)
        .ok_or(anyhow::anyhow!("Failed to parse RSA modulus"))?;
    let e = key
        .e
        .as_positive_bytes()
        .map(BigUint::from_bytes_be)
        .ok_or(anyhow::anyhow!("Failed to parse RSA exponent"))?;
    let verifying_key = rsa::RsaPublicKey::new(n, e)?;
    if alg == "rsa-sha2-256" {
        verifying_key
            .verify(
                Pkcs1v15Sign::new::<sha2::Sha256>(),
                sha2::Sha256::digest(session_identifier).as_slice(),
                &signature,
            )
            .map_err(Into::into)
    } else if alg == "rsa-sha2-512" {
        verifying_key
            .verify(
                Pkcs1v15Sign::new::<sha2::Sha512>(),
                sha2::Sha512::digest(session_identifier).as_slice(),
                &signature,
            )
            .map_err(Into::into)
    } else {
        Err(SSHAgentError::AgentFailure.into())
    }
}

fn verify_ecdsa_signature(
    key: &EcdsaPublicKey,
    signature: &[u8],
    _alg: String,
    session_identifier: &[u8],
) -> Result<(), Error> {
    match key.curve() {
        EcdsaCurve::NistP256 => {
            use p256::ecdsa::signature::Verifier;
            p256::ecdsa::VerifyingKey::from_sec1_bytes(key.as_sec1_bytes())?
                .verify(
                    session_identifier,
                    &p256::ecdsa::Signature::from_slice(signature)?,
                )
                .map_err(Into::into)
        }
        EcdsaCurve::NistP384 => {
            use p384::ecdsa::signature::Verifier;
            p384::ecdsa::VerifyingKey::from_sec1_bytes(key.as_sec1_bytes())?
                .verify(
                    session_identifier,
                    &p384::ecdsa::Signature::from_slice(signature)?,
                )
                .map_err(Into::into)
        }
        EcdsaCurve::NistP521 => {
            use p521::ecdsa::signature::Verifier;
            p521::ecdsa::VerifyingKey::from_sec1_bytes(key.as_sec1_bytes())?
                .verify(
                    session_identifier,
                    &p521::ecdsa::Signature::from_slice(signature)?,
                )
                .map_err(Into::into)
        }
    }
}

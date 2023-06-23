use crate::{
    error::LoadRootCertificateError, session::WolfSession, RootCertificate, Secret, WolfMethod,
};
use parking_lot::{Mutex, MutexGuard};
use std::ptr::NonNull;

#[allow(missing_docs)]
#[derive(Debug)]
pub struct WolfContextBuilder {
    ctx: NonNull<wolfssl_sys::WOLFSSL_CTX>,
    method: WolfMethod,
}

impl WolfContextBuilder {
    /// Invokes [`wolfSSL_CTX_new`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_new
    pub fn new(method: WolfMethod) -> Option<Self> {
        let method_fn = method.into_method_ptr()?;

        let ctx = unsafe { wolfssl_sys::wolfSSL_CTX_new(method_fn.as_ptr()) };
        let ctx = NonNull::new(ctx)?;

        Some(Self { ctx, method })
    }

    /// Wraps [`wolfSSL_CTX_load_verify_buffer`][0] and [`wolfSSL_CTX_load_verify_locations`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_buffer
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_load_verify_locations
    pub fn with_root_certificate(
        self,
        root: RootCertificate,
    ) -> Result<Self, LoadRootCertificateError> {
        use wolfssl_sys::{
            wolfSSL_CTX_load_verify_buffer, wolfSSL_CTX_load_verify_locations,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match root {
            RootCertificate::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            RootCertificate::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_load_verify_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            RootCertificate::PemFileOrDirectory(path) => {
                let is_dir = path.is_dir();
                let path =
                    std::ffi::CString::new(path.to_str().ok_or(LoadRootCertificateError::Path)?)
                        .map_err(|_| LoadRootCertificateError::Path)?;
                if is_dir {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.ctx.as_ptr(),
                            std::ptr::null(),
                            path.as_c_str().as_ptr(),
                        )
                    }
                } else {
                    unsafe {
                        wolfSSL_CTX_load_verify_locations(
                            self.ctx.as_ptr(),
                            path.as_c_str().as_ptr(),
                            std::ptr::null(),
                        )
                    }
                }
            }
        };

        if result == WOLFSSL_SUCCESS {
            Ok(self)
        } else {
            Err(LoadRootCertificateError::from(result))
        }
    }

    /// Wraps [`wolfSSL_CTX_set_cipher_list`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/ssl_8h.html#function-wolfssl_ctx_set_cipher_list
    pub fn with_cipher_list(self, cipher_list: &str) -> Option<Self> {
        let cipher_list = std::ffi::CString::new(cipher_list).ok()?;
        let result = unsafe {
            wolfssl_sys::wolfSSL_CTX_set_cipher_list(
                self.ctx.as_ptr(),
                cipher_list.as_c_str().as_ptr(),
            )
        };
        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps [`wolfSSL_CTX_use_certificate_file`][0] and [`wolfSSL_CTX_use_certificate_buffer`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_file
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_certificate_buffer
    pub fn with_certificate(self, secret: Secret) -> Option<Self> {
        use wolfssl_sys::{
            wolfSSL_CTX_use_certificate_buffer, wolfSSL_CTX_use_certificate_file,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match secret {
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => unsafe {
                let file = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_certificate_file(
                    self.ctx.as_ptr(),
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_certificate_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => unsafe {
                let file = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_certificate_file(
                    self.ctx.as_ptr(),
                    file.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_PEM,
                )
            },
        };

        if result == WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps [`wolfSSL_CTX_use_PrivateKey_file`][0] and [`wolfSSL_CTX_use_PrivateKey_buffer`][1]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_file
    /// [1]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__CertsKeys.html#function-wolfssl_ctx_use_privatekey_buffer
    pub fn with_private_key(self, secret: Secret) -> Option<Self> {
        use wolfssl_sys::{
            wolfSSL_CTX_use_PrivateKey_buffer, wolfSSL_CTX_use_PrivateKey_file,
            WOLFSSL_FILETYPE_ASN1, WOLFSSL_FILETYPE_PEM, WOLFSSL_SUCCESS,
        };

        let result = match secret {
            Secret::Asn1Buffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::Asn1File(path) => unsafe {
                let path = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_PrivateKey_file(
                    self.ctx.as_ptr(),
                    path.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_ASN1,
                )
            },
            Secret::PemBuffer(buf) => unsafe {
                wolfSSL_CTX_use_PrivateKey_buffer(
                    self.ctx.as_ptr(),
                    buf.as_ptr(),
                    buf.len() as i64,
                    WOLFSSL_FILETYPE_PEM,
                )
            },
            Secret::PemFile(path) => unsafe {
                let path = std::ffi::CString::new(path.to_str()?).ok()?;
                wolfSSL_CTX_use_PrivateKey_file(
                    self.ctx.as_ptr(),
                    path.as_c_str().as_ptr(),
                    WOLFSSL_FILETYPE_PEM,
                )
            },
        };

        if result == WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Wraps `wolfSSL_CTX_UseSecureRenegotiation`
    ///
    // TODO (pangt): I can't seem to find documentation online for this.
    // this might also prompt a more general review of how we should
    // be checking for and handling errors (i.e; should we just
    // collect all error codes and throw it back up instead of
    // wrapping it in an enum?)
    pub fn with_secure_renegotiation(self) -> Option<Self> {
        let result = unsafe { wolfssl_sys::wolfSSL_CTX_UseSecureRenegotiation(self.ctx.as_ptr()) };
        if result == wolfssl_sys::WOLFSSL_SUCCESS {
            Some(self)
        } else {
            None
        }
    }

    /// Finalizes a `WolfContext`.
    pub fn build(self) -> WolfContext {
        WolfContext {
            _method: self.method,
            ctx: Mutex::new(self.ctx),
        }
    }
}

#[allow(missing_docs)]
pub struct WolfContext {
    _method: WolfMethod,
    ctx: Mutex<NonNull<wolfssl_sys::WOLFSSL_CTX>>,
}

/// This is necessary because `WolfContext` will need to cross
/// `.await` boundaries, which means it must be safe to transfer
/// across threads.
///
/// We cannot specify just `wolfssl_sys::WOLFSSL_CTX` because of
/// orphan rules.
///
// TODO (pangt): Perhaps store the pointer inside something `Send`
// instead
unsafe impl Send for WolfContext {}

impl WolfContext {
    /// Gets the underlying [`wolfssl_sys::WOLFSSL_CTX`] pointer that this
    /// [`WolfContext`] is managing.
    pub fn ctx(&self) -> MutexGuard<NonNull<wolfssl_sys::WOLFSSL_CTX>> {
        self.ctx.lock()
    }

    /// Creates a new SSL session using this underlying context.
    pub fn new_session(&self) -> Option<WolfSession> {
        WolfSession::new_from_context(self)
    }
}

impl Drop for WolfContext {
    /// Invokes [`wolfSSL_CTX_free`][0]
    ///
    /// [0]: https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html#function-wolfssl_ctx_free
    fn drop(&mut self) {
        unsafe { wolfssl_sys::wolfSSL_CTX_free(self.ctx.lock().as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{wolf_cleanup, wolf_init};
    use test_case::test_case;

    #[test_case(WolfMethod::DtlsClient)]
    #[test_case(WolfMethod::DtlsClientV1_2)]
    #[test_case(WolfMethod::DtlsServer)]
    #[test_case(WolfMethod::DtlsServerV1_2)]
    #[test_case(WolfMethod::TlsClient)]
    #[test_case(WolfMethod::TlsClientV1_2)]
    #[test_case(WolfMethod::TlsClientV1_3)]
    #[test_case(WolfMethod::TlsServer)]
    #[test_case(WolfMethod::TlsServerV1_2)]
    #[test_case(WolfMethod::TlsServerV1_3)]
    fn wolfssl_context_new(method: WolfMethod) {
        wolf_init().unwrap();
        let _ = method.into_method_ptr().unwrap();
        wolf_cleanup().unwrap();
    }

    #[test]
    fn new() {
        WolfContextBuilder::new(WolfMethod::DtlsClient).unwrap();
        wolf_cleanup().unwrap();
    }

    #[test]
    fn root_certificate_buffer() {
        const CA_CERT: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/ca_cert_der_2048"
        ));

        let cert = RootCertificate::Asn1Buffer(CA_CERT);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_root_certificate(cert)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn set_cipher_list() {
        let _ = WolfContextBuilder::new(WolfMethod::DtlsClient)
            .unwrap()
            // This string might need to change depending on the flags
            // we built wolfssl with.
            .with_cipher_list("TLS13-CHACHA20-POLY1305-SHA256")
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn set_certificate_buffer() {
        const SERVER_CERT: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/server_cert_der_2048"
        ));

        let cert = Secret::Asn1Buffer(SERVER_CERT);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_certificate(cert)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn set_private_key_buffer() {
        const SERVER_KEY: &[u8] = &include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test_data/server_key_der_2048"
        ));

        let key = Secret::Asn1Buffer(SERVER_KEY);

        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_private_key(key)
            .unwrap();

        wolf_cleanup().unwrap();
    }

    #[test]
    fn set_secure_renegotiation() {
        let _ = WolfContextBuilder::new(WolfMethod::TlsClient)
            .unwrap()
            .with_secure_renegotiation()
            .unwrap();

        wolf_cleanup().unwrap();
    }
}

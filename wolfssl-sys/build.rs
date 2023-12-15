/*!
 * Contains the build process for WolfSSL
 */

extern crate bindgen;

use autotools::Config;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::path::{PathBuf, Path};
use std::process::Command;

/**
 * Work around for bindgen creating duplicate values.
 */
#[derive(Debug)]
struct IgnoreMacros(HashSet<String>);

impl bindgen::callbacks::ParseCallbacks for IgnoreMacros {
    fn will_parse_macro(&self, name: &str) -> bindgen::callbacks::MacroParsingBehavior {
        if self.0.contains(name) {
            bindgen::callbacks::MacroParsingBehavior::Ignore
        } else {
            bindgen::callbacks::MacroParsingBehavior::Default
        }
    }
}

/**
 * Copy WolfSSL
 */
fn copy_wolfssl(dest: &str) -> std::io::Result<()> {
    Command::new("cp")
        .arg("-rf")
        .arg("wolfssl-src")
        .arg(dest)
        .status()
        .unwrap();

    Ok(())
}

const PATCH_DIR: &str = "patches";
const PATCHES: &[&str] = &[
    "0001-tls-return-immediately-if-kyber_id2type-fails.patch",
    "0002-SP-ARM64-asm-fix-Montgomery-reduction-by-4.patch",
    "0003-SP-ARM64-P-256-mark-functions-as-SP_NOINLINE.patch",
    "0004-AES-GCM-ARM64-Replace-hardware-crypto-assembly-with-.patch",
    "0005-AES-GCM-ARM64-Fix-clobber-lists.patch",
];

/**
 * Apply patch to wolfssl-src
 */
fn apply_patch(dest: &str, patch: &str) {
    let wolfssl_path = format!("{dest}/wolfssl-src");
    let patch = format!("{}/{}", PATCH_DIR, patch);

    let patch_buffer = File::open(patch).unwrap();
    Command::new("patch")
        .arg("-d")
        .arg(wolfssl_path)
        .arg("-p1")
        .stdin(patch_buffer)
        .status()
        .unwrap();
}

/**
Builds WolfSSL
*/
fn build_wolfssl(dest: &str) -> PathBuf {
    // Create the config
    let mut conf = Config::new(format!("{dest}/wolfssl-src"));
    // Configure it
    conf.reconf("-ivf")
        // Only build the static library
        .enable_static()
        .disable_shared()
        // Enable TLS/1.3
        .enable("tls13", None)
        // Enable DTLS/1.3
        .enable("dtls13", None)
        // Disable old TLS versions
        .disable("oldtls", None)
        // Enable single threaded mode
        .enable("singlethreaded", None)
        // Enable D/TLS
        .enable("dtls", None)
        // Enable single precision
        .enable("sp", None)
        // Enable setting the D/TLS MTU size
        .enable("dtls-mtu", None)
        // Disable SHA3
        .disable("sha3", None)
        // Disable DH key exchanges
        .disable("dh", None)
        // Disable examples
        .disable("examples", None)
        // Disable benchmarks
        .disable("benchmark", None)
        // Disable sys ca certificate store
        .disable("sys-ca-certs", None)
        // Enable elliptic curve exchanges
        .enable("supportedcurves", None)
        .enable("curve25519", None)
        // Enable Secure Renegotiation
        .enable("secure-renegotiation", None)
        // Enable DTLS1.3 ClientHello fragmentation
        .enable("dtls-frag-ch", None)
        // Enable SNI
        .enable("sni", None)
        // CFLAGS
        .cflag("-g")
        .cflag("-fPIC")
        .cflag("-DWOLFSSL_DTLS_ALLOW_FUTURE")
        .cflag("-DWOLFSSL_MIN_RSA_BITS=2048")
        .cflag("-DWOLFSSL_MIN_ECC_BITS=256")
        .cflag("-DUSE_CERT_BUFFERS_4096")
        .cflag("-DUSE_CERT_BUFFERS_256")
        .cflag("-DWOLFSSL_NO_SPHINCS");

    if ! cfg!(feature = "cortexm0p") {
        // Enable single precision ASM
        conf.enable("sp-asm", None);
    } else {
        conf.env("CC", "arm-none-eabi-gcc");
        conf.env("LD", "arm-none-eabi-ld");
        conf.env("AR", "arm-none-eabi-ar");
        conf.env("RANLIB", "arm-none-eabi-ranlib");
        conf.env("STRIP", "arm-none-eabi-strip");
        conf.cflag("-specs=rdimon.specs");
        conf.cflag("-DNO_WOLFSSL_DIR");
        conf.cflag("-DWOLFSSL_USER_IO");
        conf.cflag("-DNO_WRITEV");
        conf.cflag("-DTIME_T_NOT_64BIT");
        conf.cflag("-DHAVE_PK_CALLBACKS");
        conf.cflag("-DUSE_WOLF_ARM_STARTUP");
        conf.disable("filesystem", None);
        conf.enable("fastmath", None);
        conf.config_option("host", Some("arm-none-eabi"));
    }

    if cfg!(feature = "debug") {
        conf.enable("debug", None);
        conf.cflag("-DHAVE_SECRET_CALLBACK");
    }

    if cfg!(feature = "postquantum") {
        // Post Quantum support is provided by liboqs
        if let Some(include) = std::env::var_os("DEP_OQS_ROOT") {
            let oqs_path = &include.into_string().unwrap();
            conf.cflag(format!("-I{oqs_path}/build/include/"));
            conf.ldflag(format!("-L{oqs_path}/build/lib/"));
            conf.with("liboqs", None);
        } else {
            panic!("Post Quantum requested but liboqs appears to be missing?");
        }
    }

    if build_target::target_arch().unwrap() == build_target::Arch::X86_64 {
        // Enable Intel ASM optmisations
        conf.enable("intelasm", None);
        // Enable AES hardware acceleration
        conf.enable("aesni", None);
    }

    if ! cfg!(feature = "cortexm0p") {

        if build_target::target_arch().unwrap() == build_target::Arch::AARCH64 {
            // Enable ARM ASM optimisations
            conf.enable("armasm", None);
        }

        if build_target::target_arch().unwrap() == build_target::Arch::ARM {
            // Enable ARM ASM optimisations
            conf.enable("armasm", None);
        }

    }

    // Build and return the config
    conf.build()
}

fn find_exe_dir<P>(exe_name: P) -> Option<PathBuf>
    where P: AsRef<Path>,
{
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).filter_map(|dir| {
            let full_path = dir.join(&exe_name);
            if full_path.is_file() {
                Some(dir)
            } else {
                None
            }
        }).next()
    })
}

fn main() -> std::io::Result<()> {
    // Get the build directory
    let dst_string = env::var("OUT_DIR").unwrap();

    // Extract WolfSSL
    copy_wolfssl(&dst_string)?;

    // Apply patches
    PATCHES.iter().for_each(|&f| apply_patch(&dst_string, f));
    println!("cargo:rerun-if-changed={}", PATCH_DIR);

    // Configure and build WolfSSL
    let dst = build_wolfssl(&dst_string);

    // We want to block some macros as they are incorrectly creating duplicate values
    // https://github.com/rust-lang/rust-bindgen/issues/687
    // TODO: Reach out to tlspuffin and ask if we can incorporate this code and credit them
    let mut hash_ignored_macros = HashSet::new();
    for i in &[
        "IPPORT_RESERVED",
        "EVP_PKEY_DH",
        "BIO_CLOSE",
        "BIO_NOCLOSE",
        "CRYPTO_LOCK",
        "ASN1_STRFLGS_ESC_MSB",
        "SSL_MODE_RELEASE_BUFFERS",
        // Wolfssl 4.3.0
        "GEN_IPADD",
        "EVP_PKEY_RSA",
    ] {
        hash_ignored_macros.insert(i.to_string());
    }

    let ignored_macros = IgnoreMacros(hash_ignored_macros);
    let dst_include = format!("{dst_string}/include");

    let path_eabi_gcc = {
        if cfg!(feature = "cortexm0p") {
            find_exe_dir("arm-none-eabi-gcc")
        } else {
            None
        }
    };

    // Build the Rust binding
    let builder = bindgen::Builder::default()
        .header("wrapper.h")
        .use_core()
        .clang_arg(format!("-I{dst_include}/"));

    let builder = {
        if let Some(p) = path_eabi_gcc {
            if let Some(ps) = p.to_str() {
                builder.clang_arg(format!("-I{ps}/../arm-none-eabi/include"))
            } else {
                builder
            }
        } else {
            builder
        }
    };
    
    let builder = builder.parse_callbacks(Box::new(ignored_macros))
        .formatter(bindgen::Formatter::Rustfmt);

    let builder = builder
        .allowlist_file(format!("{dst_include}/wolfssl/.*.h"))
        .allowlist_file(format!("{dst_include}/wolfssl/wolfcrypt/.*.h"))
        .allowlist_file(format!("{dst_include}/wolfssl/openssl/compat_types.h"));

    let builder = builder.blocklist_function("wolfSSL_BIO_vprintf");

    let bindings: bindgen::Bindings = builder.generate().expect("Unable to generate bindings");

    // Write out the bindings
    bindings
        .write_to_file(dst.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Tell cargo to tell rustc to link in WolfSSL
    println!("cargo:rustc-link-lib=static=wolfssl");

    if cfg!(feature = "postquantum") {
        println!("cargo:rustc-link-lib=static=oqs");
    }

    println!("cargo:rustc-link-search=native={}/lib/", dst_string);

    println!("cargo:include={}", dst_string);

    // Invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // That should do it...
    Ok(())
}

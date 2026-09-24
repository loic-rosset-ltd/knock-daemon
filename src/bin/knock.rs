//! `knock` — the SPA client.
//!
//! A separate binary from `knockd2` on purpose: it runs on an operator's
//! laptop, and asking someone to install a *daemon* in order to send one packet
//! is a bad first impression. No libpcap, no root, one static binary.
//!
//! The daemon answers nothing, ever (`SPA-DESIGN.md` §5), so this program can
//! never report that a door opened — only that a packet left. Every message
//! here is worded to keep that distinction visible; a client that printed
//! "opened!" would be lying about the one thing the protocol cannot tell it.
//!
//! # Why the module is included by path
//!
//! `knock-daemon` is a binary crate with no library target, so a binary cannot
//! `use` another binary's modules. `#[path]` pulls the SPA tree in directly.
//! Most of it is unused here — this binary builds packets and never verifies
//! one, and a `pub use` cannot escape a binary crate — hence the blanket allow
//! on the declaration rather than edits to files this binary does not own.
#[allow(dead_code, unused_imports)]
#[path = "../spa/mod.rs"]
mod spa;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use zeroize::Zeroizing;

use spa::client::{self, Request};
use spa::crypto;

/// Default destination port. Matches fwknop's default so the one number an
/// operator might already have muscle memory for is the same number.
const DEFAULT_PORT: u16 = 62201;

/// Longest opening this client will ask for. The server caps again on its own
/// terms (30 s default, 3600 s max out of the box); this cap exists so a typo
/// like `--duration 600m` is caught here, where there is someone to tell.
const MAX_DURATION_SECS: u32 = 86_400;

/// Tag prefixes, so a pasted line says what it is and a key cannot be fed to
/// the wrong slot. Public lines are shaped like `authorized_keys` entries.
const TAG_ID_PUB: &str = "knock-ed25519";
const TAG_ID_SECRET: &str = "knock-ed25519-secret";
const TAG_SRV_PUB: &str = "knock-x25519";
const TAG_SRV_SECRET: &str = "knock-x25519-secret";

const RC_HELP: &str = "\
rc file (~/.knockrc), TOML, one section per named stanza:

    [default]
    port = 62201
    identity = \"~/.knock/identity\"

    [ssh-prod]
    door = \"ssh\"
    to = \"vps1.example.net\"
    duration = \"5m\"
    server-key = \"knock-x25519 3f2a...\"

then `knock ssh-prod`. A [default] stanza is the base for every other; a named
stanza overrides it, and a command-line flag overrides both.

key sources, in order of preference:
    --identity FILE / $KNOCK_IDENTITY   Ed25519 identity, public-key mode
    --key-file FILE / $KNOCK_PASSPHRASE passphrase, PSK mode (needs --salt)
A key is never accepted as a command-line argument: argv is world-readable in
`ps`. fwknop accepts one and documents it as insecure; this does not.

The daemon replies to nothing, so a successful send is not a confirmed open.";

#[derive(Parser, Debug)]
#[command(
    name = "knock",
    version,
    about = "Single Packet Authorization client for knock-daemon",
    after_long_help = RC_HELP,
    subcommand_precedence_over_arg = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    send: SendArgs,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a server X25519 keypair and a client Ed25519 identity.
    Keygen(KeygenArgs),
}

#[derive(Args, Debug)]
struct SendArgs {
    /// Stanza in the rc file to take defaults from.
    #[arg(value_name = "STANZA")]
    stanza: Option<String>,

    /// Door to ask the server to open.
    #[arg(short, long)]
    door: Option<String>,

    /// Server hostname or address.
    #[arg(short, long)]
    to: Option<String>,

    /// UDP destination port.
    #[arg(short, long)]
    port: Option<u16>,

    /// How long to hold the door open, e.g. 90s, 5m, 1h. Omit for the server's
    /// default; the server caps it either way.
    #[arg(long, value_name = "DURATION")]
    duration: Option<String>,

    /// Ask the server to authorise this address instead of the source it
    /// observes. Opt-in on both sides and usually wrong — see SPA-DESIGN.md §6.
    #[arg(long, value_name = "ADDR")]
    source: Option<String>,

    /// File holding the PSK passphrase (first line). PSK mode.
    #[arg(long, value_name = "FILE")]
    key_file: Option<String>,

    /// PSK salt. Must match the server's configured salt exactly.
    #[arg(long, value_name = "SALT")]
    salt: Option<String>,

    /// File holding the client Ed25519 identity. Public-key mode.
    #[arg(short, long, value_name = "FILE")]
    identity: Option<String>,

    /// Server X25519 public key: a `knock-x25519 <hex>` line, bare hex, or a
    /// path to the `.pub` file. Public-key mode.
    #[arg(long, value_name = "KEY|FILE")]
    server_key: Option<String>,

    /// rc file to read.
    #[arg(long, value_name = "FILE", default_value = "~/.knockrc")]
    rc: String,

    /// Ignore the rc file entirely.
    #[arg(long)]
    no_rc: bool,

    /// Resolve the destination as IPv4 only.
    #[arg(short = '4', conflicts_with = "ipv6")]
    ipv4: bool,

    /// Resolve the destination as IPv6 only.
    #[arg(short = '6')]
    ipv6: bool,

    /// Build the packet and hex-dump it; send nothing, resolve nothing.
    #[arg(short = 'T', long)]
    dry_run: bool,

    /// Say what was sent, where, and in which mode.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args, Debug)]
struct KeygenArgs {
    /// Directory to write key files into.
    #[arg(long, value_name = "DIR", default_value = "~/.knock")]
    out_dir: String,

    /// Comment appended to the public identity line, as in `authorized_keys`.
    #[arg(long, value_name = "TEXT")]
    comment: Option<String>,

    /// Overwrite existing key files.
    #[arg(long)]
    force: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Keygen(args)) => run_keygen(&args),
        None => run_send(&cli.send),
    }
}

// ---- sending ---------------------------------------------------------------

fn run_send(args: &SendArgs) -> Result<()> {
    let merged = merge_sources(args)?;
    let plan = Plan::resolve(&merged)?;
    let keys = load_keys(&merged)?;

    // The only clock read in the program. Everything downstream takes it as a
    // parameter, which is what makes the builders testable at all.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs();

    let req = Request {
        door: plan.door.clone(),
        duration_secs: plan.duration_secs,
        addr: plan.addr,
    };
    let packet = match &keys {
        Keys::PublicKey {
            identity,
            server_pub,
        } => client::build_public_key(server_pub, identity, &req, now)?,
        Keys::Psk { key } => client::build_psk(key, &req, now)?,
    };

    if args.dry_run {
        println!(
            "{} mode, door \"{}\", {}, {} bytes → {}:{} (not sent)",
            keys.mode_name(),
            plan.door,
            describe_duration(plan.duration_secs),
            packet.len(),
            plan.host,
            plan.port
        );
        print!("{}", hex_dump(&packet));
        return Ok(());
    }

    let dest = resolve_dest(&plan.host, plan.port, args.ipv4, args.ipv6)?;
    // Bind in the destination's family; the kernel picks the source address,
    // which is precisely the address the server will authorise.
    let bind: SocketAddr = if dest.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).context("binding a local UDP socket")?;
    sock.send_to(&packet, dest)
        .with_context(|| format!("sending to {dest}"))?;

    if args.verbose {
        println!(
            "sent {} bytes to {dest} — {} mode, door \"{}\", {}.\n\
             The daemon never replies, so this confirms the packet left, nothing more.",
            packet.len(),
            keys.mode_name(),
            plan.door,
            describe_duration(plan.duration_secs),
        );
    }
    Ok(())
}

/// Everything needed to build and address a packet, with the key material
/// deliberately left out so this half can be resolved and tested without
/// touching the filesystem.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    door: String,
    host: String,
    port: u16,
    duration_secs: u32,
    addr: Option<IpAddr>,
}

impl Plan {
    fn resolve(s: &Stanza) -> Result<Self> {
        let door = s
            .door
            .clone()
            .ok_or_else(|| anyhow!("no door: pass --door, or name a stanza that sets one"))?;
        let host = s
            .to
            .clone()
            .ok_or_else(|| anyhow!("no destination: pass --to, or name a stanza that sets one"))?;
        let duration_secs = match &s.duration {
            Some(d) => parse_duration(d)?,
            None => 0,
        };
        let addr = match &s.source {
            Some(a) => Some(
                a.parse::<IpAddr>()
                    .with_context(|| format!("--source {a:?} is not an IP address"))?,
            ),
            None => None,
        };
        Ok(Plan {
            door,
            host,
            port: s.port.unwrap_or(DEFAULT_PORT),
            duration_secs,
            addr,
        })
    }
}

/// Resolved key material. Mode follows from what is configured: public-key mode
/// wins when a complete pair is available, because it is the mode
/// `SPA-DESIGN.md` §2 recommends and the only one where a stolen server config
/// authorises nothing.
// A `SigningKey` makes this ~264 bytes. Boxing it to even the variants out
// would buy an allocation and an indirection for one value that lives for one
// packet on the stack of a program that then exits.
#[allow(clippy::large_enum_variant)]
enum Keys {
    PublicKey {
        identity: SigningKey,
        server_pub: [u8; 32],
    },
    Psk {
        key: crypto::SymKey,
    },
}

impl Keys {
    fn mode_name(&self) -> &'static str {
        match self {
            Keys::PublicKey { .. } => "public-key",
            Keys::Psk { .. } => "PSK",
        }
    }
}

fn load_keys(s: &Stanza) -> Result<Keys> {
    let identity_path = s
        .identity
        .clone()
        .or_else(|| std::env::var("KNOCK_IDENTITY").ok());

    if let (Some(id), Some(srv)) = (&identity_path, &s.server_key) {
        let secret = read_private_key(Path::new(&expand_tilde(id)), TAG_ID_SECRET)
            .with_context(|| format!("reading identity {id}"))?;
        let server_pub = read_server_key(srv)?;
        return Ok(Keys::PublicKey {
            identity: SigningKey::from_bytes(&secret),
            server_pub,
        });
    }

    let passphrase = match &s.key_file {
        Some(p) => Some(read_passphrase_file(Path::new(&expand_tilde(p)))?),
        None => std::env::var("KNOCK_PASSPHRASE").ok().map(Zeroizing::new),
    };
    if let Some(pass) = passphrase {
        let salt = s.salt.as_ref().ok_or_else(|| {
            anyhow!("PSK mode needs --salt, matching the salt in the server's config exactly")
        })?;
        // Argon2id at 64 MiB, once. The same deliberate cost the server pays at
        // startup — it is what makes an offline attack on the passphrase slow.
        let key = crypto::derive_psk(pass.as_bytes(), salt.as_bytes())
            .map_err(|e| anyhow!("deriving the PSK: {e}"))?;
        return Ok(Keys::Psk { key });
    }

    // Name the two complete recipes rather than the missing field, so the fix
    // is visible from the error alone.
    match (identity_path.is_some(), s.server_key.is_some()) {
        (true, false) => {
            bail!("an identity is set but --server-key is not; public-key mode needs both")
        }
        (false, true) => {
            bail!("--server-key is set but no identity is; pass --identity or $KNOCK_IDENTITY")
        }
        _ => bail!(
            "no key: pass --identity plus --server-key (public-key mode), or \
             --key-file/$KNOCK_PASSPHRASE plus --salt (PSK mode)"
        ),
    }
}

/// Pick one destination address, honouring a forced family.
fn resolve_dest(host: &str, port: u16, want4: bool, want6: bool) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}"))?
        .collect();
    let chosen = addrs
        .iter()
        .find(|a| (!want4 || a.is_ipv4()) && (!want6 || a.is_ipv6()));
    match chosen {
        Some(a) => Ok(*a),
        None if addrs.is_empty() => bail!("{host} resolved to no addresses"),
        None => bail!(
            "{host} resolved to {} address(es), none of them {}",
            addrs.len(),
            if want4 { "IPv4" } else { "IPv6" }
        ),
    }
}

// ---- rc file ---------------------------------------------------------------

/// One named set of defaults. Every field optional: a stanza is a patch over
/// the ones below it, not a complete configuration.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Stanza {
    door: Option<String>,
    to: Option<String>,
    port: Option<u16>,
    duration: Option<String>,
    source: Option<String>,
    key_file: Option<String>,
    salt: Option<String>,
    identity: Option<String>,
    server_key: Option<String>,
}

impl Stanza {
    /// `over` wins field by field. Returning a new value rather than mutating
    /// keeps the precedence chain readable at the call site.
    fn overlay(self, over: Stanza) -> Stanza {
        Stanza {
            door: over.door.or(self.door),
            to: over.to.or(self.to),
            port: over.port.or(self.port),
            duration: over.duration.or(self.duration),
            source: over.source.or(self.source),
            key_file: over.key_file.or(self.key_file),
            salt: over.salt.or(self.salt),
            identity: over.identity.or(self.identity),
            server_key: over.server_key.or(self.server_key),
        }
    }
}

/// The stanza every other one is layered on top of.
const DEFAULT_STANZA: &str = "default";

type RcFile = BTreeMap<String, Stanza>;

fn parse_rc(text: &str) -> Result<RcFile> {
    toml::from_str(text).context("parsing the rc file")
}

/// `[default]`, then the named stanza. A named stanza that is not there is an
/// error naming what is — a silent fallback to defaults would send a packet
/// somewhere the operator did not ask for.
fn stanza_from_rc(rc: &RcFile, name: Option<&str>) -> Result<Stanza> {
    let base = rc.get(DEFAULT_STANZA).cloned().unwrap_or_default();
    let Some(name) = name else { return Ok(base) };
    if name == DEFAULT_STANZA {
        return Ok(base);
    }
    let named = rc.get(name).ok_or_else(|| {
        let known: Vec<&str> = rc
            .keys()
            .filter(|k| k.as_str() != DEFAULT_STANZA)
            .map(String::as_str)
            .collect();
        if known.is_empty() {
            anyhow!("no stanza \"{name}\" in the rc file, which defines none")
        } else {
            anyhow!(
                "no stanza \"{name}\" in the rc file; it defines: {}",
                known.join(", ")
            )
        }
    })?;
    Ok(base.overlay(named.clone()))
}

/// Flags, as a stanza, so command-line and rc-file values merge by one rule.
fn cli_stanza(a: &SendArgs) -> Stanza {
    Stanza {
        door: a.door.clone(),
        to: a.to.clone(),
        port: a.port,
        duration: a.duration.clone(),
        source: a.source.clone(),
        key_file: a.key_file.clone(),
        salt: a.salt.clone(),
        identity: a.identity.clone(),
        server_key: a.server_key.clone(),
    }
}

/// rc `[default]` → named stanza → command line, each overriding the last.
fn merge_sources(a: &SendArgs) -> Result<Stanza> {
    let from_rc = if a.no_rc {
        Stanza::default()
    } else {
        let path = expand_tilde(&a.rc);
        match std::fs::read_to_string(&path) {
            Ok(text) => stanza_from_rc(
                &parse_rc(&text).with_context(|| path.clone())?,
                a.stanza.as_deref(),
            )?,
            // No rc file is normal; naming a stanza when there is none is not.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(name) = &a.stanza {
                    bail!("no stanza \"{name}\": {path} does not exist");
                }
                Stanza::default()
            }
            Err(e) => return Err(e).with_context(|| format!("reading {path}")),
        }
    };
    Ok(from_rc.overlay(cli_stanza(a)))
}

// ---- keygen ----------------------------------------------------------------

fn run_keygen(args: &KeygenArgs) -> Result<()> {
    let dir = PathBuf::from(expand_tilde(&args.out_dir));
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let id_path = dir.join("identity");
    let id_pub_path = dir.join("identity.pub");
    let srv_path = dir.join("server-key");
    let srv_pub_path = dir.join("server-key.pub");
    for p in [&id_path, &id_pub_path, &srv_path, &srv_pub_path] {
        if p.exists() && !args.force {
            bail!("{} already exists; pass --force to overwrite", p.display());
        }
    }

    let comment = args.comment.clone().unwrap_or_else(default_comment);
    let (id_secret, id_public) = client::generate_identity();
    let (srv_secret, srv_public) = client::generate_static_keypair();

    let id_pub_line = format!("{TAG_ID_PUB} {} {comment}\n", hex_encode(&id_public));
    let srv_pub_line = format!("{TAG_SRV_PUB} {}\n", hex_encode(&srv_public));

    write_private(
        &id_path,
        &format!("{TAG_ID_SECRET} {}\n", hex_encode(&id_secret)),
    )?;
    write_private(
        &srv_path,
        &format!("{TAG_SRV_SECRET} {}\n", hex_encode(&srv_secret)),
    )?;
    std::fs::write(&id_pub_path, &id_pub_line)
        .with_context(|| format!("writing {}", id_pub_path.display()))?;
    std::fs::write(&srv_pub_path, &srv_pub_line)
        .with_context(|| format!("writing {}", srv_pub_path.display()))?;

    println!(
        "client identity  {}  (keep; mode 0600)\n\
         server static    {}  (copy to the server; mode 0600)\n\n\
         Put this line in the server's authorized keys:\n\n    {}\n\
         Give this to the client as --server-key / rc `server-key`:\n\n    {}",
        id_path.display(),
        srv_path.display(),
        id_pub_line,
        srv_pub_line
    );
    Ok(())
}

fn default_comment() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "knock".into());
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "local".into());
    format!("{user}@{host}")
}

/// Create with mode 0600 from the outset. Writing then chmod-ing would leave a
/// window where the private key is world-readable.
fn write_private(path: &Path, contents: &str) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    // An existing file keeps its old mode, so --force must tighten it too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 600 {}", path.display()))?;
    }
    Ok(())
}

// ---- key files -------------------------------------------------------------

fn read_private_key(path: &Path, tag: &str) -> Result<[u8; 32]> {
    refuse_loose_permissions(path)?;
    let text = std::fs::read_to_string(path).with_context(|| format!("{}", path.display()))?;
    parse_key_line(&text, tag)
}

/// The server key is public, so it may be given inline. Anything that parses as
/// a key is one; anything else is treated as a path.
fn read_server_key(value: &str) -> Result<[u8; 32]> {
    if let Ok(k) = parse_key_line(value, TAG_SRV_PUB) {
        return Ok(k);
    }
    let path = expand_tilde(value);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("--server-key {value:?} is neither a key nor a readable file"))?;
    parse_key_line(&text, TAG_SRV_PUB)
}

/// A tagged line (`knock-x25519 <hex>`), or bare hex for convenience when
/// pasting. Blank lines and `#` comments are skipped.
fn parse_key_line(text: &str, tag: &str) -> Result<[u8; 32]> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let hex = match line.split_whitespace().collect::<Vec<_>>()[..] {
            [t, h, ..] if t == tag => h,
            [h] => h,
            [t, ..] => bail!("expected a {tag} line, found a {t:?} one"),
            [] => continue,
        };
        let bytes = hex_decode(hex)?;
        return <[u8; 32]>::try_from(&bytes[..])
            .map_err(|_| anyhow!("a key must be 32 bytes, this one is {}", bytes.len()));
    }
    bail!("no key found (expected a {tag} line)")
}

fn read_passphrase_file(path: &Path) -> Result<Zeroizing<String>> {
    refuse_loose_permissions(path)?;
    let text = std::fs::read_to_string(path).with_context(|| format!("{}", path.display()))?;
    let first = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| anyhow!("{} is empty", path.display()))?;
    // Only the trailing newline is stripped: a passphrase may legitimately
    // begin or end with a space, and silently trimming it would produce a
    // wrong key with no way to tell.
    Ok(Zeroizing::new(
        first.trim_end_matches(['\r', '\n']).to_string(),
    ))
}

/// ssh's rule, for ssh's reason: a private key other users can read is not
/// private. Refusing beats warning — a warning scrolls past.
#[cfg(unix)]
fn refuse_loose_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("{}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "{} is mode {:04o}, readable by others; run: chmod 600 {}",
            path.display(),
            mode,
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn refuse_loose_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

// ---- small helpers ---------------------------------------------------------

/// `~` only, and only at the start. Not a shell: `~other` is left alone rather
/// than guessed at.
fn expand_tilde(path: &str) -> String {
    let Some(rest) = path.strip_prefix('~') else {
        return path.to_string();
    };
    if !(rest.is_empty() || rest.starts_with('/')) {
        return path.to_string();
    }
    match std::env::var("HOME") {
        Ok(home) => format!("{home}{rest}"),
        Err(_) => path.to_string(),
    }
}

/// `90`, `90s`, `5m`, `2h`. A bare number is seconds, as everywhere else in
/// this project's config.
fn parse_duration(s: &str) -> Result<u32> {
    let s = s.trim();
    let (digits, mult) = match s.chars().last() {
        Some('s') | Some('S') => (&s[..s.len() - 1], 1u64),
        Some('m') | Some('M') => (&s[..s.len() - 1], 60),
        Some('h') | Some('H') => (&s[..s.len() - 1], 3600),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => bail!("bad duration {s:?}: expected e.g. 90, 90s, 5m, 2h"),
    };
    // Not trimmed again: `s` was trimmed on the way in, so any space left here
    // is interior ("5 m"), which is a typo and not a duration.
    let n: u64 = digits
        .parse()
        .map_err(|_| anyhow!("bad duration {s:?}: expected e.g. 90, 90s, 5m, 2h"))?;
    // Saturating, then clamped: 4294967296h must not wrap into a small number.
    Ok(n.saturating_mul(mult).min(MAX_DURATION_SECS as u64) as u32)
}

fn describe_duration(secs: u32) -> String {
    if secs == 0 {
        "the server's default duration".to_string()
    } else {
        format!("{secs}s")
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex string has an odd length ({})", s.len());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| anyhow!("{:?} is not hexadecimal", &s[i..i + 2]))
        })
        .collect()
}

/// `xxd`-style, so a dry-run dump can be diffed against a capture by eye.
fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!(
            "{:08x}  {:<47}  |{}|\n",
            i * 16,
            hex.join(" "),
            ascii
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rc_text() -> &'static str {
        "\
[default]
port = 62201
identity = \"~/.knock/identity\"

[ssh-prod]
door = \"ssh\"
to = \"vps1.example.net\"
duration = \"5m\"

[web]
door = \"https\"
to = \"vps2.example.net\"
port = 51000
"
    }

    /// Flags only, no rc file, the shape `merge_sources` is given in tests.
    fn send_args(stanza: Option<&str>) -> SendArgs {
        SendArgs {
            stanza: stanza.map(String::from),
            door: None,
            to: None,
            port: None,
            duration: None,
            source: None,
            key_file: None,
            salt: None,
            identity: None,
            server_key: None,
            rc: "~/.knockrc".into(),
            no_rc: true,
            ipv4: false,
            ipv6: false,
            dry_run: false,
            verbose: false,
        }
    }

    // ---- rc file ---------------------------------------------------------

    #[test]
    fn a_named_stanza_supplies_every_field_it_sets() {
        let rc = parse_rc(rc_text()).unwrap();
        let s = stanza_from_rc(&rc, Some("ssh-prod")).unwrap();
        let plan = Plan::resolve(&s).unwrap();
        assert_eq!(plan.door, "ssh");
        assert_eq!(plan.host, "vps1.example.net");
        assert_eq!(plan.port, 62201, "inherited from [default]");
        assert_eq!(plan.duration_secs, 300);
    }

    #[test]
    fn a_named_stanza_overrides_the_default_stanza() {
        let rc = parse_rc(rc_text()).unwrap();
        let s = stanza_from_rc(&rc, Some("web")).unwrap();
        assert_eq!(Plan::resolve(&s).unwrap().port, 51000);
        // and inherits what it does not set
        assert_eq!(s.identity.as_deref(), Some("~/.knock/identity"));
    }

    #[test]
    fn a_command_line_flag_overrides_the_stanza() {
        let rc = parse_rc(rc_text()).unwrap();
        let from_rc = stanza_from_rc(&rc, Some("ssh-prod")).unwrap();
        let mut args = send_args(Some("ssh-prod"));
        args.port = Some(40000);
        args.duration = Some("30s".into());

        let plan = Plan::resolve(&from_rc.overlay(cli_stanza(&args))).unwrap();
        assert_eq!(plan.port, 40000);
        assert_eq!(plan.duration_secs, 30);
        assert_eq!(plan.door, "ssh", "untouched fields still come from the rc");
    }

    /// Falling back to the defaults would send a packet the operator never
    /// asked for, so a missing stanza must stop the run — and say what exists.
    #[test]
    fn a_missing_stanza_is_a_clean_error_that_lists_what_exists() {
        let rc = parse_rc(rc_text()).unwrap();
        let e = stanza_from_rc(&rc, Some("stagin")).unwrap_err().to_string();
        assert!(e.contains("stagin"), "{e}");
        assert!(e.contains("ssh-prod") && e.contains("web"), "{e}");
        assert!(
            !e.contains(DEFAULT_STANZA),
            "the base stanza is not a target: {e}"
        );
    }

    #[test]
    fn no_stanza_named_means_the_default_stanza_alone() {
        let rc = parse_rc(rc_text()).unwrap();
        let s = stanza_from_rc(&rc, None).unwrap();
        assert_eq!(s.port, Some(62201));
        assert_eq!(s.door, None);
        assert!(Plan::resolve(&s)
            .unwrap_err()
            .to_string()
            .contains("no door"));
    }

    #[test]
    fn an_rc_file_with_no_default_stanza_is_fine() {
        let rc = parse_rc("[a]\ndoor = \"ssh\"\nto = \"h\"\n").unwrap();
        assert_eq!(
            Plan::resolve(&stanza_from_rc(&rc, Some("a")).unwrap())
                .unwrap()
                .port,
            DEFAULT_PORT
        );
    }

    /// A typo in a key name must be an error, not a silently ignored setting
    /// that leaves the operator wondering why `--duration` had no effect.
    #[test]
    fn an_unknown_key_in_a_stanza_is_rejected() {
        let e = parse_rc("[a]\ndurration = \"5m\"\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("parsing the rc file"), "{e}");
    }

    #[test]
    fn stanza_keys_are_kebab_case_on_the_wire() {
        let rc = parse_rc("[a]\nserver-key = \"knock-x25519 aa\"\nkey-file = \"/k\"\n").unwrap();
        let s = &rc["a"];
        assert_eq!(s.server_key.as_deref(), Some("knock-x25519 aa"));
        assert_eq!(s.key_file.as_deref(), Some("/k"));
    }

    // ---- duration --------------------------------------------------------

    #[test]
    fn parses_every_duration_suffix_and_a_bare_number() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration(" 45s ").unwrap(), 45);
    }

    #[test]
    fn an_absurd_duration_is_clamped_rather_than_wrapped() {
        assert_eq!(parse_duration("99999h").unwrap(), MAX_DURATION_SECS);
        // The case the clamp exists for: this overflows u32 seconds outright.
        assert_eq!(parse_duration("4294967296h").unwrap(), MAX_DURATION_SECS);
        assert_eq!(parse_duration("86401s").unwrap(), MAX_DURATION_SECS);
    }

    #[test]
    fn rejects_nonsense_durations() {
        for bad in ["", "soon", "5d", "-5s", "5 m", "m"] {
            assert!(parse_duration(bad).is_err(), "{bad:?} should not parse");
        }
    }

    // ---- key lines -------------------------------------------------------

    #[test]
    fn hex_round_trips_and_rejects_malformed_input() {
        let bytes: Vec<u8> = (0..32u8).collect();
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
        assert!(hex_decode("abc").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn parses_a_tagged_key_line_a_bare_one_and_skips_comments() {
        let hex = hex_encode(&[7u8; 32]);
        for text in [
            format!("{TAG_SRV_PUB} {hex}\n"),
            format!("# a comment\n\n{TAG_SRV_PUB} {hex} extra words\n"),
            format!("{hex}\n"),
        ] {
            assert_eq!(parse_key_line(&text, TAG_SRV_PUB).unwrap(), [7u8; 32]);
        }
    }

    /// Feeding a private key where a public one belongs must be caught by the
    /// tag rather than accepted as 32 bytes that happen to fit.
    #[test]
    fn a_key_with_the_wrong_tag_is_refused() {
        let line = format!("{TAG_ID_SECRET} {}\n", hex_encode(&[1u8; 32]));
        let e = parse_key_line(&line, TAG_SRV_PUB).unwrap_err().to_string();
        assert!(e.contains(TAG_SRV_PUB), "{e}");
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        let e = parse_key_line("aabbcc\n", TAG_SRV_PUB)
            .unwrap_err()
            .to_string();
        assert!(e.contains("32 bytes"), "{e}");
        assert!(parse_key_line("", TAG_SRV_PUB).is_err());
    }

    // ---- misc ------------------------------------------------------------

    #[test]
    fn expands_a_leading_tilde_only() {
        std::env::set_var("HOME", "/home/u");
        assert_eq!(expand_tilde("~/.knockrc"), "/home/u/.knockrc");
        assert_eq!(expand_tilde("~"), "/home/u");
        assert_eq!(expand_tilde("/etc/knockrc"), "/etc/knockrc");
        assert_eq!(expand_tilde("~other/x"), "~other/x");
        assert_eq!(expand_tilde("a/~/b"), "a/~/b");
    }

    #[test]
    fn hex_dump_is_sixteen_bytes_a_line_with_printable_ascii() {
        let dump = hex_dump(b"KSPA\x01\x01abcdefghij\xff");
        let lines: Vec<&str> = dump.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].starts_with("00000000  4b 53 50 41 01 01"),
            "{}",
            lines[0]
        );
        assert!(lines[0].ends_with("|KSPA..abcdefghij|"), "{}", lines[0]);
        assert!(lines[1].starts_with("00000010  ff"), "{}", lines[1]);
    }

    #[test]
    fn a_zero_duration_is_described_as_the_servers_choice() {
        assert_eq!(describe_duration(0), "the server's default duration");
        assert_eq!(describe_duration(60), "60s");
    }

    /// clap's own consistency check. Catches a conflicting short flag or a
    /// duplicated long name at test time rather than at first run.
    #[test]
    fn the_command_line_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    /// `keygen` is a subcommand and a stanza name is a positional, so the two
    /// must not be confusable.
    #[test]
    fn keygen_is_parsed_as_a_subcommand_not_a_stanza_name() {
        let cli = Cli::try_parse_from(["knock", "keygen"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Keygen(_))));

        let cli = Cli::try_parse_from(["knock", "ssh-prod"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.send.stanza.as_deref(), Some("ssh-prod"));
    }

    /// A raw key on the command line would be visible in `ps` to every user on
    /// the machine. fwknop accepts one; this must never grow the option.
    #[test]
    fn no_flag_accepts_raw_key_material() {
        use clap::CommandFactory;
        for arg in Cli::command().get_arguments() {
            let name = arg.get_id().as_str();
            assert!(
                !matches!(name, "key" | "passphrase" | "psk" | "secret"),
                "{name} would put key material in argv"
            );
        }
    }
}

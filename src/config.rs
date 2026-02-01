use crate::version;
use clap::Parser;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_FILENAME: &str = "dnsseeder.conf";
const DEFAULT_LOG_FILENAME: &str = "dnsseeder.log";
const DEFAULT_ERR_LOG_FILENAME: &str = "dnsseeder_err.log";
const DEFAULT_LISTEN_PORT: &str = "5354";
const DEFAULT_GRPC_LISTEN_PORT: &str = "3737";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_THREADS: u8 = 8;
const DEFAULT_TESTNET_SUFFIX: u16 = 10;

static ACTIVE_CONFIG: OnceCell<Config> = OnceCell::new();
static PEERS_DEFAULT_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

#[derive(Debug, Clone)]
pub struct NetworkParams {
    pub name: String,
    pub default_port: String,
    pub dns_seeds: Vec<String>,
    pub accept_unroutable: bool,
}

struct TestnetVariant {
    suffix: u16,
    name: &'static str,
    default_port: &'static str,
    dns_seeds: &'static [&'static str],
    accept_unroutable: bool,
}

const TESTNET_VARIANTS: &[TestnetVariant] = &[
    TestnetVariant {
        suffix: 10,
        name: "kaspa-testnet-10",
        default_port: "16211",
        dns_seeds: &["testnet-10-dnsseed.kas.pa"],
        accept_unroutable: false,
    },
    TestnetVariant {
        suffix: 12,
        name: "kaspa-testnet-12",
        default_port: "16311",
        dns_seeds: &["testnet-12-dnsseed.kas.pa"],
        accept_unroutable: false,
    },
];

#[derive(Debug, Clone)]
pub struct NetworkFlags {
    pub testnet: bool,
    pub simnet: bool,
    pub devnet: bool,
    pub override_dag_params_file: Option<String>,
    pub active_net_params: NetworkParams,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub app_dir: String,
    pub known_peers: String,
    #[allow(dead_code)]
    pub show_version: bool,
    pub host: String,
    pub listen: String,
    pub nameserver: String,
    pub seeder: String,
    pub profile: String,
    pub grpc_listen: String,
    pub min_proto_ver: u8,
    pub min_ua_ver: String,
    pub net_suffix: Option<u16>,
    pub no_log_files: bool,
    pub log_level: String,
    pub threads: u8,
    pub network: NetworkFlags,
}

#[derive(clap::Parser, Debug)]
#[command(disable_help_subcommand = true, disable_version_flag = true)]
struct CliArgs {
    #[arg(short = 'b', long = "appdir")]
    app_dir: Option<String>,
    #[arg(short = 'p', long = "peers")]
    known_peers: Option<String>,
    #[arg(short = 'V', long = "version", action = clap::ArgAction::SetTrue)]
    show_version: bool,
    #[arg(short = 'H', long = "host")]
    host: Option<String>,
    #[arg(short = 'l', long = "listen")]
    listen: Option<String>,
    #[arg(short = 'n', long = "nameserver")]
    nameserver: Option<String>,
    #[arg(short = 's', long = "default-seeder")]
    seeder: Option<String>,
    #[arg(long = "profile")]
    profile: Option<String>,
    #[arg(long = "grpclisten")]
    grpc_listen: Option<String>,
    #[arg(short = 'v', long = "minprotocolversion")]
    min_proto_ver: Option<u8>,
    #[arg(long = "minuseragentversion")]
    min_ua_ver: Option<String>,
    #[arg(long = "netsuffix")]
    net_suffix: Option<u16>,
    #[arg(long = "nologfiles", action = clap::ArgAction::SetTrue)]
    no_log_files: bool,
    #[arg(long = "loglevel")]
    log_level: Option<String>,
    #[arg(long = "threads")]
    threads: Option<u8>,
    #[arg(long = "testnet", action = clap::ArgAction::SetTrue)]
    testnet: bool,
    #[arg(long = "simnet", action = clap::ArgAction::SetTrue)]
    simnet: bool,
    #[arg(long = "devnet", action = clap::ArgAction::SetTrue)]
    devnet: bool,
    #[arg(long = "override-dag-params-file")]
    override_dag_params_file: Option<String>,
}

#[derive(Default)]
struct ConfigOverrides {
    app_dir: Option<String>,
    known_peers: Option<String>,
    host: Option<String>,
    listen: Option<String>,
    nameserver: Option<String>,
    seeder: Option<String>,
    profile: Option<String>,
    grpc_listen: Option<String>,
    min_proto_ver: Option<u8>,
    min_ua_ver: Option<String>,
    net_suffix: Option<u16>,
    no_log_files: Option<bool>,
    log_level: Option<String>,
    threads: Option<u8>,
    testnet: Option<bool>,
    simnet: Option<bool>,
    devnet: Option<bool>,
    override_dag_params_file: Option<String>,
}

pub fn active_config() -> &'static Config {
    ACTIVE_CONFIG.get().expect("active config not set")
}

pub fn set_active_config(cfg: Config) -> Result<(), String> {
    ACTIVE_CONFIG
        .set(cfg)
        .map_err(|_| "active config already set".to_string())?;
    Ok(())
}

pub fn peers_default_port() -> u16 {
    PEERS_DEFAULT_PORT.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_peers_default_port(port: u16) {
    PEERS_DEFAULT_PORT.store(port, std::sync::atomic::Ordering::Relaxed);
}

pub fn load_config() -> Result<Config, String> {
    let default_app_dir = default_app_dir("dnsseeder");
    let default_config_file = Path::new(&default_app_dir).join(DEFAULT_CONFIG_FILENAME);

    let mut cfg = Config {
        app_dir: default_app_dir.clone(),
        known_peers: String::new(),
        show_version: false,
        host: String::new(),
        listen: normalize_address("localhost", DEFAULT_LISTEN_PORT),
        nameserver: String::new(),
        seeder: String::new(),
        profile: String::new(),
        grpc_listen: normalize_address("localhost", DEFAULT_GRPC_LISTEN_PORT),
        min_proto_ver: 0,
        min_ua_ver: String::new(),
        net_suffix: None,
        no_log_files: false,
        log_level: DEFAULT_LOG_LEVEL.to_string(),
        threads: DEFAULT_THREADS,
        network: NetworkFlags {
            testnet: false,
            simnet: false,
            devnet: false,
            override_dag_params_file: None,
            active_net_params: mainnet_params(),
        },
    };

    let cli = CliArgs::parse();
    if cli.show_version {
        let app_name = env::args()
            .next()
            .unwrap_or_else(|| "dnsseeder".to_string());
        println!("{} version {}", app_name, version::version());
        std::process::exit(0);
    }

    let mut overrides = ConfigOverrides::default();
    if default_config_file.exists() {
        let file_overrides = parse_config_file(&default_config_file)?;
        overrides = merge_overrides(overrides, file_overrides);
    }

    overrides = merge_overrides(overrides, overrides_from_cli(&cli));
    apply_overrides(&mut cfg, overrides);

    if cfg.host.is_empty() {
        return Err("Please specify a hostname".to_string());
    }
    if cfg.nameserver.is_empty() {
        return Err("Please specify a nameserver".to_string());
    }

    cfg.listen = normalize_address(&cfg.listen, DEFAULT_LISTEN_PORT);

    resolve_network(&mut cfg, &cli)?;

    cfg.app_dir = clean_and_expand_path(&cfg.app_dir, &default_app_dir);
    cfg.app_dir = Path::new(&cfg.app_dir)
        .join(&cfg.network.active_net_params.name)
        .to_string_lossy()
        .to_string();

    create_path_if_needed(&cfg.app_dir)?;

    if !cfg.profile.is_empty() {
        let port: u32 = cfg
            .profile
            .parse()
            .map_err(|_| "The profile port must be between 1024 and 65535".to_string())?;
        if !(1024..=65535).contains(&port) {
            return Err("The profile port must be between 1024 and 65535".to_string());
        }
    }

    if cfg.threads < 1 || cfg.threads > 32 {
        return Err("threads must be between 1 and 32".to_string());
    }

    Ok(cfg)
}

pub fn log_paths(cfg: &Config) -> (String, String) {
    let log = Path::new(&cfg.app_dir)
        .join(DEFAULT_LOG_FILENAME)
        .to_string_lossy()
        .to_string();
    let err = Path::new(&cfg.app_dir)
        .join(DEFAULT_ERR_LOG_FILENAME)
        .to_string_lossy()
        .to_string();
    (log, err)
}

fn overrides_from_cli(cli: &CliArgs) -> ConfigOverrides {
    ConfigOverrides {
        app_dir: cli.app_dir.clone(),
        known_peers: cli.known_peers.clone(),
        host: cli.host.clone(),
        listen: cli.listen.clone(),
        nameserver: cli.nameserver.clone(),
        seeder: cli.seeder.clone(),
        profile: cli.profile.clone(),
        grpc_listen: cli.grpc_listen.clone(),
        min_proto_ver: cli.min_proto_ver,
        min_ua_ver: cli.min_ua_ver.clone(),
        net_suffix: cli.net_suffix,
        no_log_files: if cli.no_log_files { Some(true) } else { None },
        log_level: cli.log_level.clone(),
        threads: cli.threads,
        testnet: if cli.testnet { Some(true) } else { None },
        simnet: if cli.simnet { Some(true) } else { None },
        devnet: if cli.devnet { Some(true) } else { None },
        override_dag_params_file: cli.override_dag_params_file.clone(),
    }
}

fn merge_overrides(mut base: ConfigOverrides, other: ConfigOverrides) -> ConfigOverrides {
    macro_rules! merge_field {
        ($field:ident) => {
            if other.$field.is_some() {
                base.$field = other.$field;
            }
        };
    }

    merge_field!(app_dir);
    merge_field!(known_peers);
    merge_field!(host);
    merge_field!(listen);
    merge_field!(nameserver);
    merge_field!(seeder);
    merge_field!(profile);
    merge_field!(grpc_listen);
    merge_field!(min_proto_ver);
    merge_field!(min_ua_ver);
    merge_field!(net_suffix);
    merge_field!(no_log_files);
    merge_field!(log_level);
    merge_field!(threads);
    merge_field!(testnet);
    merge_field!(simnet);
    merge_field!(devnet);
    merge_field!(override_dag_params_file);

    base
}

fn apply_overrides(cfg: &mut Config, overrides: ConfigOverrides) {
    if let Some(app_dir) = overrides.app_dir {
        cfg.app_dir = app_dir;
    }
    if let Some(known_peers) = overrides.known_peers {
        cfg.known_peers = known_peers;
    }
    if let Some(host) = overrides.host {
        cfg.host = host;
    }
    if let Some(listen) = overrides.listen {
        cfg.listen = listen;
    }
    if let Some(nameserver) = overrides.nameserver {
        cfg.nameserver = nameserver;
    }
    if let Some(seeder) = overrides.seeder {
        cfg.seeder = seeder;
    }
    if let Some(profile) = overrides.profile {
        cfg.profile = profile;
    }
    if let Some(grpc_listen) = overrides.grpc_listen {
        cfg.grpc_listen = grpc_listen;
    }
    if let Some(min_proto_ver) = overrides.min_proto_ver {
        cfg.min_proto_ver = min_proto_ver;
    }
    if let Some(min_ua_ver) = overrides.min_ua_ver {
        cfg.min_ua_ver = min_ua_ver;
    }
    if let Some(net_suffix) = overrides.net_suffix {
        cfg.net_suffix = Some(net_suffix);
    }
    if let Some(no_log_files) = overrides.no_log_files {
        cfg.no_log_files = no_log_files;
    }
    if let Some(log_level) = overrides.log_level {
        cfg.log_level = log_level;
    }
    if let Some(threads) = overrides.threads {
        cfg.threads = threads;
    }
    if let Some(testnet) = overrides.testnet {
        cfg.network.testnet = testnet;
    }
    if let Some(simnet) = overrides.simnet {
        cfg.network.simnet = simnet;
    }
    if let Some(devnet) = overrides.devnet {
        cfg.network.devnet = devnet;
    }
    if let Some(override_dag_params_file) = overrides.override_dag_params_file {
        cfg.network.override_dag_params_file = Some(override_dag_params_file);
    }
}

fn resolve_network(cfg: &mut Config, cli: &CliArgs) -> Result<(), String> {
    // cli flags override
    cfg.network.testnet |= cli.testnet;
    cfg.network.simnet |= cli.simnet;
    cfg.network.devnet |= cli.devnet;

    let net_suffix = cfg.net_suffix;
    if net_suffix.is_some() && !cfg.network.testnet {
        return Err("Net suffix can only be used with network=testnet.".to_string());
    }

    let active = match (cfg.network.testnet, cfg.network.simnet, cfg.network.devnet) {
        (false, false, false) => mainnet_params(),
        (true, false, false) => {
            let suffix = net_suffix.unwrap_or(DEFAULT_TESTNET_SUFFIX);
            testnet_params_for_suffix(suffix).ok_or_else(|| {
                format!(
                    "Unsupported testnet suffix {}. Supported suffixes: {}",
                    suffix,
                    supported_testnet_suffixes()
                )
            })?
        }
        (false, true, false) => simnet_params(),
        (false, false, true) => devnet_params(),
        _ => {
            return Err(
                "Multiple network parameters (testnet, simnet, devnet, etc.) \
                 cannot be used together. Please choose only one network."
                    .to_string(),
            );
        }
    };

    cfg.network.active_net_params = active;

    if let Some(path) = cfg.network.override_dag_params_file.clone() {
        if !cfg.network.devnet {
            return Err("override-dag-params-file is allowed only when using devnet".to_string());
        }

        let contents = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let json: serde_json::Value = serde_json::from_str(&contents).map_err(|e| e.to_string())?;

        let params = &mut cfg.network.active_net_params;

        if let Some(v) = json.get("acceptUnroutable").and_then(|v| v.as_bool()) {
            params.accept_unroutable = v;
        }
        if let Some(v) = json.get("defaultPort").and_then(|v| v.as_str()) {
            params.default_port = v.to_string();
        }
        if let Some(v) = json.get("name").and_then(|v| v.as_str()) {
            params.name = v.to_string();
        }
    }

    Ok(())
}

fn parse_config_file(path: &Path) -> Result<ConfigOverrides, String> {
    let mut parser = configparser::ini::Ini::new();
    let ini = parser
        .load(path.to_str().unwrap_or(""))
        .map_err(|e| e.to_string())?;
    let mut map: HashMap<String, String> = HashMap::new();
    for (_section, props) in ini {
        for (k, v) in props {
            if let Some(value) = v {
                map.insert(k.to_lowercase(), value);
            }
        }
    }

    let mut overrides = ConfigOverrides::default();
    for (key, value) in map {
        match key.as_str() {
            "appdir" => overrides.app_dir = Some(value),
            "peers" => overrides.known_peers = Some(value),
            "host" => overrides.host = Some(value),
            "listen" => overrides.listen = Some(value),
            "nameserver" => overrides.nameserver = Some(value),
            "default-seeder" => overrides.seeder = Some(value),
            "profile" => overrides.profile = Some(value),
            "grpclisten" => overrides.grpc_listen = Some(value),
            "minprotocolversion" => {
                overrides.min_proto_ver = Some(parse_u8(&value, "minprotocolversion")?)
            }
            "minuseragentversion" => overrides.min_ua_ver = Some(value),
            "netsuffix" => overrides.net_suffix = Some(parse_u16(&value, "netsuffix")?),
            "nologfiles" => overrides.no_log_files = Some(parse_bool(&value, "nologfiles")?),
            "loglevel" => overrides.log_level = Some(value),
            "threads" => overrides.threads = Some(parse_u8(&value, "threads")?),
            "testnet" => overrides.testnet = Some(parse_bool(&value, "testnet")?),
            "simnet" => overrides.simnet = Some(parse_bool(&value, "simnet")?),
            "devnet" => overrides.devnet = Some(parse_bool(&value, "devnet")?),
            "override-dag-params-file" => overrides.override_dag_params_file = Some(value),
            _ => {}
        }
    }

    Ok(overrides)
}

fn parse_bool(value: &str, name: &str) -> Result<bool, String> {
    match value.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(format!("Invalid boolean value for {}: {}", name, value)),
    }
}

fn parse_u8(value: &str, name: &str) -> Result<u8, String> {
    value
        .parse()
        .map_err(|_| format!("Invalid value for {}: {}", name, value))
}

fn parse_u16(value: &str, name: &str) -> Result<u16, String> {
    value
        .parse()
        .map_err(|_| format!("Invalid value for {}: {}", name, value))
}

fn clean_and_expand_path(path: &str, default_app_dir: &str) -> String {
    let mut expanded = path.to_string();
    if let Some(stripped) = expanded.strip_prefix('~') {
        let base_dir = Path::new(default_app_dir)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(default_app_dir));
        expanded = base_dir
            .join(stripped.trim_start_matches('/'))
            .to_string_lossy()
            .to_string();
    }
    let mut out = String::new();
    let mut chars = expanded.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '$' {
            let mut var = String::new();
            while let Some(&c) = chars.peek() {
                if c == '_' || c.is_ascii_alphanumeric() {
                    var.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            if !var.is_empty() {
                if let Ok(val) = env::var(&var) {
                    out.push_str(&val);
                }
            } else {
                out.push(ch);
            }
        } else {
            out.push(ch);
        }
    }
    Path::new(&out).to_string_lossy().to_string()
}

fn create_path_if_needed(path: &str) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())
}

fn normalize_address(addr: &str, default_port: &str) -> String {
    if has_explicit_port(addr) {
        return addr.to_string();
    }
    if addr.starts_with('[') && addr.ends_with(']') {
        return format!("{}:{}", addr, default_port);
    }
    if addr.contains(':') {
        return format!("[{}]:{}", addr, default_port);
    }
    format!("{}:{}", addr, default_port)
}

fn has_explicit_port(addr: &str) -> bool {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let after = &rest[end + 1..];
            return after.starts_with(':') && after.len() > 1;
        }
        return false;
    }

    if addr.matches(':').count() == 1
        && let Some((_, port)) = addr.rsplit_once(':')
    {
        return !port.is_empty();
    }
    false
}

fn default_app_dir(app_name: &str) -> String {
    if cfg!(target_os = "windows") {
        let base = env::var("LOCALAPPDATA")
            .or_else(|_| env::var("APPDATA"))
            .unwrap_or_else(|_| ".".to_string());
        return Path::new(&base)
            .join(app_name)
            .to_string_lossy()
            .to_string();
    }
    if cfg!(target_os = "macos") {
        let home = home_dir().unwrap_or_else(|| PathBuf::from("."));
        let mut app = app_name.to_string();
        if let Some(first) = app.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
        return home
            .join("Library")
            .join("Application Support")
            .join(app)
            .to_string_lossy()
            .to_string();
    }
    let home = home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(format!(".{}", app_name))
        .to_string_lossy()
        .to_string()
}

fn home_dir() -> Option<PathBuf> {
    if let Ok(home) = env::var("HOME") {
        return Some(PathBuf::from(home));
    }
    if cfg!(target_os = "windows")
        && let Ok(profile) = env::var("USERPROFILE")
    {
        return Some(PathBuf::from(profile));
    }
    None
}

pub(crate) fn mainnet_params() -> NetworkParams {
    NetworkParams {
        name: "kaspa-mainnet".to_string(),
        default_port: "16111".to_string(),
        dns_seeds: vec![
            "mainnet-dnsseed.kas.pa".to_string(),
            "mainnet-dnsseed-1.kaspanet.org".to_string(),
            "mainnet-dnsseed-2.kaspanet.org".to_string(),
            "dnsseed.cbytensky.org".to_string(),
            "seeder1.kaspad.net".to_string(),
            "seeder2.kaspad.net".to_string(),
            "seeder3.kaspad.net".to_string(),
            "seeder4.kaspad.net".to_string(),
            "kaspadns.kaspacalc.net".to_string(),
        ],
        accept_unroutable: false,
    }
}

fn testnet_params_for_suffix(suffix: u16) -> Option<NetworkParams> {
    let variant = testnet_variant(suffix)?;
    Some(NetworkParams {
        name: variant.name.to_string(),
        default_port: variant.default_port.to_string(),
        dns_seeds: variant
            .dns_seeds
            .iter()
            .map(|seed| seed.to_string())
            .collect(),
        accept_unroutable: variant.accept_unroutable,
    })
}

fn testnet_variant(suffix: u16) -> Option<&'static TestnetVariant> {
    TESTNET_VARIANTS
        .iter()
        .find(|variant| variant.suffix == suffix)
}

fn supported_testnet_suffixes() -> String {
    TESTNET_VARIANTS
        .iter()
        .map(|variant| variant.suffix.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn simnet_params() -> NetworkParams {
    NetworkParams {
        name: "kaspa-simnet".to_string(),
        default_port: "16511".to_string(),
        dns_seeds: vec![],
        accept_unroutable: false,
    }
}

pub(crate) fn devnet_params() -> NetworkParams {
    NetworkParams {
        name: "kaspa-devnet".to_string(),
        default_port: "16611".to_string(),
        dns_seeds: vec![],
        accept_unroutable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_address_appends_port_for_bracketed_ipv6() {
        let addr = normalize_address("[::1]", "5354");
        assert_eq!(addr, "[::1]:5354");
    }

    #[test]
    fn normalize_address_brackets_unbracketed_ipv6() {
        let addr = normalize_address("::1", "5354");
        assert_eq!(addr, "[::1]:5354");
    }

    #[test]
    fn normalize_address_leaves_explicit_port() {
        let addr = normalize_address("[::1]:53", "5354");
        assert_eq!(addr, "[::1]:53");
    }

    #[test]
    fn normalize_address_ipv4_adds_port() {
        let addr = normalize_address("127.0.0.1", "5354");
        assert_eq!(addr, "127.0.0.1:5354");
    }

    #[test]
    fn clean_and_expand_path_uses_parent_of_default_app_dir_for_tilde() {
        let default_app_dir = if cfg!(windows) {
            r"C:\base\App"
        } else {
            "/tmp/base/App"
        };
        let expanded = clean_and_expand_path("~/data", default_app_dir);
        let expected = Path::new(default_app_dir).parent().unwrap().join("data");
        assert_eq!(Path::new(&expanded), expected);
    }
}

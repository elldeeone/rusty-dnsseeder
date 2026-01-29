const VALID_CHARACTERS: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-";

const APP_MAJOR: u32 = 0;
const APP_MINOR: u32 = 12;
const APP_PATCH: u32 = 7;

pub fn version() -> String {
    let mut version = format!("{}.{}.{}", APP_MAJOR, APP_MINOR, APP_PATCH);
    if let Some(build) = option_env!("DNSSEEDER_BUILD")
        && !build.is_empty()
    {
        check_app_build(build);
        version = format!("{}-{}", version, build);
    }
    version
}

fn check_app_build(app_build: &str) {
    for ch in app_build.chars() {
        if !VALID_CHARACTERS.contains(ch) {
            panic!(
                "appBuild string ({}) contains forbidden characters. Only alphanumeric characters and dashes are allowed",
                app_build
            );
        }
    }
}

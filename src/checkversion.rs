use regex::Regex;

pub fn check_version(min_version: &str, user_agent: &str) -> Result<(), String> {
    if min_version.is_empty() {
        return Ok(());
    }
    let min_ver = parse_version(min_version)?;
    let trimmed = user_agent.trim_start_matches('/');
    let end = trimmed
        .find('/')
        .ok_or_else(|| "Invalid userAgent format".to_string())?;
    let first_group = &trimmed[..end];
    let re = Regex::new(r"\b(\d+\.\d+\.\d+)\b").map_err(|e| e.to_string())?;
    let caps = re
        .captures(first_group)
        .ok_or_else(|| "No valid version found in userAgent".to_string())?;
    let client_ver = parse_version(&caps[1])?;
    if client_ver < min_ver {
        return Err("UserAgent version is below minimum required".to_string());
    }
    Ok(())
}

fn parse_version(version: &str) -> Result<(u32, u32, u32), String> {
    let mut parts = version.split('.');
    let major = parts
        .next()
        .ok_or_else(|| "Invalid version".to_string())?
        .parse()
        .map_err(|_| "Invalid version".to_string())?;
    let minor = parts
        .next()
        .ok_or_else(|| "Invalid version".to_string())?
        .parse()
        .map_err(|_| "Invalid version".to_string())?;
    let patch = parts
        .next()
        .ok_or_else(|| "Invalid version".to_string())?
        .parse()
        .map_err(|_| "Invalid version".to_string())?;
    Ok((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::check_version;

    #[test]
    fn test_check_version() {
        let tests = vec![
            ("0.17.1", "/kaspad:0.17.1/kaspad:0.17.1/", false),
            ("0.17.1", "/kaspad:0.17.1/kaspad:0.0.0/", false),
            (
                "0.17.1",
                "/kaspad:0.17.1/kaspad:0.12.15(kdx_2.12.10)/",
                false,
            ),
            ("0.17.1", "/kaspad:0.18.9/kaspad:0.18.9/", false),
            ("0.17.1", "/kaspad:1.1.0/", false),
            ("0.18.9", "/kaspad:0.17.1/kaspad:0.17.1/", true),
            ("0.18.9", "/kaspad:0.17.1/kaspad:0.0.0/", true),
            (
                "0.18.9",
                "/kaspad:0.17.1/kaspad:0.12.15(kdx_2.12.10)/",
                true,
            ),
            ("0.18.9", "/kaspad:0.18.9/kaspad:0.18.9/", false),
            ("0.18.9", "/kaspad:1.1.0/", false),
            ("1.0.0", "/kaspad:0.17.1/kaspad:0.17.1/", true),
            ("1.0.0", "/kaspad:0.17.1/kaspad:0.0.0/", true),
            ("1.0.0", "/kaspad:0.17.1/kaspad:0.12.15(kdx_2.12.10)/", true),
            ("1.0.0", "/kaspad:0.18.9/kaspad:0.18.9/", true),
            ("1.0.0", "/kaspad:1.1.0/", false),
        ];

        for (min_version, user_agent, should_fail) in tests {
            let res = check_version(min_version, user_agent);
            if should_fail && res.is_ok() {
                panic!("Expected failure for {min_version} with {user_agent}");
            }
            if !should_fail && res.is_err() {
                panic!(
                    "Unexpected error for {min_version} with {user_agent}: {:?}",
                    res
                );
            }
        }
    }
}

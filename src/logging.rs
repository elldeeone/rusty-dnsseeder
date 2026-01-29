use log::LevelFilter;

pub fn init(
    no_log_files: bool,
    log_level: &str,
    log_file: &str,
    err_log_file: &str,
) -> Result<(), String> {
    let level = level_from_string(log_level)?;
    let mut dispatch = fern::Dispatch::new().format(|out, message, record| {
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "0001-01-01T00:00:00Z".to_string());
        out.finish(format_args!("{ts} [{}] {}", record.level(), message))
    });

    dispatch = dispatch.chain(fern::Dispatch::new().level(level).chain(std::io::stdout()));

    if !no_log_files {
        dispatch = dispatch.chain(
            fern::Dispatch::new()
                .level(LevelFilter::Trace)
                .chain(fern::log_file(log_file).map_err(|e| e.to_string())?),
        );
        dispatch = dispatch.chain(
            fern::Dispatch::new()
                .level(LevelFilter::Warn)
                .chain(fern::log_file(err_log_file).map_err(|e| e.to_string())?),
        );
    }

    dispatch.apply().map_err(|e| e.to_string())?;
    Ok(())
}

fn level_from_string(level: &str) -> Result<LevelFilter, String> {
    match level.to_lowercase().as_str() {
        "trace" | "trc" => Ok(LevelFilter::Trace),
        "debug" | "dbg" => Ok(LevelFilter::Debug),
        "info" | "inf" => Ok(LevelFilter::Info),
        "warn" | "warning" | "wrn" => Ok(LevelFilter::Warn),
        "error" | "err" => Ok(LevelFilter::Error),
        "critical" | "crt" => Ok(LevelFilter::Error),
        "off" => Ok(LevelFilter::Off),
        _ => Err(format!("Invalid loglevel: {}", level)),
    }
}

#[cfg(test)]
mod tests {
    use super::level_from_string;
    use log::LevelFilter;

    #[test]
    fn level_from_string_accepts_shorthand() {
        assert_eq!(level_from_string("trc").unwrap(), LevelFilter::Trace);
        assert_eq!(level_from_string("dbg").unwrap(), LevelFilter::Debug);
        assert_eq!(level_from_string("inf").unwrap(), LevelFilter::Info);
        assert_eq!(level_from_string("wrn").unwrap(), LevelFilter::Warn);
        assert_eq!(level_from_string("err").unwrap(), LevelFilter::Error);
        assert_eq!(level_from_string("crt").unwrap(), LevelFilter::Error);
    }
}

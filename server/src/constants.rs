use std::sync::OnceLock;

// if true, ip rate limiting for streamed file upload is not disabled
pub(crate) static DEVELOPMENT_MODE: OnceLock<bool> = OnceLock::new();

// A token corresponds to 1 allowed ws_file_upload()
/// Time in ms for the per-email upload limiter to replenish by 1 token
pub(crate) const UPLOAD_RATE_LIMIT_EMAIL_REPLENISH_TIME: u64 = 2000;
/// Time in ms for the per-IP upload limiter limit bucket to replenish by 1 token
pub(crate) const UPLOAD_RATE_LIMIT_IP_REPLENISH_TIME: u64 = 1000;

// A token corresponds to 1 allowed general API call (list_files, get_file, etc.)
/// Time in ms for the per-email general limiter to replenish by 1 token
pub(crate) const GENERAL_RATE_LIMIT_EMAIL_REPLENISH_TIME: u64 = 200;
/// Time in ms for the per-IP general limiter limit bucket to replenish by 1 token
pub(crate) const GENERAL_RATE_LIMIT_IP_REPLENISH_TIME: u64 = 100;

pub(crate) fn set_dev_mode() {
    let development_mode = match std::env::var("EFS_SERVER_DEVELOPMENT_MODE") {
        Ok(variable) => match variable.as_ref() {
            "1" => {
                println!("DEVELOPMENT_MODE is enabled");
                true
            }
            _ => false,
        },
        Err(_) => {
            println!(
                "Environment variable 'EFS_SERVER_DEVELOPMENT_MODE' is not set, defaulting to false"
            );
            false
        }
    };
    DEVELOPMENT_MODE
        .set(development_mode)
        .expect("Couldn't evaluate DEVELOPMENT_MODE");
}

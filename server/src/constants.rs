// if true, ip rate limiting for streamed file upload is not disabled
pub const DEVELOPMENT_MODE: bool = true;

// A token corresponds to 1 allowed ws_file_upload()
/// Time in ms for the per-email upload limiter to replenish by 1 token
pub const UPLOAD_RATE_LIMIT_EMAIL_REPLENISH_TIME: u64 = 2000;
/// Time in ms for the per-IP upload limiter limit bucket to replenish by 1 token
pub const UPLOAD_RATE_LIMIT_IP_REPLENISH_TIME: u64 = 1000;

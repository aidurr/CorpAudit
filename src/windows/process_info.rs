#[cfg(windows)]
use anyhow::Result;

#[cfg(windows)]
pub fn get_process_modules(_pid: u32) -> Result<Vec<String>> {
    let dependencies: Vec<String> = Vec::new();
    Ok(dependencies)
}

#[cfg(windows)]
pub fn get_process_publisher(_pid: u32) -> Result<Option<String>> {
    Ok(None)
}

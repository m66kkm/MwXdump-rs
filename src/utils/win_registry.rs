

fn get_string_from_registry(key_path: String, value_name: String) -> Result<Option<String>> {
    // const WECHAT_REG_KEY_PATH: &str = "Software\\Tencent\\WeChat";
    // const WECHAT_FILES_VALUE_NAME: &str = "FileSavePath";

    match win_api::read_registry_sz_value(
        windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
        key_path,
        value_name,
    ) {
        Ok(path_str) => {
            if path_str == "MyDocument:" { 
                if let Some(user_profile) = std::env::var("USERPROFILE").ok() {
                    let docs_path = PathBuf::from(user_profile).join("Documents");
                    let wechat_files_path = docs_path.join("WeChat Files");
                    if wechat_files_path.exists() && wechat_files_path.is_dir(){
                        println!("[InfoExtractor] Resolved 'MyDocument:' to WeChat Files path: {:?}", wechat_files_path);
                        return Ok(Some(wechat_files_path));
                    } else {
                         println!("[InfoExtractor] 'MyDocument:' resolved path does not exist or not a dir: {:?}", wechat_files_path);
                        return Ok(None);
                    }
                } else {
                     println!("[InfoExtractor] Could not resolve 'MyDocument:' due to missing USERPROFILE.");
                    return Ok(None);
                }
            } else if !path_str.is_empty() {
                let path_str_clone_for_join = path_str.clone(); // Clone for the first PathBuf creation
                let wechat_files_path = PathBuf::from(path_str_clone_for_join).join("WeChat Files"); 
                 if wechat_files_path.exists() && wechat_files_path.is_dir(){
                    println!("[InfoExtractor] Found WeChat Files path from registry (joined): {:?}", wechat_files_path);
                    return Ok(Some(wechat_files_path));
                } else {
                    let original_path_buf = PathBuf::from(&path_str); // Borrow original path_str
                    if original_path_buf.exists() && original_path_buf.is_dir() && original_path_buf.file_name().map_or(false, |name| name == "WeChat Files") {
                        println!("[InfoExtractor] Found WeChat Files path from registry (original path): {:?}", original_path_buf);
                        return Ok(Some(original_path_buf));
                    }
                    println!("[InfoExtractor] Registry path for WeChat Files does not exist or not a dir: {:?} (and original path {:?} also invalid)", wechat_files_path, path_str);
                    return Ok(None);
                }
            }
            Ok(None)
        }
        Err(e) => {
            println!("[InfoExtractor] Failed to read WeChat FileSavePath from registry: {}. This might be normal.", e);
            Ok(None)
        }
    }
}
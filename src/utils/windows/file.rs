use std::path::{Path, PathBuf};
use std::fs;
use std::time::SystemTime;
use anyhow::{Result, Context};
use std::io::Read;

/// 获取当前用户的主目录
/// 返回类似 C:\Users\USERNAME 的路径
pub fn get_user_profile_dir() -> Result<PathBuf> {
    // 首先尝试 USERPROFILE 环境变量
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        return Ok(PathBuf::from(user_profile));
    }
    
    // 备选方案：组合 HOMEDRIVE 和 HOMEPATH
    if let (Ok(home_drive), Ok(home_path)) = (
        std::env::var("HOMEDRIVE"),
        std::env::var("HOMEPATH")
    ) {
        return Ok(PathBuf::from(format!("{}{}", home_drive, home_path)));
    }
    
    anyhow::bail!("无法获取用户主目录")
}

/// 递归获取指定目录下指定扩展名的文件列表
/// 返回文件的绝对路径集合
pub fn list_files(dir: &Path, extension: &str, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    
    if !dir.exists() {
        return Ok(files);
    }
    
    let entries = fs::read_dir(dir)
        .with_context(|| format!("读取目录失败: {:?}", dir))?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().eq_ignore_ascii_case(extension) {
                    // 确保返回绝对路径
                    let abs_path = if path.is_absolute() {
                        path
                    } else {
                        std::env::current_dir()?.join(&path)
                    };
                    files.push(abs_path);
                }
            }
        } else if path.is_dir() && recursive {
            // 递归处理子目录
            let sub_files = list_files(&path, extension, recursive)?;
            files.extend(sub_files);
        }
    }
    
    Ok(files)
}

/// 读取文件内容，返回字节数组
pub fn read_file_content(path: &Path) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("打开文件失败: {:?}", path))?;
    
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .with_context(|| format!("读取文件内容失败: {:?}", path))?;
    
    Ok(content)
}

/// 获取文件的修改时间
pub fn get_file_modified_time(path: &Path) -> Result<SystemTime> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("获取文件元数据失败: {:?}", path))?;
    
    metadata.modified()
        .with_context(|| format!("获取文件修改时间失败: {:?}", path))
}

/// 检查目录是否存在
pub fn check_directory_exists(path: &Path) -> bool {
    path.exists() && path.is_dir()
}

/// 在指定目录下查找以特定前缀开头的子目录
pub fn find_directories_with_prefix(parent: &Path, prefix: &str) -> Result<Vec<PathBuf>> {
    let mut directories = Vec::new();
    
    if !parent.exists() || !parent.is_dir() {
        return Ok(directories);
    }
    
    let entries = fs::read_dir(parent)
        .with_context(|| format!("读取目录失败: {:?}", parent))?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_dir() {
            if let Some(dir_name) = path.file_name() {
                let dir_name_str = dir_name.to_string_lossy();
                if dir_name_str.starts_with(prefix) {
                    // 返回绝对路径
                    let abs_path = if path.is_absolute() {
                        path
                    } else {
                        std::env::current_dir()?.join(&path)
                    };
                    directories.push(abs_path);
                }
            }
        }
    }
    
    Ok(directories)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_get_user_profile_dir() {
        let result = get_user_profile_dir();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.exists());
        assert!(path.is_dir());
    }

    #[test]
    fn test_list_files() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        
        // 创建测试文件
        fs::write(dir_path.join("test1.ini"), "content1").unwrap();
        fs::write(dir_path.join("test2.ini"), "content2").unwrap();
        fs::write(dir_path.join("test3.txt"), "content3").unwrap();
        
        // 创建子目录和文件
        let sub_dir = dir_path.join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        fs::write(sub_dir.join("test4.ini"), "content4").unwrap();
        
        // 测试非递归
        let files = list_files(dir_path, "ini", false).unwrap();
        assert_eq!(files.len(), 2);
        
        // 测试递归
        let files = list_files(dir_path, "ini", true).unwrap();
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn test_read_file_content() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = b"Hello, World!";
        fs::write(&file_path, content).unwrap();
        
        let read_content = read_file_content(&file_path).unwrap();
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_find_directories_with_prefix() {
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();
        
        // 创建测试目录
        fs::create_dir(dir_path.join("wxid_test1")).unwrap();
        fs::create_dir(dir_path.join("wxid_test2")).unwrap();
        fs::create_dir(dir_path.join("other_dir")).unwrap();
        
        let dirs = find_directories_with_prefix(dir_path, "wxid_").unwrap();
        assert_eq!(dirs.len(), 2);
        
        for dir in &dirs {
            assert!(dir.is_absolute());
            let file_name = dir.file_name().unwrap().to_string_lossy();
            assert!(file_name.starts_with("wxid_"));
        }
    }
}
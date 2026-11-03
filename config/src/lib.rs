pub mod typedef;

use std::{env, fs::OpenOptions, io::Read, path::PathBuf, str::FromStr};

use log::{info, warn};
use serde::Deserialize;

use crate::typedef::{PatchDef, TraceDef, Validate};
const ENV_VAR_CONFIG_FILE: &str = "COR_PROF_CONFIG_FILE";
const ENV_VAR_CONFIG_DATA: &str = "COR_PROF_CONFIG_DATA";

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    patches: Option<Vec<PatchDef>>,
    traces: Option<Vec<TraceDef>>,
}

impl Config {
    pub fn patches(&self) -> Option<&Vec<PatchDef>> {
        self.patches.as_ref()
    }

    pub fn traces(&self) -> Option<&Vec<TraceDef>> {
        self.traces.as_ref()
    }

    pub fn parse_json_str(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn parse_json_file(path: &str) -> Result<Self, String> {
        let path = PathBuf::from_str(path).unwrap();
        let path = path.canonicalize()
            .map_err(|err| format!("PathError: {err}"))?;

        info!("reading config from {}", path.display());

        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|err| {
                warn!("can't open '{}' due to {}", path.display(), err);
                format!("IOError: {err}")
            })?;
        
        let mut content = String::new();
        file.read_to_string(&mut content).map_err(|err| {
            warn!("failed to read '{}' due to {}", path.display(), err);
            format!("IOError: {err}")
        })?;

        Self::parse_json_str(&content.as_str())
        .map_err(|err| {
            warn!("failed to parse JSON due to: {err}");
            format!("JSONError: {err}")
        })
    }

    pub fn parse_env_file() -> Result<Self, String>{
        let config_path = env::var(ENV_VAR_CONFIG_FILE).unwrap_or("config.json".to_string());
        Self::parse_json_file(&config_path)
    }

    pub fn parse_env_var() -> Result<Self, String> {
        let config_data = env::var(ENV_VAR_CONFIG_DATA).unwrap_or("".to_string());
        Self::parse_json_str(&config_data).map_err(|err| {
            warn!("failed to parse JSON in env var {ENV_VAR_CONFIG_DATA}; err: {err}");
            format!("JSONError: {err}")
        })
    }
}

impl Validate for Config {
    fn validate(&self) -> Result<(), String> {
        if let Some(patches) = &self.patches {
            for patch in patches {
                patch.validate()?
            }
        }

        if let Some(traces) = &self.traces {
            for trace in traces {
                trace.validate()?
            }    
        }

        Ok(())
    }
}

pub fn read_config(json: &String) -> Config {
    serde_json::from_str(json).unwrap()
}

pub fn read_json(path: &str) -> Result<Config, String> {
    let path = PathBuf::from_str(path).unwrap();
    let path = path.canonicalize()
        .unwrap();

    info!("reading config from {}", path.display());

    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();

    serde_json::from_reader(file)
        .map_err(|err| format!("JsonError: {err}"))
}

#[cfg(test)]
mod test {
    use crate::Config;

    #[test]
    fn test_config_patches_name_from_str() {
        let raw_json = r#"
            {
                "patches": [
                    {
                        "name": "test method"
                    }
                ]
            }"#;

        let config = Config::parse_json_str(raw_json).unwrap();
        assert!(config.patches().is_some());
        assert!(config.traces().is_none());
        
        let dotpatch = config.patches().unwrap();
        assert_eq!(dotpatch.len(), 1);
        
        let patch1 = &dotpatch[0];
        assert_eq!(patch1.matcher.name().unwrap(), "test method");
    }

    #[test]
    fn test_config_pacthes_by_pattern_seq() {
        let raw_json = r#"
        {
            "patches": [
                {
                    "pattern": ["1", "2", "?", "0x0a"],
                    "new_bytes": ["4", "5"]
                }
            ]
        }"#;

        let config = Config::parse_json_str(raw_json).unwrap();
        assert!(config.patches.is_some());
        assert!(config.traces().is_none());
        
        let dotpatch = config.patches().unwrap();
        assert_eq!(dotpatch.len(), 1);
        
        let patch1 = &dotpatch[0];
        assert_eq!(patch1.matcher.pattern().unwrap(), [01, 02, b'?', 10]);
        assert_eq!(patch1.params.new_bytes(), [04, 05]);
    }

    #[test]
    #[should_panic]
    fn test_config_by_bytes_from_str_invalid() {
        let raw_json = r#"
        {
            "patches":[
                {   
                    "pattern": ["1", "2", "3", "hh"],
                    "new_bytes": ["4", "5"]
                }
            ]
        }"#;

        // let result = std::panic::catch_unwind(|| read_config(&raw_json.to_string()));
        // assert!(result.is_err())
        let _ = Config::parse_json_str(&raw_json).unwrap();
    }

    #[test]
    fn test_read_config_from_file() {
        //println!("{}", current_dir().unwrap().display());
        let config = Config::parse_json_file("../config.json").unwrap();
        assert!(config.patches().is_some());
        
        let dotpatch = config.patches().unwrap();
        assert_eq!(dotpatch.len(), 4);
        
        let patch = &dotpatch[0];
        assert_eq!(patch.matcher.name().unwrap(), "userCertValidationCallbackWrapper");

        let patch = &dotpatch[3];
        assert_eq!(patch.matcher.pattern().unwrap(), [
                0x72, b'?', b'?', b'?', b'?',
                0x28, b'?', b'?', b'?', b'?',
                0x16, 0x2a
            ]
        );
    }
}

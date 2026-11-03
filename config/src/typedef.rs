use std::{marker::PhantomData, num::ParseIntError};

use log::debug;
use serde::{Deserialize, Deserializer, de::{self, SeqAccess, Visitor}};
use wildcard::Wildcard;

const TRUE: fn() -> bool = || true;

pub trait Validate {
    fn validate(&self) -> Result<(), String>;
}

fn default_new_il() -> Vec<u8> {
    vec![0x17, 0x2a] //[ldc.i4.1, ret]
}

/// Function Matcher. 
/// Will match all given values.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct Matcher {
    #[serde(default)]
    pub(crate) name: Option<String>,

    #[serde(default)]
    pub(crate) class: Option<String>,
    
    #[serde(deserialize_with="deser_to_byte_pattern")]
    #[serde(default)]
    pub(crate) pattern: Option<Vec<u8>>,
}

impl Matcher {
    ///Function name
    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }

    ///Containing Class(TypeDef)
    pub fn class(&self) -> Option<String> {
        
        self.class.clone()
    }

    ///IL Byte Patterns (with wildcards)
    pub fn pattern(&self) -> Option<Vec<u8>> {
        self.pattern.clone()
    }

    ///Match given parameters
    pub fn is_match(&self, name: &str, class: &str, bytes: &[u8]) -> bool {
        if self.name.is_none() || (self.name().unwrap() == name) {
            if self.class.is_none() || (self.class().unwrap() == class) {
                if self.pattern().is_none() 
                    || (Wildcard::new(&self.pattern()
                            .unwrap())
                        .unwrap()
                        .is_match(bytes)) 
                {
                    debug!("matched with {{Name: {}, Class: {}, Pattern: {}}}",
                        self.name.is_some(), 
                        self.class.is_some(), 
                        self.pattern.is_some()
                    );
                    return true
                }
            }
        }
        false
    }
}

impl Validate for Matcher {
    fn validate(&self) -> Result<(), String> {
        if !(self.name.is_some() 
            || self.pattern.is_some()) {
            return Err("missing name or pattern".into());
        }

        Ok(())
    }
}

///Params for patching IL.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct PatchParams {
    #[serde(default="default_new_il")]
    #[serde(deserialize_with="deser_to_byte_array")]
    pub(crate) new_bytes: Vec<u8>,

    #[serde(default)]
    pub(crate) offset: usize,

    #[serde(default="TRUE")]
    pub(crate) truncate: bool,

    #[serde(default)]
    pub(crate) copy_header: bool,
}

impl PatchParams {
    ///New IL bytes
    pub fn new_bytes(&self) -> Vec<u8> {
        self.new_bytes.clone()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn truncate(&self) -> bool {
        self.truncate
    }

    pub fn copy_header(&self) -> bool {
        self.copy_header
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct PatchDef {
    #[serde(flatten)]
    pub matcher: Matcher,

    #[serde(flatten)]
    pub params: PatchParams,
}

impl Validate for PatchDef {
    fn validate(&self) -> Result<(), String> {
        self.matcher.validate()
    }
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq)]
pub enum ArgType {
    String,
 
    #[default]
    ByteArray,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq)]
pub enum WriteTo {
    #[serde(alias="stdout")]
    #[default]
    STDOUT,

    #[serde(alias="file")]
    FILE
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct TraceParams {
    #[serde(default)]
    pub(crate) arg_num: u8,

    #[serde(flatten)]
    #[serde(default)]
    pub(crate) out_cfg: OutCfg,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct OutCfg {
    #[serde(default)]
    pub(crate) write_to: WriteTo,

    #[serde(default)]
    pub(crate) metadata: bool
}

impl OutCfg {
     pub fn write_to(&self) -> &WriteTo {
        &self.write_to
    }

    pub fn metadata(&self) -> bool {
        self.metadata
    }
}


impl TraceParams {
    pub fn arg_num(&self) -> u8 {
        self.arg_num
    }

    pub fn data_out(&self) -> &OutCfg {
        &self.out_cfg
    }

    pub fn write_to(&self) -> &WriteTo {
        &self.out_cfg.write_to
    }

    pub fn metadata(&self) -> bool {
        self.out_cfg.metadata
    }
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct TraceDef {
    #[serde(flatten)]
    pub matcher: Matcher,

    #[serde(default)]
    pub params: Vec<TraceParams>,

    #[serde(default)]
    pub(crate) retval: Option<OutCfg>,
}

impl TraceDef {
    ///Should dump return value?
    pub fn retval(&self) -> &Option<OutCfg> {
        &self.retval
    }
}

impl Validate for TraceDef {
    fn validate(&self) -> Result<(), String> {
        match self.matcher.validate() {
            Ok(()) => {
                if self.params.len() > 0 {
                    Ok(())
                } else {
                    Err("at least one param config is required".into())
                }
            },
            Err(err) => Err(err)
        }
    }
}

fn deser_to_byte_pattern<'de, D>(deser: D) -> Result<Option<Vec<u8>>, D::Error>
    where D: Deserializer<'de>
{
    struct StrSeqVisitor(PhantomData<fn() -> Vec<u8>>);

    impl <'de> Visitor<'de> for StrSeqVisitor {
        type Value = Option<Vec<u8>>;
    
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("hex encoded bytes, either as an array or space seperated hex pairs")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: serde::de::SeqAccess<'de>
        {

            let mut res: Vec<u8> = vec![];
            while let Some(value) = seq.next_element::<String>()? {
                let byte = hex_to_byte(value.as_str(), true);
                res.push(byte.map_err(|e| de::Error::custom(e.to_string()))?);
            }

            Ok(Some(res))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error, {
            
            let hex_bytes = v.split(" ");
            let mut res: Vec<u8> = vec![];
            
            for hex in hex_bytes {
                let byte = hex_to_byte(hex, true);
                res.push(byte.map_err(|e| de::Error::custom(e.to_string()))?);
            }

            Ok(Some(res))
        }
    }

    let visitor = StrSeqVisitor(PhantomData);
    deser.deserialize_any(visitor)
}


fn deser_to_byte_array<'de, D>(deser: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de>
{
    struct StrSeqVisitor(PhantomData<fn() -> Vec<u8>>);

    impl <'de> Visitor<'de> for StrSeqVisitor {
        type Value = Vec<u8>;
    
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a non empty sequence of strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: SeqAccess<'de>
        {

            let mut res: Vec<u8> = vec![];
            while let Some(value) = seq.next_element::<String>()? {      
                let byte = hex_to_byte(&value, false);
                res.push(byte.map_err(|e| de::Error::custom(e.to_string()))?);
            }

            Ok(res)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error, {
            
            let hex_bytes = v.split(" ");
            let mut res: Vec<u8> = vec![];
            
            for hex in hex_bytes {
                let byte = hex_to_byte(hex, false);
                res.push(byte.map_err(|e| de::Error::custom(e.to_string()))?);
            }

            Ok(res)
        }
    }

    let visitor = StrSeqVisitor(PhantomData);
    deser.deserialize_any(visitor)
}


fn hex_to_byte(value: &str, wildchars: bool) -> Result<u8, ParseIntError> {
    match value {
        "?" | "??" if wildchars => Ok(b'?'),
        "*" | "**" if wildchars => Ok(b'*'),
        x => {                
            let mut val = x.to_string().to_lowercase();
            let radix = if val.starts_with("0x") || val.starts_with("\\x") {
                val = val.split('x').collect::<Vec<&str>>()[1].to_string();
                16
            } else {
                10
            };
            
            u8::from_str_radix(&val, radix)                
        }
    }
}

#[cfg(test)]
mod test {
    use super::{WriteTo, Validate, PatchDef, TraceDef, Matcher};
    use super::{hex_to_byte, deser_to_byte_array, deser_to_byte_pattern, default_new_il}; 

    use serde::{self, Deserialize};    
    use wildcard::Wildcard;


    #[derive(Debug, Default, Deserialize, Clone)]
    struct TestType {
        #[serde(deserialize_with="deser_to_byte_pattern")]
        #[serde(default)]
        pattern: Option<Vec<u8>>,
        
        #[serde(deserialize_with="deser_to_byte_array")]
        #[serde(default="default_new_il")]
        new_il: Vec<u8>
    }

    #[test]
    fn test_hex_to_bytes() {
        let data = vec![
            "1".to_string(), 
            "0x02".to_string(), 
            "*".to_string(), 
            "?".to_string()
        ];
        let expected = [1, 2, b'*', b'?'];
        let result = data.iter()
            .map(|v| hex_to_byte(v, true).unwrap())
            .collect::<Vec<u8>>();
        assert_eq!(result, expected)
    }

    #[test]
    #[should_panic]
    fn test_hex_to_bytes_disallow_wildcard() {
        let data = vec![
            "1".to_string(), 
            "0x02".to_string(), 
            "*".to_string(), 
            "?".to_string()
        ];
        //let expected = [1, 2, b'*', b'?'];
        let _ = data.iter()
            .map(|v|  hex_to_byte(v, false).unwrap())
            .collect::<Vec<u8>>();
    }

    #[test]
    fn test_deser_pattern_from_str_seq() {
        let json = r#"
        {
            "pattern": ["0x0a", "0x0B", "0x1", "?", "**", "??", "*", "09"]
        }
        "#;

        let parsed: TestType = serde_json::from_str(json).unwrap();
        let pattern = parsed.pattern.unwrap();
        assert_eq!(pattern.len(), 8);
        assert_eq!(pattern, [10, 11, 1, b'?', b'*', b'?', b'*', 9]);
    }

    #[test]
    fn test_deser_pattern_from_str() {
        let json = r#"
        {
            "pattern": "0x0a 0x0B 0x1 ?? * ? * 09"
        }
        "#;

        let parsed: TestType = serde_json::from_str(json).unwrap();
        let pattern = parsed.pattern.unwrap();
        assert_eq!(pattern.len(), 8);
        assert_eq!(pattern, [10, 11, 1, b'?', b'*', b'?', b'*', 9]);
    }

    #[test]
    fn test_derser_bytes_from_seq() {
        let json = r#"
        {
            "new_il": "0x0a 0x0B 0x1 09"
        }
        "#;

        let parsed: TestType = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.new_il.len(), 4);
        assert_eq!(parsed.new_il, [10, 11, 1, 9]);
    }

    #[test]
    fn test_deser_matcher_all_fields() {
        let json = r#"
        {
            "name": "TestName",
            "class": "TestClass",
            "pattern": "0x0a 0x0b"
        }
        "#;

        let matcher: Matcher = serde_json::from_str(&json).unwrap();
        assert_eq!(matcher.name().unwrap(), "TestName");
        assert_eq!(matcher.class().unwrap(), "TestClass");
        assert_eq!(matcher.pattern().unwrap(), [10, 11]);
    }

    #[test]
    fn test_deser_matcher_only_pattern() {
        let json = r#"
        {
            "pattern": ["0x0a", "0x0b"]
        }
        "#;

        let matcher: Matcher = serde_json::from_str(&json).unwrap();
        assert!(matcher.name().is_none());
        assert!(matcher.class().is_none());
        assert_eq!(matcher.pattern().unwrap(), [10, 11]);
    }

    #[test]
    fn test_deser_patchdef_all_fields() {
        let json = r#"
        {
            "name": "TestName",
            "class": "TestClass",
            "pattern": "0x0a 0x0b ?? *",
            "new_bytes": ["10", "20"],
            "copy_header": true,
            "truncate": true
        }
        "#;

        let patch: PatchDef = serde_json::from_str(&json).unwrap();
        
        let matcher = &patch.matcher;
        assert_eq!(matcher.name().unwrap(), "TestName");
        assert_eq!(matcher.class().unwrap(), "TestClass");
        assert_eq!(matcher.pattern().unwrap(), [10, 11, b'?', b'*']);

        let params = &patch.params;
        assert_eq!(params.new_bytes(), [10, 20]);
        assert!(params.copy_header());
        assert!(params.truncate());
    }

    #[test]
    fn test_deser_patchdef_truncate_default() {
        let json = r#"
        {
            "name": "TestName",
            "class": "TestClass",
            "pattern": "0x0a 0x0b ?? *",
            "copy_header": true
        }"#;

        let patch: PatchDef = serde_json::from_str(&json).unwrap();
        
        let matcher = &patch.matcher;
        assert_eq!(matcher.name().unwrap(), "TestName");
        assert_eq!(matcher.class().unwrap(), "TestClass");
        assert_eq!(matcher.pattern().unwrap(), [10, 11, b'?', b'*']);

        let params = &patch.params;
        assert!(params.copy_header());
        assert!(params.truncate());
    }

    #[test]
    fn test_deser_tracedef_all_fields() {
        let json = r#"
        {
            "name": "TestName",
            "class": "TestClass",
            "pattern": "0x0a 0x0b ?? *",
            "params": [
                {
                    "arg_num": 1,
                    "arg_type": "ByteArray",
                    "write_to": "file",
                    "metadata": true
                }
            ],
            "retval": {
                "write_to": "file",
                "metadata": true
            }
        }
        "#;

        let trace: TraceDef = serde_json::from_str(&json).unwrap();
        assert!(trace.validate().is_ok());
        assert!(trace.retval().is_some());
        assert_eq!(trace.retval().as_ref().unwrap().write_to, WriteTo::FILE);


        let matcher = &trace.matcher;
        assert_eq!(matcher.name().unwrap(), "TestName");
        assert_eq!(matcher.class().unwrap(), "TestClass");
        assert_eq!(matcher.pattern().unwrap(), [10, 11, b'?', b'*']);

        let params = &trace.params[0];
        assert_eq!(params.arg_num(), 1);
        //assert_eq!(*params.arg_type(), ArgType::ByteArray);
    }

    #[test]
    fn match_byte_pattern_is_match() {
        let data = [01u8, 02, 03, 04, 05, 06, 07, 08, 09, 10];
        let pattern = [01u8, 02, 03, b'?', 05, 06, b'*', 10];
        let wildcard = Wildcard::new(&pattern).unwrap();
        assert!(wildcard.is_match(&data))
    }

    #[test]
    fn match_byte_pattern_captures() {
        let data = [01u8, 02, 03, 04, 05, 06, 07, 08, 09, 10];
        let pattern = [01u8, 02, 03, b'?', 05, 06, b'*', 10];
        let wildcard = Wildcard::new(&pattern).unwrap();
        let captures = wildcard.captures(&data).unwrap();
        assert_eq!(captures.len(), 2);
        assert_eq!(captures, [vec![04], vec![07, 08, 09]])
    }

}

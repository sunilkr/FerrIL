use core::slice;
use std::{
    convert::TryInto, 
    ffi::OsString, 
    fmt::Display, 
    os::windows::ffi::OsStringExt
};

use log::debug;

use crate::{
    ffi::*,
    signature::{
        MethodSignature,
        SignatureError, 
        SignatureParser, 
        TypeSignature,
        TypeSignature as TS,
    }
};

pub struct ArrayClassInfo {
    pub element_type: CorElementType,
    pub element_class_id: Option<ClassID>,
    pub rank: u32,
}

pub struct ClassInfo {
    pub module_id: ModuleID,
    pub token: mdTypeDef,
}

#[derive(Debug)]
pub struct FunctionInfo {
    pub class_id: ClassID,
    pub module_id: ModuleID,
    pub token: mdMethodDef,
}

pub struct FunctionTokenAndMetadata {
    pub metadata_import: *mut MetaDataImport,
    pub token: mdMethodDef,
}

#[derive(Debug)]
pub struct ModuleInfo {
    pub base_load_address: LPCBYTE,
    pub file_name: String,
    pub assembly_id: AssemblyID,
}

pub struct IlFunctionBody {
    pub method_header: LPCBYTE,
    pub method_size: u32,
}

pub struct AppDomainInfo {
    pub name: String,
    pub process_id: ProcessID,
}

pub struct AssemblyInfo {
    pub name: String,
    pub app_domain_id: AppDomainID,
    pub module_id: ModuleID,
}

#[derive(Debug)]
pub struct FunctionInfo2 {
    pub class_id: ClassID,
    pub module_id: ModuleID,
    pub token: mdMethodDef,
    pub type_args: Vec<ClassID>,
}

pub struct ClassLayout {
    pub field_offset: Vec<COR_FIELD_OFFSET>,
    pub class_size_bytes: u32,
}

pub struct ClassInfo2 {
    pub module_id: ModuleID,
    pub token: mdTypeDef,
    pub parent_class_id: ClassID,
    pub type_args: Vec<ClassID>,
}

pub struct ArrayObjectInfo {
    pub dimension_sizes: Vec<u32>,
    pub dimension_lower_bounds: Vec<i32>,
    pub data: *mut BYTE, // TODO: This should be the raw buffer for the array, which is laid out according to the C++ convention.
}

pub struct StringLayout {
    pub string_length_offset: u32,
    pub buffer_offset: u32,
}

pub struct FunctionEnter3Info {
    pub frame_info: COR_PRF_FRAME_INFO,
    pub argument_info_length: u32,
    pub argument_info: COR_PRF_FUNCTION_ARGUMENT_INFO,
}

pub struct FunctionLeave3Info {
    pub frame_info: COR_PRF_FRAME_INFO,
    pub retval_range: COR_PRF_FUNCTION_ARGUMENT_RANGE,
}

pub struct RuntimeInfo {
    pub clr_instance_id: ClrInstanceID,
    pub runtime_type: COR_PRF_RUNTIME_TYPE,
    pub major_version: u16,
    pub minor_version: u16,
    pub build_number: u16,
    pub qfe_version: u16,
    pub version_string: String,
}

#[derive(Debug)]
pub struct ModuleInfo2 {
    pub base_load_address: LPCBYTE,
    pub file_name: String,
    pub assembly_id: AssemblyID,
    pub module_flags: COR_PRF_MODULE_FLAGS,
}

pub struct FunctionAndRejit {
    pub function_id: FunctionID,
    pub rejit_id: ReJITID,
}

pub struct EventMask2 {
    pub events_low: COR_PRF_MONITOR,
    pub events_high: COR_PRF_HIGH_MONITOR,
}

pub struct EnumNgenModuleMethodsInliningThisMethod<'a> {
    pub incomplete_data: bool,
    pub method_enum: &'a mut CorProfilerMethodEnum,
}

pub struct DynamicFunctionInfo {
    pub module_id: ModuleID,
    pub sig: PCCOR_SIGNATURE,
    pub sig_length: u32,
    pub name: String,
}

#[derive(Debug)]
pub struct MethodProps {
    pub class_token: mdTypeDef,
    pub name: String,
    pub attr_flags: CorMethodAttr,
    pub sig: PCCOR_SIGNATURE,
    pub sig_length: u32,
    pub rva: u32,
    pub impl_flags: CorMethodImpl,
}

impl MethodProps {
    pub fn parse_signature(&self) -> Result<MethodSignature, SignatureError> {
        let mut parser = SignatureParser::new(self.sig, self.sig_length);
        parser.parse_method_signature()
    }
}

#[derive(Debug)]
pub struct TypeDefProps {
    pub name: String,
    pub type_def_flags: CorTypeAttr,
    pub parent_token: mdTypeDef
}

#[derive(Debug)]
pub struct CorFuncArg {
    pub sig_type: TypeSignature,
    pub raw_bytes: Vec<u8>,
}

impl CorFuncArg {
    pub fn from_arg_range(arg_range: &COR_PRF_FUNCTION_ARGUMENT_RANGE, arg_type: &TypeSignature) -> Self {
        let raw_bytes = unsafe {slice::from_raw_parts(arg_range.startAddress as *const u8, arg_range.length as usize)};
        Self { 
            sig_type: arg_type.clone(), 
            raw_bytes: raw_bytes.to_vec() 
        }
    }

    //TODO: Parse all the types
    //TODO: Read array element/object size from MethodTable (ref https://www.reddit.com/r/csharp/comments/92i28f/c_internals_calculating_the_heap_size_of_managed/)
    //TODO: Remove all `expect()` and return Result.
    //TODO: Create Error struct.
    pub fn value(&self) -> Result<TypedValue, String> {
        let ptr_size = size_of::<usize>();
        debug!("pointer size: {ptr_size}");

        match &self.sig_type {
            TS::String => {
                let mut ptr = usize::from_le_bytes(
                    self.raw_bytes.clone()
                    .try_into()
                    .map_err(|err| format!("failed to convert arg bytes to ptr due to {err:?}"))?
                );
                debug!("param String; object pointer = {ptr:#x?}");

                let mptr_slice = unsafe { slice::from_raw_parts(ptr as *const u8, ptr_size ) };
                let mptr = usize::from_le_bytes(mptr_slice.try_into().expect("insufficient data")); //should not result in error
                debug!("param String; MethodTable pointer = {mptr:#x?}");

                ptr += ptr_size;
                let size_bytes = unsafe { slice::from_raw_parts(ptr as *const u8, 4) }; //what happens if data is more than I32::Max?
                let size = u32::from_le_bytes(size_bytes.try_into().expect("insufficient data")); //should not result in error
                debug!("param String; length = {size} ({size:#x})");

                ptr += 4;
                let raw_bytes = unsafe { slice::from_raw_parts(ptr as *const u16, size as usize) };
                let value = OsString::from_wide(raw_bytes);

                let val = RefType {
                    method_table_ptr: mptr,
                    size: size as usize,
                    value: RefValue::String(value)
                };
                Ok(TypedValue::Ref(val))
            },

            TS::SZArray(el_type) => {
                let mut ptr = usize::from_le_bytes(
                    self.raw_bytes.clone()
                    .try_into()
                    .map_err(|err| format!("failed to convert arg bytes to ptr due to {err:?}"))?
                );
                debug!("param SZArray; object pointer = {ptr:#x?}");

                let mptr_slice = unsafe { slice::from_raw_parts(ptr as *const u8, ptr_size ) };
                let mptr = usize::from_le_bytes(mptr_slice.try_into().expect("insufficient data")); //should not result in error
                debug!("param SZArray; MethodTable pointer = {mptr:#x?}");

                ptr += ptr_size;
                let size_bytes = unsafe { slice::from_raw_parts(ptr as *const u8, 4) }; //what happens if size is more than I32::Max?
                
                let size = u32::from_le_bytes(size_bytes.try_into().expect("insufficient data"));//should not result in error
                debug!("param SZArray; length = {size} ({size:#x})");

                #[cfg(target_arch = "x86_64")]
                { //only needed for x64
                    debug!("skipping padding for x64");
                    ptr += 4;
                    let _padding = u32::from_le_bytes(size_bytes.try_into().expect("insufficient data")); //should not result in error
                }

                ptr += 4;

                debug!("param SZArray; element type: {:?}", **el_type);
                let value = match **el_type {
                    TS::Byte | TS::Boolean | TS::Char | TS::SByte => {
                        unsafe { slice::from_raw_parts(ptr as *const u8, size as usize) }
                    },
                    _ => todo!(), //TODO: implement other array types
                };

                let val = RefType {
                    method_table_ptr: mptr,
                    size: size as usize,
                    value: RefValue::Array(value.to_vec())
                };

                Ok(TypedValue::Ref(val))
            },

            _ => {
                Ok(TypedValue::Val(ValueType::try_from(&self.raw_bytes, &self.sig_type)?))
            }
        }
    }
}

#[derive(Debug)]
pub enum TypedValue {
    Val(ValueType),
    Ref(RefType),
}

impl Display for TypedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            Self::Ref(val) => format!("{val}"),
            Self::Val(val) => format!("{val}")
        };
        write!(f, "{str}")
    }
}

#[derive(Debug)]
pub enum ValueType {
    Void,
    Bool(bool),
    Char(char),
    Byte(u8),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Unknown(Vec<u8>),
}

impl Display for ValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ValueType::*;
        
        let str = match self {
            Void => "(void)".into(),
            Bool(value) => value.to_string(),
            Char(value) => value.to_string(),
            Byte(value) => value.to_string(),
            Int16(value) => value.to_string(),
            UInt16(value) => value.to_string(),
            Int32(value) => value.to_string(),
            UInt32(value) => value.to_string(),
            Int64(value) => value.to_string(),
            UInt64(value) => value.to_string(),
            Unknown(value) => format!("{:?}", value)
        };

        write!(f, "{str}")
    }
}

impl ValueType {

    pub(crate) fn try_from(value: &Vec<u8>, typesig: &TypeSignature) -> Result<Self, String> {
        let parsed = match typesig {
            TS::Boolean => Self::Bool(value.iter().any(|v| *v != 0)),
            TS::Char => Self::Char(value[0].try_into().map_err(|err| format!("{err}"))?),
            TS::SByte | TS::Byte => Self::Byte(value[0].try_into().map_err(|err| format!("{err}"))?),
            TS::Int16  => Self::Int16(i16::from_le_bytes(value.clone().try_into().map_err(|err| format!("{err:?}"))?)),
            TS::UInt16 => Self::UInt16(u16::from_le_bytes(value.clone().try_into().map_err(|err| format!("{err:?}"))?)),
            TS::Int32  => Self::Int32(i32::from_le_bytes(value.clone().try_into().map_err(|err| format!("{err:?}"))?)),
            TS::UInt32 => Self::UInt32(u32::from_le_bytes(value.clone().try_into().map_err(|err| format!("{err:?}"))?)),
            TS::Int64  => Self::Int64(i64::from_le_bytes(value.clone().try_into().map_err(|err| format!("{err:?}"))?)),
            TS::UInt64 => Self::UInt64(u64::from_le_bytes(value.clone().try_into().map_err(|err| format!("{err:?}"))?)),
            _ => Self::Unknown(value.clone()),
        };
        
        Ok(parsed)
    }
}

#[derive(Debug)]
pub struct RefType {
    pub method_table_ptr: UINT_PTR,
    pub size: usize,
    pub value: RefValue,
}

impl Display for RefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[derive(Debug)]
pub enum RefValue {
    String(OsString),
    Array(Vec<u8>),
    Unknown(Vec<u8>),
}

impl Display for RefValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RefValue::*;
        let str = match self {
            String(val) => format!("\"{}\"",val.to_string_lossy().to_string()),
            Array(val) => format!("{val:?}"),
            Unknown(val) => format!("{val:?}"),
        };
        write!(f, "{str}")
    }
}

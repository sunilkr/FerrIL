use crate::ffi::PCCOR_SIGNATURE;
use crate::MetadataImportTrait;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::slice;

/// Represents a parsed method signature
#[derive(Debug, Clone, PartialEq)]
pub struct MethodSignature {
    pub calling_convention: CallingConvention,
    pub generic_param_count: u32,
    pub return_type: TypeSignature,
    pub parameters: Vec<ParameterSignature>,
    pub has_this: bool,
    pub explicit_this: bool,
}

/// Calling conventions for methods
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CallingConvention {
    Default,
    VarArg,
    Field,
    LocalSig,
    Property,
    Unmanaged,
    GenericInst,
    NativeVarArg,
    Other(u8),
}

impl From<u8> for CallingConvention {
    fn from(value: u8) -> Self {
        match value & 0x0F {
            0x00 => Self::Default,
            0x01 => Self::VarArg,
            0x02 => Self::Field,
            0x03 => Self::LocalSig,
            0x04 => Self::Property,
            0x05 => Self::Unmanaged,
            0x0A => Self::GenericInst,
            0x0B => Self::NativeVarArg,
            other => Self::Other(other),
        }
    }
}

/// Represents a type in a signature
#[derive(Debug, Clone, PartialEq)]
pub enum TypeSignature {
    Void,
    Boolean,
    Char,
    SByte,
    Byte,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Single,
    Double,
    String,
    Pointer(Box<TypeSignature>),
    ByRef(Box<TypeSignature>),
    ValueType(u32), // Token
    Class(u32),     // Token
    Array(Box<TypeSignature>, Vec<u32>), // Element type, dimensions
    SZArray(Box<TypeSignature>),         // Single-dimension array
    GenericInst(Box<TypeSignature>, Vec<TypeSignature>), // Generic type, type arguments
    Var(u32),       // Generic parameter index (method)
    MVar(u32),      // Generic parameter index (type)
    FnPtr(Box<MethodSignature>),
    Object,
    TypedByRef,
    IntPtr,
    UIntPtr,
    Custom(u32, Box<TypeSignature>), // Token, type
    Unknown(u8),
}

impl TypeSignature {
    pub fn data_size(&self) -> Option<usize> {
        match self {
            Self::Void => Some(0),
            Self::Boolean | Self::Char | Self::SByte | Self::Byte | Self::Unknown(_) => Some(size_of::<u8>()),
            Self::Int16 | Self::UInt16 => Some(size_of::<u16>()),
            Self::Int32 | Self::UInt32 | Self::Single => Some(size_of::<u32>()),
            Self::Int64 | Self::UInt64 | Self::Double => Some(size_of::<u64>()),
            _ => None,
            // Self::String => todo!(),
            // Self::Pointer(type_signature) => todo!(),
            // Self::ByRef(type_signature) => todo!(),
            // Self::ValueType(_) => todo!(),
            // Self::Class(_) => todo!(),
            // Self::Array(type_signature, items) => todo!(),
            // Self::SZArray(type_signature) => todo!(),
            // Self::GenericInst(type_signature, type_signatures) => todo!(),
            // Self::Var(_) => todo!(),
            // Self::MVar(_) => todo!(),
            // Self::FnPtr(method_signature) => todo!(),
            // Self::Object => todo!(),
            // Self::TypedByRef => todo!(),
            // Self::IntPtr => todo!(),
            // Self::UIntPtr => todo!(),
            // Self::Custom(_, type_signature) => todo!(),
            // Self::Unknown(_) => todo!(),
        }
    }
}

/// Represents a parameter in a method signature
#[derive(Debug, Clone, PartialEq)]
pub struct ParameterSignature {
    pub type_sig: TypeSignature,
    pub is_in: bool,
    pub is_out: bool,
    pub is_optional: bool,
}

/// Parser for method signatures
pub struct SignatureParser<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> SignatureParser<'a> {
    /// Create a new parser from a raw signature pointer
    pub fn new(sig: PCCOR_SIGNATURE, len: u32) -> Self {
        let data = unsafe { slice::from_raw_parts(sig, len as usize) };
        SignatureParser { data, position: 0 }
    }

    /// Parse a method signature
    pub fn parse_method_signature(&mut self) -> Result<MethodSignature, SignatureError> {
        // Read calling convention
        let conv_byte = self.read_byte()?;
        let has_this = (conv_byte & 0x20) != 0;
        let explicit_this = (conv_byte & 0x40) != 0;
        let calling_convention = CallingConvention::from(conv_byte);

        // Read generic parameter count if present
        let generic_param_count = if calling_convention == CallingConvention::Default 
            && (conv_byte & 0x10) != 0 {
            self.read_compressed_uint()?
        } else {
            0
        };

        // Read parameter count
        let param_count = self.read_compressed_uint()?;

        // Read return type
        let return_type = self.parse_type()?;

        // Read parameters
        let mut parameters = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            parameters.push(self.parse_parameter()?);
        }

        Ok(MethodSignature {
            calling_convention,
            generic_param_count,
            return_type,
            parameters,
            has_this,
            explicit_this,
        })
    }

    /// Parse a parameter signature
    fn parse_parameter(&mut self) -> Result<ParameterSignature, SignatureError> {
        // Check for parameter modifiers
        let mut is_in = false;
        let mut is_out = false;
        let mut is_optional = false;

        loop {
            let peek = self.peek_byte()?;
            match peek {
                0x10 => { // ELEMENT_TYPE_CMOD_REQD
                    self.read_byte()?;
                    let _token = self.read_compressed_uint()?;
                    // Handle required modifier
                }
                0x11 => { // ELEMENT_TYPE_CMOD_OPT
                    self.read_byte()?;
                    let _token = self.read_compressed_uint()?;
                    // Handle optional modifier
                }
                0x45 => { // Custom attribute for [In]
                    self.read_byte()?;
                    is_in = true;
                }
                0x46 => { // Custom attribute for [Out]
                    self.read_byte()?;
                    is_out = true;
                }
                0x51 => { // Custom attribute for [Optional]
                    self.read_byte()?;
                    is_optional = true;
                }
                _ => break,
            }
        }

        let type_sig = self.parse_type()?;
        Ok(ParameterSignature {
            type_sig,
            is_in,
            is_out,
            is_optional,
        })
    }

    /// Parse a type signature
    fn parse_type(&mut self) -> Result<TypeSignature, SignatureError> {
        let type_byte = self.read_byte()?;
        match type_byte {
            0x01 => Ok(TypeSignature::Void),
            0x02 => Ok(TypeSignature::Boolean),
            0x03 => Ok(TypeSignature::Char),
            0x04 => Ok(TypeSignature::SByte),
            0x05 => Ok(TypeSignature::Byte),
            0x06 => Ok(TypeSignature::Int16),
            0x07 => Ok(TypeSignature::UInt16),
            0x08 => Ok(TypeSignature::Int32),
            0x09 => Ok(TypeSignature::UInt32),
            0x0A => Ok(TypeSignature::Int64),
            0x0B => Ok(TypeSignature::UInt64),
            0x0C => Ok(TypeSignature::Single),
            0x0D => Ok(TypeSignature::Double),
            0x0E => Ok(TypeSignature::String),
            0x0F => {
                let inner = self.parse_type()?;
                Ok(TypeSignature::Pointer(Box::new(inner)))
            }
            0x10 => {
                let inner = self.parse_type()?;
                Ok(TypeSignature::ByRef(Box::new(inner)))
            }
            0x11 => {
                let token = self.read_compressed_uint()?;
                Ok(TypeSignature::ValueType(token))
            }
            0x12 => {
                let token = self.read_compressed_uint()?;
                Ok(TypeSignature::Class(token))
            }
            0x13 => {
                let index = self.read_compressed_uint()?;
                Ok(TypeSignature::Var(index))
            }
            0x14 => {
                let elem_type = self.parse_type()?;
                let rank = self.read_compressed_uint()?;
                let mut dimensions = Vec::with_capacity(rank as usize);
                
                // Read sizes
                let num_sizes = self.read_compressed_uint()?;
                for _ in 0..num_sizes {
                    dimensions.push(self.read_compressed_uint()?);
                }
                
                // Read lower bounds
                let num_bounds = self.read_compressed_uint()?;
                for _ in 0..num_bounds {
                    let _ = self.read_compressed_uint()?; // Ignore lower bounds for now
                }
                
                Ok(TypeSignature::Array(Box::new(elem_type), dimensions))
            }
            0x15 => {
                let generic_type = self.parse_type()?;
                let arg_count = self.read_compressed_uint()?;
                let mut type_args = Vec::with_capacity(arg_count as usize);
                
                for _ in 0..arg_count {
                    type_args.push(self.parse_type()?);
                }
                
                Ok(TypeSignature::GenericInst(Box::new(generic_type), type_args))
            }
            0x16 => Ok(TypeSignature::TypedByRef),
            0x18 => Ok(TypeSignature::IntPtr),
            0x19 => Ok(TypeSignature::UIntPtr),
            0x1B => {
                let fn_sig = self.parse_method_signature()?;
                Ok(TypeSignature::FnPtr(Box::new(fn_sig)))
            }
            0x1C => Ok(TypeSignature::Object),
            0x1D => {
                let elem_type = self.parse_type()?;
                Ok(TypeSignature::SZArray(Box::new(elem_type)))
            }
            0x1E => {
                let index = self.read_compressed_uint()?;
                Ok(TypeSignature::MVar(index))
            }
            _ => Ok(TypeSignature::Unknown(type_byte)),
        }
    }

    /// Read a single byte from the signature
    fn read_byte(&mut self) -> Result<u8, SignatureError> {
        if self.position >= self.data.len() {
            return Err(SignatureError::UnexpectedEnd);
        }
        let byte = self.data[self.position];
        self.position += 1;
        Ok(byte)
    }

    /// Peek at the next byte without advancing
    fn peek_byte(&self) -> Result<u8, SignatureError> {
        if self.position >= self.data.len() {
            return Err(SignatureError::UnexpectedEnd);
        }
        Ok(self.data[self.position])
    }

    /// Read a compressed unsigned integer
    fn read_compressed_uint(&mut self) -> Result<u32, SignatureError> {
        let first = self.read_byte()? as u32;
        
        if (first & 0x80) == 0 {
            // 1-byte encoding
            return Ok(first);
        } else if (first & 0xC0) == 0x80 {
            // 2-byte encoding
            let second = self.read_byte()? as u32;
            return Ok(((first & 0x3F) << 8) | second);
        } else if (first & 0xE0) == 0xC0 {
            // 4-byte encoding
            let second = self.read_byte()? as u32;
            let third = self.read_byte()? as u32;
            let fourth = self.read_byte()? as u32;
            return Ok(((first & 0x1F) << 24) | (second << 16) | (third << 8) | fourth);
        }
        
        Err(SignatureError::InvalidCompressedInteger)
    }
}

/// Errors that can occur during signature parsing
#[derive(Debug)]
pub enum SignatureError {
    UnexpectedEnd,
    InvalidCompressedInteger,
    InvalidType,
    InvalidCallingConvention,
}

impl Display for MethodSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        // Format return type
        write!(f, "{} ", self.return_type)?;
        
        // Format generic parameters if any
        if self.generic_param_count > 0 {
            write!(f, "<")?;
            for i in 0..self.generic_param_count {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "T{}", i)?;
            }
            write!(f, "> ")?;
        }
        
        // Format parameters
        write!(f, "(")?;
        for (i, param) in self.parameters.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            
            if param.is_in {
                write!(f, "[In] ")?;
            }
            if param.is_out {
                write!(f, "[Out] ")?;
            }
            if param.is_optional {
                write!(f, "[Optional] ")?;
            }
            
            write!(f, "{}", param.type_sig)?;
        }
        write!(f, ")")
    }
}

impl Display for TypeSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            TypeSignature::Void => write!(f, "void"),
            TypeSignature::Boolean => write!(f, "bool"),
            TypeSignature::Char => write!(f, "char"),
            TypeSignature::SByte => write!(f, "sbyte"),
            TypeSignature::Byte => write!(f, "byte"),
            TypeSignature::Int16 => write!(f, "short"),
            TypeSignature::UInt16 => write!(f, "ushort"),
            TypeSignature::Int32 => write!(f, "int"),
            TypeSignature::UInt32 => write!(f, "uint"),
            TypeSignature::Int64 => write!(f, "long"),
            TypeSignature::UInt64 => write!(f, "ulong"),
            TypeSignature::Single => write!(f, "float"),
            TypeSignature::Double => write!(f, "double"),
            TypeSignature::String => write!(f, "string"),
            TypeSignature::Pointer(inner) => write!(f, "{}*", inner),
            TypeSignature::ByRef(inner) => write!(f, "{}&", inner),
            TypeSignature::ValueType(token) => write!(f, "ValueType(0x{:X})", token),
            TypeSignature::Class(token) => write!(f, "Class(0x{:X})", token),
            TypeSignature::Array(elem, dims) => {
                write!(f, "{}[", elem)?;
                for (i, dim) in dims.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    if *dim > 0 {
                        write!(f, "{}", dim)?;
                    }
                }
                write!(f, "]")
            }
            TypeSignature::SZArray(elem) => write!(f, "{}[]", elem),
            TypeSignature::GenericInst(base_type, args) => {
                write!(f, "{}<", base_type)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ">")
            }
            TypeSignature::Var(index) => write!(f, "T{}", index),
            TypeSignature::MVar(index) => write!(f, "M{}", index),
            TypeSignature::FnPtr(_) => write!(f, "delegate*"),
            TypeSignature::Object => write!(f, "object"),
            TypeSignature::TypedByRef => write!(f, "typedref"),
            TypeSignature::IntPtr => write!(f, "IntPtr"),
            TypeSignature::UIntPtr => write!(f, "UIntPtr"),
            TypeSignature::Custom(token, inner) => write!(f, "Custom(0x{:X}, {})", token, inner),
            TypeSignature::Unknown(byte) => write!(f, "Unknown(0x{:X})", byte),
        }
    }
}

// Extension trait for MetadataImport
pub trait SignatureParserExt {
    fn parse_method_signature(&self, method_def: crate::ffi::mdMethodDef) -> Result<MethodSignature, SignatureError>;
}

impl SignatureParserExt for crate::MetadataImport {
    fn parse_method_signature(&self, method_def: crate::ffi::mdMethodDef) -> Result<MethodSignature, SignatureError> {
        let method_props = self.get_method_props(method_def)
            .map_err(|_| SignatureError::UnexpectedEnd)?;
        
        let mut parser = SignatureParser::new(method_props.sig, method_props.sig_length);
        parser.parse_method_signature()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_method_signature() {
        // This represents a simple void Method() signature
        let signature_bytes = [
            0x00, // DEFAULT calling convention
            0x00, // 0 parameters
            0x01, // VOID return type
        ];
        
        let mut parser = SignatureParser {
            data: &signature_bytes,
            position: 0,
        };
        
        let result = parser.parse_method_signature().unwrap();
        
        assert_eq!(result.calling_convention, CallingConvention::Default);
        assert_eq!(result.generic_param_count, 0);
        assert!(matches!(result.return_type, TypeSignature::Void));
        assert_eq!(result.parameters.len(), 0);
        assert_eq!(result.has_this, false);
        assert_eq!(result.explicit_this, false);
    }
    
    #[test]
    fn test_parse_instance_method_signature() {
        // This represents an instance int Method(string) signature
        let signature_bytes = [
            0x20, // DEFAULT calling convention with HASTHIS flag
            0x01, // 1 parameter
            0x08, // INT32 return type
            0x0E, // STRING parameter type
        ];
        
        let mut parser = SignatureParser {
            data: &signature_bytes,
            position: 0,
        };
        
        let result = parser.parse_method_signature().unwrap();
        
        assert_eq!(result.calling_convention, CallingConvention::Default);
        assert_eq!(result.generic_param_count, 0);
        assert!(matches!(result.return_type, TypeSignature::Int32));
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(result.parameters[0].type_sig, TypeSignature::String));
        assert_eq!(result.has_this, true);
        assert_eq!(result.explicit_this, false);
    }
    
    #[test]
    fn test_parse_generic_method_signature() {
        // This represents a generic T Method<T>(T) signature
        let signature_bytes = [
            0x10, // DEFAULT calling convention with GENERIC flag
            0x01, // 1 generic parameter
            0x01, // 1 parameter
            0x13, // VAR (generic type parameter) return type
            0x00, // Index 0
            0x13, // VAR (generic type parameter) parameter type
            0x00, // Index 0
        ];
        
        let mut parser = SignatureParser {
            data: &signature_bytes,
            position: 0,
        };
        
        let result = parser.parse_method_signature().unwrap();
        
        assert_eq!(result.calling_convention, CallingConvention::Default);
        assert_eq!(result.generic_param_count, 1);
        assert!(matches!(result.return_type, TypeSignature::Var(0)));
        assert_eq!(result.parameters.len(), 1);
        assert!(matches!(result.parameters[0].type_sig, TypeSignature::Var(0)));
    }
    
    #[test]
    fn test_parse_complex_types() {
        // This represents a List<int>[] Method(ref Dictionary<string, object>) signature
        let signature_bytes = [
            0x00, // DEFAULT calling convention
            0x01, // 1 parameter
            0x1D, // SZARRAY return type
            0x15, // GENERICINST
            0x12, // CLASS
            0x01, 0x00, 0x00, 0x01, // Token 0x01000001 (List<>)
            0x01, // 1 type argument
            0x08, // INT32
            0x10, // BYREF parameter modifier
            0x15, // GENERICINST
            0x12, // CLASS
            0x02, 0x00, 0x00, 0x01, // Token 0x01000002 (Dictionary<,>)
            0x02, // 2 type arguments
            0x0E, // STRING
            0x1C, // OBJECT
        ];
        
        let mut parser = SignatureParser {
            data: &signature_bytes,
            position: 0,
        };
        
        let result = parser.parse_method_signature().unwrap();
        
        // Check return type: List<int>[]
        if let TypeSignature::SZArray(elem_type) = &result.return_type {
            if let TypeSignature::GenericInst(base_type, type_args) = &**elem_type {
                if let TypeSignature::Class(token) = &**base_type {
                    assert_eq!(*token, 0x01000001);
                } else {
                    panic!("Expected Class base type");
                }
                assert_eq!(type_args.len(), 1);
                assert!(matches!(type_args[0], TypeSignature::Int32));
            } else {
                panic!("Expected GenericInst");
            }
        } else {
            panic!("Expected SZArray");
        }
        
        // Check parameter: ref Dictionary<string, object>
        assert_eq!(result.parameters.len(), 1);
        if let TypeSignature::ByRef(elem_type) = &result.parameters[0].type_sig {
            if let TypeSignature::GenericInst(base_type, type_args) = &**elem_type {
                if let TypeSignature::Class(token) = &**base_type {
                    assert_eq!(*token, 0x01000002);
                } else {
                    panic!("Expected Class base type");
                }
                assert_eq!(type_args.len(), 2);
                assert!(matches!(type_args[0], TypeSignature::String));
                assert!(matches!(type_args[1], TypeSignature::Object));
            } else {
                panic!("Expected GenericInst");
            }
        } else {
            panic!("Expected ByRef");
        }
    }
    
    #[test]
    fn test_compressed_uint() {
        // Test 1-byte encoding
        let bytes_1 = [0x05]; // 5
        let mut parser_1 = SignatureParser {
            data: &bytes_1,
            position: 0,
        };
        assert_eq!(parser_1.read_compressed_uint().unwrap(), 5);
        
        // Test 2-byte encoding
        let bytes_2 = [0x80, 0x80]; // 128
        let mut parser_2 = SignatureParser {
            data: &bytes_2,
            position: 0,
        };
        assert_eq!(parser_2.read_compressed_uint().unwrap(), 128);
        
        // Test 4-byte encoding
        let bytes_4 = [0xC0, 0x00, 0x00, 0x01]; // 0x10000
        let mut parser_4 = SignatureParser {
            data: &bytes_4,
            position: 0,
        };
        assert_eq!(parser_4.read_compressed_uint().unwrap(), 0x10000);
    }
    
    #[test]
    fn test_display_method_signature() {
        let signature = MethodSignature {
            calling_convention: CallingConvention::Default,
            generic_param_count: 2,
            return_type: TypeSignature::Int32,
            parameters: vec![
                ParameterSignature {
                    type_sig: TypeSignature::String,
                    is_in: false,
                    is_out: false,
                    is_optional: false,
                },
                ParameterSignature {
                    type_sig: TypeSignature::Var(0),
                    is_in: false,
                    is_out: false,
                    is_optional: false,
                },
                ParameterSignature {
                    type_sig: TypeSignature::Var(1),
                    is_in: true,
                    is_out: true,
                    is_optional: true,
                },
            ],
            has_this: true,
            explicit_this: false,
        };
        
        let display_str = format!("{}", signature);
        assert_eq!(display_str, "int <T0, T1> (string, T0, [In] [Out] [Optional] T1)");
    }
}

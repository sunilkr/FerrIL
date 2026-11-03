use crate::{
    ffi::{mdMethodDef, mdTypeDef, HRESULT},
    MethodProps, TypeDefProps,
};

pub trait MetadataImportTrait {
    fn get_method_props(&self, mb: mdMethodDef) -> Result<MethodProps, HRESULT>;
    fn get_type_def_props(&self, td: mdTypeDef) -> Result<TypeDefProps, HRESULT>;
}

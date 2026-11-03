use std::{sync::OnceLock, vec};

use clr_profiler::{
    traits::{
        ClrProfiler, CorProfilerCallback, CorProfilerCallback2, CorProfilerCallback3, CorProfilerCallback4, CorProfilerCallback5, 
        CorProfilerCallback6, CorProfilerCallback7, CorProfilerCallback8, CorProfilerCallback9, CorProfilerInfo, MetadataImportTrait
    },
    ProfilerInfo, 
    types::{IlFunctionBody, MethodProps, TypeDefProps},
    cil::{Method, MethodHeader, TinyMethodHeader}, 
    ffi::{COR_PRF_MONITOR, ClassFactory, CorOpenFlags, DWORD, E_FAIL, ERROR_INVALID_DATA, FunctionID, HANDLE, HRESULT, LPVOID, REFCLSID, REFIID}
};
use config::{self, Config, typedef::{PatchDef, PatchParams}};
use log::{debug, error, info, trace, warn};
use log_init::init_logging;
use uuid::Uuid;
use wildcard::Wildcard;

const PROFILER_UUID: &str = "DF63A541-5A33-4611-8829-F4E495985EE3";
//const PATCHED_FUNCS: [&str; 3]  = ["userCertValidationCallbackWrapper", "OperateVisibleSystem", "ValidateChain"];
//static mut CONFIG: Option<Config> = None;
static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Clone)]
struct Profiler {
    pub(crate) clsid: Uuid,
    pub(crate) patch_defs: Vec<PatchDef>,
    profiler_info: Option<ProfilerInfo>,
}

impl Profiler {
    fn profiler_info(&self) -> &ProfilerInfo {
        self.profiler_info.as_ref().unwrap()
    }

    fn with_clsid(clsid: Uuid) -> Self {
        Self { 
            clsid: clsid, 
            patch_defs: vec![],
            profiler_info: None, 
        }
    }

    fn get_patch_for(&self, method_props: &MethodProps, class_props: &TypeDefProps, il_body: &IlFunctionBody) -> Result<Option<Method>, HRESULT> {
        let method = Method::new(il_body.method_header, il_body.method_size).or(Err(E_FAIL))?;
        let il_bytes = method.instructions_to_bytes();

        let Some(patch_def) = self.find_patch_config(method_props, class_props, &il_bytes)
            else {
                trace!("no config for {}::{}", class_props.name, method_props.name);
                return Ok(None);
            };

        //we have found a match
        info!("found patch config for {}::{}", class_props.name, method_props.name);
        
        info!("inspecting {}::{}()", class_props.name, method_props.name);
        debug!("{class_props:#?}");
        debug!("{method_props:#?}");

        debug!("{:#?}", method.method_header);
        debug!("body:\n{{\n    {}\n}}",
            method.instructions.iter()
            .map(|inst| format!("{:#?} : {inst}", 
                inst.into_bytes()
                .iter()
                .map(|b| format!("{b:#02x}"))
                .collect::<Vec<String>>().
                join(" "))
            )
            .collect::<Vec<String>>()
            .join("\n    ")
        );
        
        debug!("sections: {:#?}", method.sections);
        
        let new_bytes = self.apply_patch(&patch_def.params, &il_bytes);
        let new_body = Method::instructions_from_bytes(&new_bytes).or(Err(ERROR_INVALID_DATA))?;
        debug!("new IL body: \n{{\n  {}\n}}", 
            new_body.iter()
            .map(|inst| format!("{inst}"))
            .collect::<Vec<String>>()
            .join("\n  ")
        );

        // TODO:
        // 1. Modify method header
        // 2. Add a prologue
        // 3. Add an epilogue
        // 4. Modify SEH tables
        let new_header = if new_body.len() > 8 || patch_def.params.copy_header(){
            debug!("copying old method header");
            method.method_header
        } else { 
            debug!("creating new tiny header");
            MethodHeader::Tiny(TinyMethodHeader{code_size: new_body.len() as u8}) 
        };

        let new_method = Method{
            method_header: new_header,
            instructions: new_body,
            sections: vec![]
        };

        info!("creating replacement method with {} instructions", new_method.instructions.len());

        return Ok(Some(new_method));
    }

    fn find_patch_config(&self, method_props: &MethodProps, class_props: &TypeDefProps, il_bytes: &Vec<u8>) -> Option<&PatchDef> {
        for patch_def in &self.patch_defs {
            let matcher = &patch_def.matcher;
            
            if matcher.name().is_none() || (matcher.name().unwrap() == method_props.name) {
                if matcher.class().is_none() || (matcher.class().unwrap() == class_props.name) {
                    if matcher.pattern().is_none() 
                        || (Wildcard::new(&matcher.pattern()
                                .unwrap())
                            .unwrap()
                            .is_match(il_bytes)) 
                    {
                        debug!("found patch using matcher with {{Name: {}, Class: {}, Pattern: {}}}",
                            matcher.name().is_some(), 
                            matcher.class().is_some(), 
                            matcher.pattern().is_some()
                        );
                        return Some(patch_def)
                    }
                }
            }
        }

        None
    }

    fn apply_patch(&self, params: &PatchParams, il_bytes: &Vec<u8>) -> Vec<u8> {
        let mut new_bytes: Vec<u8>; //= patch_def.params.new_bytes();
        // if new_bytes.len() == 0 {
        //     new_bytes = vec![23, 42]; //[ldc_i4_1(), ret()], //return true;
        // }

        let offset = params.offset();
        if offset > 0 {
            new_bytes = il_bytes[..offset].to_vec();
            new_bytes.extend(params.new_bytes());
        } else {
            new_bytes = params.new_bytes();
        }
        
        if !params.truncate() {
            new_bytes.extend(il_bytes[(offset + params.new_bytes().len())..].to_vec()); //TODO: ensure correctness of instructions.
        }

        new_bytes
    }
}


impl ClrProfiler for Profiler {
    fn new() -> Profiler {
        Profiler {
            clsid: Uuid::parse_str(PROFILER_UUID).unwrap(), //Should not result in error.
            patch_defs: vec![],
            profiler_info: None,
        }
    }

    fn clsid(&self) -> &Uuid {
        &self.clsid
    }
}

impl CorProfilerCallback for Profiler {
    fn initialize(&mut self, profiler_info: ProfilerInfo) -> Result<(), HRESULT> {
        info!("initializing profiler");
        
        // Initialize ICorProfilerInfo reference    
        self.profiler_info = Some(profiler_info);
        if let Some(conf) = CONFIG.get() {
            if let Some(patch_defs) = conf.patches() {
                self.patch_defs = patch_defs.clone();
                info!("got {} patch configs", self.patch_defs.len());
            }
        } else {
            warn!("did not find any patch config")
        }

        // Set the event mask
        self.profiler_info()
            .set_event_mask(
                COR_PRF_MONITOR::COR_PRF_MONITOR_JIT_COMPILATION
                | COR_PRF_MONITOR::COR_PRF_DISABLE_ALL_NGEN_IMAGES
            )?;
            //.set_event_mask(COR_PRF_MONITOR::COR_PRF_ALL)?; // COR_PRF_MONITOR_JIT_COMPILATION

        match self.profiler_info().get_event_mask() {
            Ok(mask) => debug!("current event mask: {mask:?}"),
            Err(hresult) => warn!("failed to get current event mask, HRESULT = {hresult:#x}"),
        } 

        Ok(())
    }


    fn jit_compilation_started(&mut self, function_id: FunctionID, _is_safe_to_block: bool) -> Result<(), HRESULT> {
        let function_info = self.profiler_info().get_function_info(function_id)?;
        let module_metadata = self
            .profiler_info()
            .get_module_metadata(function_info.module_id, CorOpenFlags::ofRead)?;
        
        let method_props = module_metadata.get_method_props(function_info.token)?;
        let class_props = module_metadata.get_type_def_props(method_props.class_token)?;

        let qualified_method_name = match method_props.name.as_str() {
                ".ctor" | ".cctor" => format!("{}", class_props.name),
                _ => format!("{}.{}", class_props.name, method_props.name)
            }; 
        trace!("jit compiling {qualified_method_name}()");

        let il_body = self
                .profiler_info()
                .get_il_function_body(function_info.module_id, function_info.token)?;
        
        if let Some(new_method) = self.get_patch_for(&method_props, &class_props, &il_body)?{            
            self.profiler_info().set_il_function_body(function_info.module_id, function_info.token, new_method.into_bytes().as_ptr())?;
            info!("function body replaced");
        }
        
        module_metadata.release();
        Ok(())
    }
}

impl CorProfilerCallback2 for Profiler {}
impl CorProfilerCallback3 for Profiler {}
impl CorProfilerCallback4 for Profiler {}
impl CorProfilerCallback5 for Profiler {}
impl CorProfilerCallback6 for Profiler {}
impl CorProfilerCallback7 for Profiler {}
impl CorProfilerCallback8 for Profiler {}
impl CorProfilerCallback9 for Profiler {}

//register!(Profiler);

#[unsafe(no_mangle)]
unsafe extern "system" fn DllGetClassObject(rclsid: REFCLSID, riid: REFIID, ppv: *mut LPVOID) -> HRESULT {
    //println!("[PROF_DEBUG] In DllGetClassObject");
    trace!("in DllGetClassObject");
    
    unsafe {
        debug!("*rclsid = {}, *riid = {}", *rclsid, *riid);
    }
    
    let guid = unsafe { *rclsid };
    let profiler = match Uuid::from_fields(guid.data1, guid.data2, guid.data3, &guid.data4) {
        Ok(uuid) => {
            info!("creating profiler with UUID: {{{}}}", uuid.to_hyphenated());
            Profiler::with_clsid(uuid)
        },
        Err(err) => {
            error!("failed to covert {guid:?} to UUID; err: {err}");
            warn!("creating profiler with default GUID {{{PROFILER_UUID}}}");
            Profiler::new()
        }
    };

    //let profiler = Profiler::new(rclsid);
    //let clsid = GUID::from(*profiler.clsid());
    
    let class_factory: &mut ClassFactory<Profiler> = ClassFactory::new(profiler);
    unsafe { class_factory.QueryInterface(riid, ppv) }
}


const DLL_PROCESS_ATTACH: DWORD = 1;
const DLL_PROCESS_DETACH: DWORD = 0;
const DLL_THREAD_ATTACH:  DWORD = 2;
const DLL_THREAD_DETACH:  DWORD = 3;

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
unsafe extern "system" fn DllMain(hinstDll: HANDLE, fdwReason: DWORD, lpvReserved: LPVOID) {
    let _ = lpvReserved;
    //eprintln!("DllMain(): called");

    match fdwReason {
        DLL_PROCESS_ATTACH => {
            init_logging();
            info!("profiler loaded at {hinstDll:#x?}");

            let cfg = Config::parse_env_file();
            match cfg {
                Ok(config) => {
                    CONFIG.get_or_init(|| config);
                    info!("initialized config");
                },
                Err(err) => {
                    warn!("failed to load config; err: {err}");
                }
            } 
        },

        DLL_PROCESS_DETACH => {
            info!("unloadind DLL");
        },

        DLL_THREAD_ATTACH => {
            debug!("new thread attached");
        },

        DLL_THREAD_DETACH => { },

        _ => {
            eprintln!("DLLMain(): unknwon reason: {fdwReason}");
        }
    }
}


#[cfg(test)]
mod test {

}

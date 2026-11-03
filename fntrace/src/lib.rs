use std::{
    any::type_name, collections::HashMap, fs::OpenOptions, io::Write, path::Path, ptr, sync::{Mutex, Once, OnceLock}
};

use clr_profiler::{
    traits::{
        ClrProfiler, CorProfilerCallback, CorProfilerCallback2, CorProfilerCallback3, CorProfilerCallback4, CorProfilerCallback5,
        CorProfilerCallback6, CorProfilerCallback7, CorProfilerCallback8, CorProfilerCallback9, CorProfilerInfo, CorProfilerInfo2, 
        MetadataImportTrait
    }, 
    types::{CorFuncArg, MethodProps, IlFunctionBody, RefValue, TypeDefProps, TypedValue},
    signature::{MethodSignature, TypeSignature},
    profiler_info::ProfilerInfo,
    cil::Method, 
    ffi::*,
    MetadataImport,
};
use config::{Config, typedef::{OutCfg, TraceDef, TraceParams, Validate, WriteTo}};
use log::{debug, error, info, trace, warn};
use log_init::init_logging;
use rand::distr::{Alphanumeric, SampleString};
use uuid::Uuid;
use lazy_static::lazy_static;

const PROFILER_UUID: &str = "DF63A541-5A33-4611-8829-F4E495985EE3";

static mut PROFILER_INFO: *const ProfilerInfo = ptr::null();
static INIT: Once = Once::new();
static CONFIG: OnceLock<Config> = OnceLock::new();

lazy_static!{
    static ref TRACE_MAP: Mutex<HashMap<FunctionID, Option<TraceDef>>> = Mutex::new(HashMap::new());
}

fn get_cfg_trace_def(methof_props: &MethodProps, class_props: &TypeDefProps, function_body: &IlFunctionBody) -> Result<Option<TraceDef>, HRESULT> {
    let conf = CONFIG.get().ok_or_else( || {
        warn!("config is none");
        E_POINTER
    })?;

    let traces = conf.traces().ok_or({
        trace!("config does not have trace defs");
        E_POINTER
    })?;

    let il_bytes = Method::new(function_body.method_header, function_body.method_size)
        .map_err(|err|{
            warn!("failed to create method due to {err:?}");
            E_FAIL
        })?
        .instructions_to_bytes();
    
    for trace in traces {
        if trace.matcher.is_match(&methof_props.name, &class_props.name, &il_bytes) {
            debug!("got trace config for {}:{}()", class_props.name, methof_props.name);
            return Ok(Some(trace.clone()))
        }
    }

    Ok(None)
}


unsafe extern "system" fn function_enter_2(
    func_id: FunctionID,
    _client_data: UINT_PTR,
    func: COR_PRF_FRAME_INFO,
    argument_info: *const COR_PRF_FUNCTION_ARGUMENT_INFO,
) {
    //trace!("entering fuction {:0x}", func_id);

    if unsafe { PROFILER_INFO.is_null() } {
        panic!("unable to process because PROFILER_INFO is null");
    }

    let profiler_info = unsafe { &*PROFILER_INFO };
    let function_info2 = profiler_info.get_function_info_2(func_id, func).unwrap();
    trace!("{function_info2:#?}");

    let metadata = profiler_info
        .get_module_metadata(function_info2.module_id, CorOpenFlags::ofRead)
        .unwrap();

    let method_props = metadata.get_method_props(function_info2.token).unwrap();
    trace!("{method_props:#?}");
    
    let type_props = metadata
        .get_type_def_props(method_props.class_token)
        .unwrap();
    trace!("{type_props:#?}");

    //Check config
    let trace_def = {
        let mut trace_map = TRACE_MAP.lock().unwrap();
        if trace_map.contains_key(&func_id) {
            let trace = trace_map.get(&func_id).unwrap(); //should not panic since key is checked
            trace!("cached trace def for {func_id:#0x} is None? {}", trace.is_none());
            trace.clone()
        } else {
            let method_body = profiler_info.get_il_function_body(function_info2.module_id, function_info2.token).unwrap();

            let Ok(trace) = get_cfg_trace_def(&method_props, &type_props, &method_body) else {
                warn!("failed to get trace config for {:#0x}", func_id);
                return;
            };

            trace_map.insert(func_id, trace.clone());
            trace
        }
    };

    let Some(trace_cfg) =  trace_def else {
        trace!("no config for func_id {func_id:#0x}");
        return;
    };

    debug!("found trace config for {}", method_props.name);

    let args = unsafe { &*argument_info };
    debug!("arguments_info: nums: {}", args.numRanges);

    let signature = method_props.parse_signature().unwrap();

    debug!("{signature:#x?}");

    let args_vec = args.to_range_vec();

    info!("dumping params of {}::{}()", type_props.name, method_props.name);

    for param_cfg in &trace_cfg.params {
        match dump_func_param(param_cfg, &signature, &args_vec) {
            Ok(out_str) => info!("{{param: {}, {}}}", param_cfg.arg_num(), out_str),
            Err(err) => warn!("failed to dump param#{}; err: {err}", param_cfg.arg_num()),
        }
    }
}

fn dump_func_param(param_cfg: &TraceParams, sig: &MethodSignature, args: &Vec<COR_PRF_FUNCTION_ARGUMENT_RANGE>) -> Result<String, String> {
    let param_type = &sig.parameters[param_cfg.arg_num() as usize].type_sig; //NOTE: signature does not include `this` in params.
    let param_index = param_cfg.arg_num() as usize + if sig.has_this { 1 } else { 0 };
    
    let arg_range = args[param_index];
    debug!("argument range : {:#x?}", args[param_index]);
    
    let arg_value = CorFuncArg::from_arg_range(&arg_range, &param_type).value()?;
    let out_str = write_clr_value(arg_value, param_type, param_cfg.data_out())?;
    Ok(out_str)
}

fn write_clr_value(value: TypedValue, sig_type: &TypeSignature, out_cfg: &OutCfg) -> Result<String, String> {
    let mut out_str: String = "".into();

    match value {
        TypedValue::Val(value_type) => {
            debug!("writing to out_str value_type of {}", type_of(&value_type));
            out_str = format!("type: {:?}, value: {}", sig_type, value_type);
        },
        TypedValue::Ref(ref_type) => {
            if out_cfg.metadata() {
                out_str = format!("method_table: 0x{:08x}, size: {}, ", ref_type.method_table_ptr, ref_type.size);
            }

            match ref_type.value {
                RefValue::String(os_string) => {
                    match out_cfg.write_to() {
                        WriteTo::STDOUT => {
                            out_str = format!("{out_str}type: OsString, value: '{}'", os_string.display());
                        },
                        WriteTo::FILE => {
                            debug!("writing OsString to file");
                            let fname = dump_buffer(os_string.as_encoded_bytes(), "txt")
                                .map_err(|err| format!("failed to dump string to file; err: {err}"))?;
                            out_str = format!("{out_str}msg: dumped string to {fname}");
                        },
                    };
                },
                RefValue::Array (buff) | RefValue::Unknown (buff) => {
                    match out_cfg.write_to() {
                        WriteTo::STDOUT => {
                            out_str = format!("{out_str}type: {:?}, len: {}, value: {:02x?}", sig_type, buff.len(), buff); 
                        },
                        WriteTo::FILE => {
                            debug!("writing buffer to file");
                            let fname = dump_buffer(&buff, "bin")
                                .map_err(|err| format!("failed to dump buffer to file; err: {err}"))?;
                            out_str = format!("{out_str}msg: dumped buffer to {fname}");
                        },
                    };
                },
            }
        },
    }

    Ok(out_str)
}

fn type_of<T>(_: &T) -> String {
    type_name::<T>().to_string()
}

fn rand_str(len: usize) -> String {
    let mut rng = rand::rng();
    Alphanumeric.sample_string(&mut rng, len)
}

fn dump_buffer(buff: &[u8], ext: &str) -> std::io::Result<String> {
    let fname = format!("dump-{}.{ext}", rand_str(4));
    let path = Path::new(&fname);

    info!("writing buffer ({} bytes) to {}", buff.len(), path.display());

    let mut fout = OpenOptions::new()
        .truncate(true)
        .write(true)
        .create(true)
        .open(path)?;

    fout.write_all(buff)?;
    fout.flush()?;

    let path = path.canonicalize()?;
    Ok(path
        .display()
        .to_string()
        .trim_start_matches(r"\\?\")
        .to_string()
    )
}

#[allow(unused)]
unsafe extern "system" fn function_leave_2(
    func_id: FunctionID,
    client_data: UINT_PTR,
    func: COR_PRF_FRAME_INFO,
    retval_range: *const COR_PRF_FUNCTION_ARGUMENT_RANGE,
) {
    let trace_def = {
        let mut trace_map = TRACE_MAP.lock().unwrap();
        if trace_map.contains_key(&func_id) { //Only checking cache, since the cfg would be cached during FunctionEnter2 call.
            let trace = trace_map.get(&func_id).unwrap(); //should not panic since key is checked
            trace!("cached trace def for {func_id:#0x} is None? {}", trace.is_none());
            trace.clone()
        } else { None }
    };

    let Some(trace_cfg) =  trace_def else {
        trace!("no config for func_id {func_id:#0x}");
        return;
    };

    let Some(retval_out) = trace_cfg.retval() else {
        trace!("retval is false for func_id {func_id:#0x}");
        return;
    };

    let profiler_info = unsafe { &*PROFILER_INFO };
    let function_info2 = profiler_info.get_function_info_2(func_id, func).unwrap();
    trace!("{function_info2:#?}");

    let metadata = profiler_info
        .get_module_metadata(function_info2.module_id, CorOpenFlags::ofRead)
        .unwrap();

    let method_props = metadata.get_method_props(function_info2.token).unwrap();
    trace!("{method_props:#?}");

    let type_props = metadata
        .get_type_def_props(method_props.class_token)
        .unwrap();
    trace!("{type_props:#?}");

    debug!("reading return value of {}:{}()", type_props.name, method_props.name);

    let signature = method_props.parse_signature().unwrap();

    debug!("{signature:#x?}");

    let retval_range = unsafe { &*retval_range };

    let retval_type = signature.return_type;
    let return_val = CorFuncArg::from_arg_range(&retval_range, &retval_type).value();
    
    info!("return value of {}::{}()", type_props.name, method_props.name);
    match return_val {
        Ok(value) => match write_clr_value(value, &retval_type, retval_out) {
            Ok(out_str) => info!("{{{}}}", out_str),
            Err(err) => warn!("failed to write return value; err: {} ", err),
        }
        Err(err) => {
            warn!("failed to parse return value; err: {err}");
        },
    }
}


#[allow(unused)]
unsafe extern "system" fn function_tailcall_2(
    func_id: FunctionID,
    client_data: UINT_PTR,
    func: COR_PRF_FRAME_INFO,
) {
    //debug!("leaving fuction {func_id:0x}");
}

#[allow(unused)]
struct MethodAndClassProps {
    method_props: MethodProps,
    class_props: TypeDefProps,
}

#[allow(unused)]
impl MethodAndClassProps {
    fn qualified_name(self) -> String {
        format!("{}.{}", self.class_props.name, self.method_props.name)
    }
}

#[allow(unused)]
#[derive(Clone)]
struct Profiler {
    clsid: Uuid,
    profiler_info: Option<ProfilerInfo>,
    metadata_providers: HashMap<ModuleID, MetadataImport>,
    trace_defs: Vec<TraceDef>,
}

#[allow(unused)]
impl Profiler {
    fn profiler_info(&self) -> &ProfilerInfo {
        self.profiler_info.as_ref().unwrap()
    }

    fn with_clsid(clsid: Uuid) -> Self {
        Self {
            clsid: clsid,
            profiler_info: None,
            metadata_providers: HashMap::new(),
            trace_defs: vec![],
        }
    }

    fn get_method_and_class_props(
        &mut self,
        module_id: ModuleID,
        token: u32,
    ) -> Result<MethodAndClassProps, HRESULT> {
        // TODO: Find a idiomatic way to do this.
        // TODO: Make it thread safe??
        // let metadata = match self.metadata_providers.get(&module_id) {
        //     Some(value) => value,
        //     None => {
        //         let mt = self.profiler_info().get_module_metadata(module_id, CorOpenFlags::ofRead)?;
        //         self.metadata_providers.insert(module_id, mt);
        //         self.metadata_providers.get(&module_id).unwrap() //won't panic on newly added value
        //     }
        // };

        let metadata = self
            .profiler_info()
            .get_module_metadata(module_id, CorOpenFlags::ofRead)?;
        let method_props = metadata.get_method_props(token)?;
        let class_props = metadata.get_type_def_props(method_props.class_token)?;
        Ok(MethodAndClassProps {
            method_props,
            class_props,
        })
    }
}

impl ClrProfiler for Profiler {
    fn new() -> Profiler {
        Profiler {
            clsid: Uuid::parse_str(PROFILER_UUID).unwrap(), //Should not result in error.
            profiler_info: None,
            metadata_providers: HashMap::new(),
            trace_defs: vec![],
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

        unsafe {
            INIT.call_once(|| PROFILER_INFO = self.profiler_info());
        }

        if let Some(conf) = CONFIG.get() {
            if let Some(trace_defs) = conf.traces() {
                self.trace_defs = trace_defs.clone();
                info!("got {} trace configs", self.trace_defs.len());
            }
        } else {
            warn!("did not find any trace config");
        }

        // Set the event mask
        self.profiler_info().set_event_mask(
            COR_PRF_MONITOR::COR_PRF_MONITOR_ENTERLEAVE
                | COR_PRF_MONITOR::COR_PRF_ENABLE_FUNCTION_ARGS
                | COR_PRF_MONITOR::COR_PRF_ENABLE_FUNCTION_RETVAL,
        )?;

        match self.profiler_info().get_event_mask() {
            Ok(mask) => debug!("current event mask: {mask:?}"),
            Err(hresult) => warn!("failed to get current event mask, HRESULT = {hresult:#x}"),
        }

        match self.profiler_info().set_enter_leave_function_hooks_2(
            function_enter_2,
            function_leave_2,
            function_tailcall_2,
        ) {
            Ok(()) => debug!("function enter/leave hooks set"),
            Err(hresult) => warn!("failed to get current event mask, HRESULT = {hresult:#x}"),
        }

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
unsafe extern "system" fn DllGetClassObject(
    rclsid: REFCLSID,
    riid: REFIID,
    ppv: *mut LPVOID,
) -> HRESULT {
    //println!("[PROF_DEBUG] In DllGetClassObject");
    //init_logging();
    trace!("in DllGetClassObject");

    unsafe {
        debug!("*rclsid = {}, *riid = {}", *rclsid, *riid);
    }

    let guid = unsafe { *rclsid };
    let profiler = match Uuid::from_fields(guid.data1, guid.data2, guid.data3, &guid.data4) {
        Ok(uuid) => {
            info!("creating profiler with UUID: {{{}}}", uuid.to_hyphenated());
            Profiler::with_clsid(uuid)
        }
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
                    config.validate().unwrap();
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

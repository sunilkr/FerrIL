use std::{ffi::c_long};
use log::info;
use log_init::init_logging;

#[unsafe(no_mangle)]
unsafe extern "system" fn DllGetClassObject(_rclsid: *mut (), _riid: *mut (), _ppv: *mut ()) -> c_long {
    // File::create("prof.log")
    //     .and_then(|mut f| f.write_all(b"[PROF_DEBUG] In DllGetClassObject"))
    //     .unwrap();
    
    println!("[PROF_DEBUG] In DllGetClassObject\n");

    init_logging();
    
    info!("profiler load test successfull");

    return 0;
}

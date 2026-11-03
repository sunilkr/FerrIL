use std::{
    env::current_exe, fmt::Display, fs::File, 
    os::windows::process::CommandExt, 
    path::PathBuf, process::Command
};

use bitflags::bitflags;
use clap::{Parser, ValueEnum};
use exe::{ImageDataDirectory, ImageDirectoryEntry, PE, VecPE};
use uuid::Uuid;

bitflags! {
    pub struct CreationFlags: u32 {
        const DEBUG_PROCESS             = 0x00000001;
        const DEBUG_ONLY_THIS_PROCESS   = 0x00000002;
        const SUSPENDED                 = 0x00000004;
        const DETACHED_PROCESS          = 0x00000008;
        const NEW_CONSOLE               = 0x00000010;
        const NEW_PROCESS_GROUP         = 0x00000200;
        const SEPARATE_WOW_VDM          = 0x00000800;
        const SHARED_WOW_VDM            = 0x00001000;
        const INHERIT_PARENT_AFFINITY   = 0x00010000;
        const PROTECTED_PROCESS         = 0x00040000;
        const BREAKAWAY_FROM_JOB        = 0x01000000;
        const DEFAULT_ERROR_MODE        = 0x04000000;
        const NO_WINDOW                 = 0x08000000;
        const SECURE_PROCESS            = 0x00400000;
        const UNICODE_ENVIRONMENT       = 0x00000400;
        const PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000;
    }
}

impl Into<u32> for CreationFlags {
    fn into(self) -> u32 {
        self.bits()
    }
}

//const PROFILER_CLSID: &str = "DF63A541-5A33-4611-8829-F4E495985EE3";
const PROFILER_DLL: &str = "test_profilers.dll";

fn parse_clsid(s: &str) -> Result<Uuid, uuid::Error> {
    if s == "Random UUID" {
        Ok(Uuid::new_v4())
    } else {
        Uuid::parse_str(s)
    }
}


#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Create process in suspended mode
    /// 
    /// Useful for debugging. Only works with EXEs.
    #[arg(short, long)]
    suspended: bool,

    /// Check target for compatibility
    /// 
    /// Useful only for debugging. Do not use for while profiling.
    #[arg(short='C', long)]
    check: bool,

    /// Profiler (DLL) to use
    #[arg(short, long, default_value = PROFILER_DLL )]
    profiler: PathBuf,
    
    /// GUID of profiler interface
    /// 
    /// If provider DLL implements multiple profiler interfaces,
    /// implementation may choose to not check in only one exists.
    #[arg(short, long,
        default_value = "Random UUID",
        value_parser = parse_clsid
    )]
    clsid: Uuid,

    /// Log level to use
    /// 
    /// Sets RUST_LOG environment variable.
    #[arg(short, long, ignore_case=true, default_value_t=Default::default())]
    log_level: LogLevel,

    
    /// File path for log messages
    /// 
    /// Some applications do not create/share console handles,
    /// so log messages generated from profiler are log shown.
    //#[arg(long, default_value="C:\\result\\clr-profiler.log")]
    #[arg(long, default_value="clr-profiler.log")]
    log_file: String,

    /// Append to log file
    /// 
    /// 
    #[arg(short='A', long, default_value_t=false)]
    log_append: bool,

    /// Path to JSON config
    /// 
    /// Use custom profiler config 
    #[arg(long, default_value="config.json")]
    config: String,

    #[arg(short='D', long, default_value_t=false)]
    dev: bool,

    /// .NET program to profile
    target: PathBuf,

    /// Arguments to the target
    #[arg(last = true)]
    params: Vec<String>
}

#[repr(u8)]
#[derive(Debug, Default, Clone, Copy)]
#[derive(ValueEnum)]
enum LogLevel {
    Off   = 0,
    Error = 1,
    Warn  = 2,
    #[default]
    Info  = 3,
    Debug = 4,
    Trace = 5,
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn get_profiler_path(profiler_path: &PathBuf, target_type: &AsmType, in_dev: bool) -> PathBuf {
    let exe_path = current_exe().expect("failed to get current exe");
    let exe_dir = exe_path.parent().expect(&format!("failed to get parent of {}", exe_path.display()));
    let profiler_file = profiler_path.file_stem().unwrap().to_str().unwrap();
    let mut res_path = exe_dir.join(profiler_path);

    let bitness = match target_type {
        AsmType::X86Exe | AsmType::X86Dll => "-x86",
        AsmType::X64Exe | AsmType::X64Dll => "-x64",
        AsmType::NotDotNet => panic!("target is not a dotnet assembly"),
    };

    if in_dev{
        res_path.set_file_name(profiler_file);
    } else {
        res_path.set_file_name(format!("{}{}", profiler_file, bitness));
    }

    res_path.set_extension("dll");
    res_path.canonicalize().expect(&format!("failed to make absolute path from {}", res_path.display()))
}

fn launch_with_profiler(profiler_path: &PathBuf, command_line: &str, opts: &Cli) {
    let mut command = Command::new(command_line);

    if opts.suspended {
        if command_line.ends_with(".dll") {
            panic!("cannot launch dll in suspended mode");
        } else {
            println!("[*] launching in suspended mode");
            command.creation_flags(CreationFlags::SUSPENDED.into())    
        }
    } else if opts.params.len() > 0 {
        command.args(opts.params.iter())
    }else { 
        &mut command
    }
        .env("COR_PROF_CONFIG_FILE", opts.config.clone())
        .env("COR_PROF_LOG_LEVEL", opts.log_level.to_string())
        .env("COR_PROF_LOG_FILE", opts.log_file.clone())
        .env("COR_ENABLE_PROFILING", "1")
        .env("COR_PROFILER", format!("{{{}}}", opts.clsid.to_hyphenated().to_string()))
        .env("COR_PROFILER_PATH", 
            profiler_path.to_str()
                .unwrap_or_else(|| panic!("can't convert profiler path to &str")
            )
        );

    match command.spawn() {
        Ok(mut child) => {
            println!("[*] process created with pid: {}", child.id());
            
            if opts.suspended {
                println!("[*] attach debugger to pid {} and continue.", child.id());
            }

            match child.wait() {
                Ok(status) => println!("[*] process existed with status {status}"),
                Err(err) => eprintln!("[!] could not wait for child to complete due to {err}"),
            }
        },

        Err(err) => {
            println!("[x] failed to launch '{command_line}' with profiler; err: {err}");
        }
    }
}


bitflags! {
    #[derive(Debug)]
    pub struct ILFlags: u32 {
        const IL_ONLY   = 0x00000001;
        const REQ_32BIT = 0x00000002;
        const IL_LIBL   = 0x00000004;
        const STRONG_NAME_SIGNED =  0x00000008;
        const NATIVE_ENTRYPOINT  =  0x00000010;
        const TRACK_DEBUG_DATA   =  0x00010000;
        const PREF_32BIT         =  0x00020000;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ImageCOR20Header {
    ///Size of herader; should be 0x48.
    pub cb: u32, 
    pub major_version: u16,
    pub minor_version: u16,
    pub metadata_rva: ImageDataDirectory,
    pub il_flags: u32,
    ///EntryPoint Union {RVA, Token}
    pub ep_rva_or_token: u32,
    pub resources: ImageDataDirectory,
    pub strong_name_sig: ImageDataDirectory,
    ///Should be 0
    pub code_manager_table: ImageDataDirectory,
    pub vtable_fixups: ImageDataDirectory,
    ///ExportAddressTableJumps; Should be 0 in .NET image.
    pub eat_jumps: ImageDataDirectory,
    ///Precompiled image info (internal use only - set to zero)
    pub managed_native_header: ImageDataDirectory
}

impl ImageCOR20Header {
    pub fn is_32bit(&self) -> bool {
        self.flags().intersects(ILFlags::REQ_32BIT | ILFlags::PREF_32BIT)
    }

    pub fn is_lib(&self) -> bool {
        self.flags().contains(ILFlags::IL_LIBL)
    }

    pub fn flags(&self) -> ILFlags {
        ILFlags::from_bits_truncate(self.il_flags)
    }
}

// unsafe impl Castable for ImageCOR20Header {
    
// }

#[derive(Debug, Default, PartialEq)]
enum AsmType {
    X86Exe,
    X64Exe,
    X86Dll,
    X64Dll,
    #[default]
    NotDotNet,
}

fn get_target_type(target_path: &PathBuf) -> Result<AsmType, exe::Error> {
    let image = VecPE::from_disk_file(target_path)?;
    let dotnet_dir = image.get_data_directory(exe::ImageDirectoryEntry::COMDescriptor)?;
    
    if dotnet_dir.size == 0 || dotnet_dir.virtual_address == exe::RVA(0) {
        return Ok(AsmType::NotDotNet);
    }

    //let cor20 = dotnet_dir.cast::<ImageCOR20Header, VecPE>(&image)?;
    let cor20 = image.cast_directory::<ImageCOR20Header>(ImageDirectoryEntry::COMDescriptor)?;
    //eprintln!("cor20: {cor20:#04x?}");
    //eprintln!("cor_flags: {:?}", cor20.flags());

    let res = match (cor20.is_32bit(), cor20.is_lib()) {
        (true, true) => AsmType::X86Dll,
        (true, false) => AsmType::X86Exe,
        (false, true) => AsmType::X64Dll,
        (false, false) => AsmType::X64Exe,
    };

    println!("[*] target is: {res:?}");
    Ok(res)
}

fn get_command_line(target: &PathBuf, target_type: &AsmType) -> String {
    match target_type {
        AsmType::X86Exe | AsmType::X64Exe => format!("{}", target.display()).to_string(),
        AsmType::X64Dll | AsmType::X86Dll => format!("dotnet {}", target.display()).to_string(),
        AsmType::NotDotNet => panic!("target is not a dotnet assembly"),
    }
    
    // if target.ex {
    //     format!("dotnet {}", target_path).to_string()
    // } else {
    //     target_path.to_string()
    // }
}

fn main() {
    let args = Cli::parse();
    //eprintln!("{args:#?}");
    //eprintln!("RUST_LOG={:?}", args.log_level as u8);

    let target_path = args.target.canonicalize().unwrap();
    if !target_path.is_file() {
        panic!("[x] {} is not a file", target_path.display());
    }

    let target_type = get_target_type(&target_path).unwrap();

    if args.check || target_type == AsmType::NotDotNet {
        print!("target is {target_type:?}");
        return;
    }

    println!("[*] profiler: {}", &args.profiler.display());
    let profiler_path = get_profiler_path(&args.profiler, &target_type, args.dev);
    let cmdline = get_command_line(&target_path, &target_type);

    if !args.log_append {
        println!("[*] truncating log file {}", &args.log_file);
        let _ = File::create(&args.log_file);
    }

    println!("[*] launching '{}' with profiler {}", cmdline, profiler_path.display());
    launch_with_profiler(&profiler_path, &cmdline, &args);
}

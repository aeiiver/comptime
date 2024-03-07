use std::{ffi::CString, io::Write};

use anyhow::{bail, Result};
use clap::Parser;
use libc::{c_char, c_int, c_long, c_short, c_uchar, c_uint, c_ulong, c_ushort, c_void};
use once_cell::sync::OnceCell;

static COMPTIME_PREFIX: OnceCell<String> = OnceCell::new();

/// Comptime function preprocessor for C
#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Set prefix
    #[arg(short, long, default_value = "comptime_")]
    prefix: String,

    /// Expand without linking
    #[arg(short, long)]
    expand: bool,

    /// Link library
    #[arg(short, long)]
    libs: Vec<String>,

    /// Files to preprocess
    #[arg(value_name = "FILE", required = true)]
    fnames: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let prefix = cli.prefix;
    let expand = cli.expand;
    let libs = cli.libs;
    let fnames = cli.fnames;

    let cname = std::env::var("CC").unwrap_or("cc".to_owned());
    COMPTIME_PREFIX.set(prefix).unwrap();

    let mut files = Vec::new();
    for f in &fnames {
        files.push(File {
            name: f.to_owned(),
            data: std::fs::read(f)?,
        });
    }

    let defs = {
        let mut v = Vec::new();
        let mut p = new_ts_c_parser();
        for f in &files {
            let t = match p.parse(&f.data, None) {
                Some(v) => v,
                None => bail!("Failed to parse '{}'", f.name),
            };
            collect_defs(t.root_node(), &f.data, &mut v)?;
        }
        v
    };

    let sofile = {
        let v = tempfile::NamedTempFile::new()?;
        let mut cc = std::process::Command::new(&cname);
        cc.arg("-shared")
            .arg("-fpic")
            .arg("-o")
            .arg(v.path())
            .args(&fnames)
            .args(libs.iter().map(|l| "-l".to_owned() + l))
            .spawn()?
            .wait()?;

        eprint!("{} ", cname);
        for a in cc.get_args() {
            match a.to_str() {
                Some(v) => eprint!("{} ", v),
                None => {
                    eprintln!("warn: couldn't display compiler args");
                    break;
                }
            };
        }
        eprintln!();

        v
    };

    unsafe {
        let dlhandle = {
            let f = sofile.path().to_str().unwrap();
            let f = CString::new(f).unwrap();
            let v = libc::dlopen(f.as_ptr(), libc::RTLD_LAZY);
            if v.is_null() {
                bail!(
                    "dlopen: {}",
                    CString::from_raw(libc::dlerror()).to_str().unwrap()
                );
            }
            v
        };

        for f in &mut files {
            preprocess(f, &defs, dlhandle)?;
        }

        if libc::dlclose(dlhandle) != 0 {
            bail!(
                "dlsym: {}",
                CString::from_raw(libc::dlerror()).to_str().unwrap()
            );
        }
    }

    if expand {
        for f in files {
            let dst = f.name.to_owned() + ".comptime";
            let mut dstf = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&dst)?;
            dstf.write_all(&f.data)?;
            eprintln!("expand: {} -> {}", f.name, dst);
        }
    } else {
        let mut tmpfiles = Vec::new();
        for f in files {
            let mut v = tempfile::NamedTempFile::new()?;
            v.write_all(&f.data)?;
            tmpfiles.push(v);
        }

        let tmpfiles = tmpfiles.iter().map(|f| f.path().to_str().unwrap());
        let mut cc = std::process::Command::new(&cname);
        cc.arg("-xc")
            .arg("-I.")
            .args(tmpfiles)
            .args(libs.iter().map(|l| "-l".to_owned() + l))
            .spawn()?
            .wait()?;

        eprint!("{} ", cname);
        for a in cc.get_args() {
            match a.to_str() {
                Some(v) => eprint!("{} ", v),
                None => {
                    eprintln!("warn: couldn't display compiler args");
                    break;
                }
            };
        }
        eprintln!();
    };

    Ok(())
}

fn collect_defs(root: tree_sitter::Node, src: &[u8], acc: &mut Vec<FnDef>) -> Result<()> {
    if root.kind() != "function_definition" {
        for c in root.named_children(&mut root.walk()) {
            collect_defs(c, src, acc)?;
        }
        return Ok(());
    }

    let name = {
        let mut d = root.child_by_field_name("declarator").unwrap();
        while d.kind() != "identifier" {
            d = d.child_by_field_name("declarator").unwrap();
        }
        let v = d.utf8_text(src)?.to_owned();
        if !v.starts_with(COMPTIME_PREFIX.get().unwrap()) {
            // NOTE: We don't need to keep recursing because we won't find
            // more definitions within a definition.
            return Ok(());
        }
        v
    };

    #[rustfmt::skip]
    let rtype = {
        let d = root.child_by_field_name("declarator").unwrap();
        let t = root.child_by_field_name("type").unwrap();
        let t = t.utf8_text(src)?;

        if d.kind() == "pointer_declarator"   { CType::Pointer }
        else if t == "void"                   { CType::Void    }
        else if t.ends_with("unsigned long")  { CType::ULong   }
        else if t.ends_with("unsigned int")   { CType::UInt    }
        else if t.ends_with("unsigned short") { CType::UShort  }
        else if t.ends_with("unsigned char")  { CType::UChar   }
        else if t.ends_with("long")           { CType::Long    }
        else if t.ends_with("int")            { CType::Int     }
        else if t.ends_with("short")          { CType::Short   }
        else if t.ends_with("char")           { CType::Char    }
        else                                  { bail!("unsupported return type '{t}' ({name})") }
    };

    let atypes = {
        let mut d = root.child_by_field_name("declarator").unwrap();
        while d.child_by_field_name("parameters").is_none() {
            d = d.child_by_field_name("declarator").unwrap();
        }
        let parms = d.child_by_field_name("parameters").unwrap();

        let mut v = Vec::new();
        for c in parms.named_children(&mut parms.walk()) {
            // HACK: If there is no declarator, just use any other node.
            // We fallthough the first condition anyway.
            let d = c.child_by_field_name("declarator").unwrap_or(c);
            let t = c.child_by_field_name("type").unwrap();
            let t = t.utf8_text(src)?;

            #[rustfmt::skip]
            v.push(
                if d.kind() == "pointer_declarator"   { CType::Pointer }
                else if t == "void"                   { CType::Void    }
                else if t.ends_with("unsigned long")  { CType::ULong   }
                else if t.ends_with("unsigned int")   { CType::UInt    }
                else if t.ends_with("unsigned short") { CType::UShort  }
                else if t.ends_with("unsigned char")  { CType::UChar   }
                else if t.ends_with("long")           { CType::Long    }
                else if t.ends_with("int")            { CType::Int     }
                else if t.ends_with("short")          { CType::Short   }
                else if t.ends_with("char")           { CType::Char    }
                else                                      { bail!("unsupported parameter type '{t}' {name}") }
            );
        }
        v
    };

    acc.push(FnDef {
        name,
        rtype,
        atypes,
    });

    Ok(())
}

unsafe fn preprocess(file: &mut File, defs: &[FnDef], dlhandle: *mut c_void) -> Result<()> {
    let mut p = new_ts_c_parser();
    loop {
        let t = match p.parse(&file.data, None) {
            Some(v) => v,
            None => bail!("Failed to parse '{}'", file.name),
        };

        let mut call = match next_call(t.root_node(), &file.data)? {
            Some(v) => v,
            None => break,
        };
        let def = match defs.iter().find(|def| def.name == call.name) {
            Some(v) => v,
            None => {
                eprintln!(
                    "warn: ignored call to implicitly-declared function '{}'",
                    call.name
                );
                continue;
            }
        };

        let ptr = {
            let fnname = CString::new(def.name.clone()).unwrap();
            let fnptr = libc::dlsym(dlhandle, fnname.as_ptr());
            if fnptr.is_null() {
                eprintln!(
                    "warn: dlsym: {}",
                    CString::from_raw(libc::dlerror()).to_str().unwrap()
                );
                continue;
            }
            libffi::low::CodePtr::from_ptr(std::mem::transmute(fnptr))
        };

        let mut atypes = Vec::new();
        for a in &def.atypes {
            match a {
                CType::Void => (),
                t => atypes.push(t.as_ffi_type() as *mut _),
            }
        }
        let mut args = Vec::new();
        for a in &mut call.args[..atypes.len()] {
            #[rustfmt::skip]
            match a {
                CExpr::NumberLit(ref mut v) => { args.push(v as *mut _ as *mut c_void); },
                CExpr::StringLit(ref mut v) => { args.push(v as *mut _ as *mut c_void); },
                CExpr::Ident(v)             => { todo!("{v}"); },
            };
        }

        let mut cif = libffi::low::ffi_cif::default();
        libffi::low::prep_cif(
            &mut cif,
            libffi::low::ffi_abi_FFI_DEFAULT_ABI,
            atypes.len(),
            &mut *def.rtype.as_ffi_type(),
            atypes.as_mut_ptr(),
        )
        .expect("prep_cif() arguments are malformed");

        #[rustfmt::skip]
        let ret = match def.rtype {
            CType::Void    => {             libffi::low::call::<()>      (&mut cif, ptr, args.as_mut_ptr()); "".to_owned() },
            CType::Pointer => format!("{}", libffi::low::call::<usize>   (&mut cif, ptr, args.as_mut_ptr())),
            CType::Long    => format!("{}", libffi::low::call::<c_long>  (&mut cif, ptr, args.as_mut_ptr())),
            CType::Int     => format!("{}", libffi::low::call::<c_int>   (&mut cif, ptr, args.as_mut_ptr())),
            CType::Short   => format!("{}", libffi::low::call::<c_short> (&mut cif, ptr, args.as_mut_ptr())),
            CType::Char    => format!("{}", libffi::low::call::<c_char>  (&mut cif, ptr, args.as_mut_ptr())),
            CType::ULong   => format!("{}", libffi::low::call::<c_ulong> (&mut cif, ptr, args.as_mut_ptr())),
            CType::UInt    => format!("{}", libffi::low::call::<c_uint>  (&mut cif, ptr, args.as_mut_ptr())),
            CType::UShort  => format!("{}", libffi::low::call::<c_ushort>(&mut cif, ptr, args.as_mut_ptr())),
            CType::UChar   => format!("{}", libffi::low::call::<c_uchar> (&mut cif, ptr, args.as_mut_ptr())),
        };

        let beg = call.node.start_byte();
        let end = call.node.end_byte();
        _ = file.data.splice(beg..end, ret.bytes()).collect::<Vec<_>>();

        p.reset();
    }
    Ok(())
}

fn next_call<'a>(root: tree_sitter::Node<'a>, src: &'a [u8]) -> Result<Option<FnCall<'a>>> {
    let mut calls = Vec::new();
    collect_calls(root, src, 0, &mut calls)?;
    calls.sort_by(|a, b| b.lvl.cmp(&a.lvl));
    Ok(calls.first().cloned())
}

fn collect_calls<'a>(
    root: tree_sitter::Node<'a>,
    src: &'a [u8],
    lvl: u32,
    acc: &mut Vec<FnCall<'a>>,
) -> Result<()> {
    if root.kind() != "call_expression" {
        for c in root.named_children(&mut root.walk()) {
            collect_calls(c, src, lvl, acc)?
        }
        return Ok(());
    }

    let name = root.child_by_field_name("function").unwrap();
    if name.kind() != "identifier" {
        eprintln!(
            "warn: ignored unsupported call expression '{}'",
            root.utf8_text(src)?
        );

        for c in root.named_children(&mut root.walk()) {
            collect_calls(c, src, lvl, acc)?
        }
        return Ok(());
    }

    let name = name.utf8_text(src)?.to_owned();
    if !name.starts_with(COMPTIME_PREFIX.get().unwrap()) {
        for c in root.named_children(&mut root.walk()) {
            collect_calls(c, src, lvl, acc)?
        }
        return Ok(());
    }

    let mut args = Vec::new();
    let arglist = root.child_by_field_name("arguments").unwrap();
    for c in arglist.named_children(&mut arglist.walk()) {
        collect_calls_inner(c, src, lvl, acc, &mut args)?;
    }

    acc.push(FnCall {
        name,
        args,
        node: root,
        lvl,
    });

    Ok(())
}

fn collect_calls_inner<'a>(
    c: tree_sitter::Node<'a>,
    src: &'a [u8],
    lvl: u32,
    acc: &mut Vec<FnCall<'a>>,
    args: &mut Vec<CExpr>,
) -> Result<()> {
    // dbg!(lvl, c.utf8_text(src)?);
    match c.kind() {
        "number_literal" => {
            let str = c.utf8_text(src)?;
            let num = str.parse::<i64>().expect("tree-sitter missparsed this?");
            args.push(CExpr::NumberLit(num));
        }
        "string_literal" => {
            let str = c.utf8_text(src)?;
            let str = CString::new(&str[1..str.len() - 1]).unwrap();
            args.push(CExpr::StringLit(str));
        }
        "call_expression" => {
            collect_calls(c, src, lvl + 1, acc)?;
        }
        "binary_expression" => {
            let mut postpone = false;
            let lc = c.child_by_field_name("left").unwrap();
            let rl = c.child_by_field_name("right").unwrap();
            if lc.kind() == "call_expression" {
                collect_calls_inner(lc, src, lvl, acc, args)?;
                postpone = true;
            }
            if rl.kind() == "call_expression" {
                collect_calls_inner(rl, src, lvl, acc, args)?;
                postpone = true;
            }
            if !postpone {
                match (lc.kind(), rl.kind()) {
                    ("number_literal", "number_literal") => {
                        let lstr = lc.utf8_text(src)?;
                        let rstr = rl.utf8_text(src)?;
                        let lnum = lstr.parse::<i64>().expect("tree-sitter missparsed this?");
                        let rnum = rstr.parse::<i64>().expect("tree-sitter missparsed this?");
                        args.push(CExpr::NumberLit(lnum + rnum));
                    }
                    ("binary_expression", _) => {
                        collect_calls_inner(lc, src, lvl, acc, args)?;
                    }
                    (_, "binary_expression") => {
                        collect_calls_inner(rl, src, lvl, acc, args)?;
                    }
                    (a, b) => todo!("unhandled binary_expression variant: ({}, {})", a, b),
                }
            }
        }
        "identifier" => {
            let str = c.utf8_text(src)?.to_owned();
            args.push(CExpr::Ident(str));
        }
        k => todo!(
            "unhandled argument node kind: {} ({})",
            k,
            c.utf8_text(src)?
        ),
    };
    Ok(())
}

fn new_ts_c_parser() -> tree_sitter::Parser {
    let mut p = tree_sitter::Parser::new();
    if let Err(e) = p.set_language(tree_sitter_c::language()) {
        panic!("{e}");
    }
    p
}

#[derive(Debug)]
struct File {
    name: String,
    data: Vec<u8>,
}

#[derive(Debug)]
struct FnDef {
    name: String,
    rtype: CType,
    atypes: Vec<CType>,
}

#[derive(Debug, Clone)]
struct FnCall<'a> {
    name: String,
    args: Vec<CExpr>,
    node: tree_sitter::Node<'a>,
    lvl: u32,
}

#[derive(Debug)]
enum CType {
    Void,
    Pointer,
    Long,
    Int,
    Short,
    Char,
    ULong,
    UInt,
    UShort,
    UChar,
}

impl CType {
    #[rustfmt::skip]
    unsafe fn as_ffi_type(&self) -> *mut libffi::low::ffi_type {
        match self {
            CType::Void    => &mut libffi::low::types::void,
            CType::Pointer => &mut libffi::low::types::pointer,
            CType::Long    => &mut libffi::low::types::sint64,
            CType::Int     => &mut libffi::low::types::sint32,
            CType::Short   => &mut libffi::low::types::sint16,
            CType::Char    => &mut libffi::low::types::sint8,
            CType::ULong   => &mut libffi::low::types::uint64,
            CType::UInt    => &mut libffi::low::types::uint32,
            CType::UShort  => &mut libffi::low::types::uint16,
            CType::UChar   => &mut libffi::low::types::uint8,
        }
    }
}

#[derive(Debug, Clone)]
enum CExpr {
    NumberLit(i64),
    StringLit(CString),
    Ident(String),
}

#[cfg(test)]
mod test {
    use std::io::BufRead;

    #[test]
    fn expanded_ok() {
        std::env::set_current_dir("test").expect("test is ill");
        std::process::Command::new("sh")
            .arg("-c")
            .arg("../target/debug/comptime -e *.c -lcurl")
            .status()
            .expect("test is ill")
            .success()
            .then_some(0)
            .expect("test is ill");
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("find -name '*.comptime'")
            .output()
            .expect("test is ill");
        let fnames = out.stdout.lines().map(|l| l.expect("test is ill"));

        for frecv in fnames {
            let fexpc = frecv.to_owned() + "_expected";
            let recv = std::fs::read_to_string(&frecv).expect("test is ill");
            let expc = std::fs::read_to_string(&fexpc).expect("test is ill");

            let c = prettydiff::diff_lines(&recv, &expc)
                .names(&frecv, &fexpc)
                .set_diff_only(true)
                .set_show_lines(true);
            let d = c.diff();

            // NOTE: The actual test
            if d.len() > 1 {
                c.prettytable();
                panic!("received and expected versions don't match");
            }
        }
    }
}

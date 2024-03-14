use std::borrow::Cow;
#[cfg(test)]
use std::env;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result as FmtResult;
use std::mem;
use std::mem::swap;
use std::ops::Deref as _;
#[cfg(test)]
use std::path::Path;
use std::rc::Rc;

use gimli::Dwarf;

use crate::elf::ElfParser;
use crate::error::IntoCowStr;
use crate::inspect::FindAddrOpts;
use crate::inspect::SymInfo;
use crate::symbolize::AddrCodeInfo;
use crate::symbolize::CodeInfo;
use crate::symbolize::IntSym;
use crate::symbolize::SrcLang;
use crate::Addr;
use crate::Error;
use crate::ErrorExt;
use crate::Result;
use crate::SymType;

use super::location::Location;
use super::reader;
use super::units::Units;


impl ErrorExt for gimli::Error {
    type Output = Error;

    fn context<C>(self, context: C) -> Self::Output
    where
        C: IntoCowStr,
    {
        Error::from(self).context(context)
    }

    fn with_context<C, F>(self, f: F) -> Self::Output
    where
        C: IntoCowStr,
        F: FnOnce() -> C,
    {
        Error::from(self).with_context(f)
    }
}


impl From<Option<gimli::DwLang>> for SrcLang {
    fn from(other: Option<gimli::DwLang>) -> Self {
        match other {
            Some(gimli::DW_LANG_Rust) => SrcLang::Rust,
            Some(
                gimli::DW_LANG_C_plus_plus
                | gimli::DW_LANG_C_plus_plus_03
                | gimli::DW_LANG_C_plus_plus_11
                | gimli::DW_LANG_C_plus_plus_14,
            ) => SrcLang::Cpp,
            _ => SrcLang::Unknown,
        }
    }
}


/// DwarfResolver provides abilities to query DWARF information of binaries.
pub(crate) struct DwarfResolver {
    /// The lazily parsed compilation units of the DWARF file.
    // SAFETY: We must not hand out references with a 'static lifetime to
    //         this member. Rather, they should never outlive `self`.
    //         Furthermore, this member has to be listed before `parser`
    //         to make sure we never end up with a dangling reference.
    units: Units<'static>,
    parser: Rc<ElfParser>,
    line_number_info: bool,
}

impl DwarfResolver {
    /// Retrieve the resolver's underlying `ElfParser`.
    pub fn parser(&self) -> &Rc<ElfParser> {
        &self.parser
    }

    pub fn from_parser(parser: Rc<ElfParser>, line_number_info: bool) -> Result<Self, Error> {
        // SAFETY: We own the `ElfParser` and make sure that it stays
        //         around while the `Units` object uses it. As such, it
        //         is fine to conjure a 'static lifetime here.
        let static_parser =
            unsafe { mem::transmute::<&ElfParser, &'static ElfParser>(parser.deref()) };
        let mut load_section = |section| reader::load_section(static_parser, section);
        let dwarf = Dwarf::load(&mut load_section)?;
        let units = Units::parse(dwarf)?;
        let slf = Self {
            units,
            parser,
            line_number_info,
        };
        Ok(slf)
    }

    /// Open a binary to load and parse .debug_line for later uses.
    ///
    /// `filename` is the name of an ELF binary/or shared object that
    /// has .debug_line section.
    #[cfg(test)]
    pub fn open(filename: &Path, debug_line_info: bool) -> Result<Self> {
        let parser = ElfParser::open(filename)?;
        Self::from_parser(Rc::new(parser), debug_line_info)
    }

    /// Find source code information of an address.
    ///
    /// `addr` is a normalized address.
    pub fn find_code_info(
        &self,
        addr: Addr,
        inlined_fns: bool,
    ) -> Result<Option<AddrCodeInfo<'_>>> {
        // TODO: This conditional logic is weird and potentially
        //       unnecessary. Consider removing it or moving it higher
        //       in the call chain.
        let code_info = if self.line_number_info {
            if let Some(direct_location) = self.units.find_location(addr)? {
                let Location {
                    dir,
                    file,
                    line,
                    column,
                } = direct_location;

                let mut direct_code_info = CodeInfo {
                    dir: Some(Cow::Borrowed(dir)),
                    file: Cow::Borrowed(file),
                    line,
                    column: column.map(|col| col.try_into().unwrap_or(u16::MAX)),
                    _non_exhaustive: (),
                };

                let inlined = if inlined_fns {
                    if let Some(inline_stack) = self.units.find_inlined_functions(addr)? {
                        let mut inlined = Vec::with_capacity(inline_stack.len());
                        for result in inline_stack {
                            let (name, location) = result?;
                            let mut code_info = location.map(|location| {
                                let Location {
                                    dir,
                                    file,
                                    line,
                                    column,
                                } = location;

                                CodeInfo {
                                    dir: Some(Cow::Borrowed(dir)),
                                    file: Cow::Borrowed(file),
                                    line,
                                    column: column.map(|col| col.try_into().unwrap_or(u16::MAX)),
                                    _non_exhaustive: (),
                                }
                            });

                            // For each frame we need to move the code information
                            // up by one layer.
                            if let Some((_last_name, ref mut last_code_info)) = inlined.last_mut() {
                                let () = swap(&mut code_info, last_code_info);
                            } else if let Some(code_info) = &mut code_info {
                                let () = swap(code_info, &mut direct_code_info);
                            }

                            let () = inlined.push((name, code_info));
                        }
                        inlined
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };

                let code_info = AddrCodeInfo {
                    direct: (None, direct_code_info),
                    inlined,
                };

                Some(code_info)
            } else {
                None
            }
        } else {
            None
        };

        Ok(code_info)
    }

    /// Lookup the symbol at an address.
    pub(crate) fn find_sym(&self, addr: Addr) -> Result<Option<IntSym<'_>>, Error> {
        let result = self.units.find_function(addr)?;
        if let Some((function, language)) = result {
            let name = function
                .name
                .map(|name| name.to_string())
                .transpose()?
                .unwrap_or("");
            let addr = function.range.map(|range| range.begin).unwrap_or(0);
            let size = function
                .range
                .map(|range| usize::try_from(range.end - range.begin).unwrap_or(usize::MAX));
            let sym = IntSym {
                name,
                addr,
                size,
                lang: language.into(),
            };
            Ok(Some(sym))
        } else {
            Ok(None)
        }
    }

    /// Find the address of a symbol from DWARF.
    ///
    /// # Arguments
    ///
    /// * `name` - is the symbol name to find.
    /// * `opts` - is the context giving additional parameters.
    pub(crate) fn find_addr<'slf>(
        &'slf self,
        name: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymInfo<'slf>>> {
        if let SymType::Variable = opts.sym_type {
            return Err(Error::with_unsupported("not implemented"))
        }

        let syms = self
            .units
            .find_name(name)
            .map(|result| {
                match result {
                    Ok(function) => {
                        // SANITY: We found the function by name, so it must have the
                        //         name attribute set.
                        let name = function.name.unwrap().to_string().unwrap();
                        let addr = function
                            .range
                            .as_ref()
                            .map(|range| range.begin as Addr)
                            .unwrap_or(0);
                        let size = function
                            .range
                            .as_ref()
                            .and_then(|range| range.end.checked_sub(range.begin))
                            .map(|size| usize::try_from(size).unwrap_or(usize::MAX))
                            .unwrap_or(0);
                        let info = SymInfo {
                            name: Cow::Borrowed(name),
                            addr,
                            size,
                            sym_type: SymType::Function,
                            file_offset: opts
                                .offset_in_file
                                .then(|| self.parser.find_file_offset(addr))
                                .transpose()?
                                .flatten(),
                            obj_file_name: None,
                        };
                        Ok(info)
                    }
                    Err(err) => Err(Error::from(err)),
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(syms)
    }
}

impl Debug for DwarfResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(stringify!(DwarfResolver))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::env::current_exe;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use test_log::test;

    use crate::ErrorKind;


    /// Exercise the `Debug` representation of various types.
    #[test]
    fn debug_repr() {
        let bin_name = current_exe().unwrap();
        let resolver = DwarfResolver::open(&bin_name, true).unwrap();
        assert_ne!(format!("{resolver:?}"), "");
    }

    /// Check that we can convert a `gimli::Error` into our own error type.
    #[test]
    fn error_conversion() {
        let inner = gimli::Error::Io;
        let err = Result::<(), _>::Err(inner)
            .context("failed to read")
            .unwrap_err();
        assert_eq!(format!("{err:#}"), format!("failed to read: {inner}"));

        let err = Result::<(), _>::Err(inner)
            .with_context(|| "failed to read")
            .unwrap_err();
        assert_eq!(format!("{err:#}"), format!("failed to read: {inner}"));
    }

    /// Check that we can find the source code location of an address.
    #[test]
    fn source_location_finding() {
        let bin_name = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses.bin");
        let resolver = DwarfResolver::open(bin_name.as_ref(), true).unwrap();

        let info = resolver.find_code_info(0x2000100, true).unwrap().unwrap();
        assert_ne!(info.direct.1.dir, Some(Cow::Owned(PathBuf::new())));
        assert_eq!(info.direct.1.file, OsStr::new("test-stable-addresses.c"));
        assert_eq!(info.direct.1.line, Some(10));
        assert!(info.direct.1.column.is_some());
    }

    /// Check that we can look up a symbol in DWARF debug information.
    #[test]
    fn lookup_symbol() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-dwarf-only.bin");
        let opts = FindAddrOpts {
            offset_in_file: false,
            sym_type: SymType::Function,
        };
        let resolver = DwarfResolver::open(test_dwarf.as_ref(), true).unwrap();

        let symbols = resolver.find_addr("factorial", &opts).unwrap();
        assert_eq!(symbols.len(), 1);

        // `factorial` resides at address 0x2000100.
        let symbol = symbols.first().unwrap();
        assert_eq!(symbol.addr, 0x2000100);
    }

    /// Check that we fail to look up variables.
    #[test]
    fn lookup_symbol_wrong_type() {
        let test_dwarf = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .join("data")
            .join("test-stable-addresses-dwarf-only.bin");
        let opts = FindAddrOpts {
            offset_in_file: false,
            sym_type: SymType::Variable,
        };
        let resolver = DwarfResolver::open(test_dwarf.as_ref(), true).unwrap();

        let err = resolver.find_addr("factorial", &opts).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }
}

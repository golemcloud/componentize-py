#![deny(warnings)]

use std::{
    collections::{HashMap, HashSet},
    fs::{self},
    io::Cursor,
    ops::Deref,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use indexmap::IndexMap;
use tar::Archive;
use tempfile::TempDir;
use zstd::Decoder;

use crate::{ComponentizePyConfig, ConfigContext, Library, RawComponentizePyConfig};

static NATIVE_EXTENSION_SUFFIXES: &[&str] = &[".cpython-314-wasm32-wasi.so", ".abi3.so"];

/// Check if a file starts with the WASM magic bytes (`\0asm`).
fn is_wasm_file(path: &Path) -> bool {
    fs::read(path)
        .map(|bytes| bytes.starts_with(b"\0asm"))
        .unwrap_or(false)
}

type ConfigsMatchedWorlds<'a> =
    IndexMap<String, (ConfigContext<ComponentizePyConfig>, &'a [&'a str])>;

pub fn embedded_python_standard_library() -> Result<TempDir> {
    // Untar the embedded copy of the Python standard library into a temporary
    // directory
    let stdlib = tempfile::tempdir()?;

    Archive::new(Decoder::new(Cursor::new(
        embedded_python_standard_library_archive(),
    ))?)
    .unpack(stdlib.path())
    .unwrap();

    Ok(stdlib)
}

pub fn embedded_helper_utils() -> Result<TempDir> {
    // Untar the embedded copy of helper utilities into a temporary directory
    let bundled = tempfile::tempdir()?;

    Archive::new(Decoder::new(Cursor::new(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/bundled.tar.zst"
    ))))?)
    .unpack(bundled.path())
    .unwrap();

    Ok(bundled)
}

pub fn embedded_python_standard_library_archive() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/python-lib.tar.zst"))
}

pub fn embedded_adapter() -> Result<Vec<u8>> {
    Ok(zstd::decode_all(Cursor::new(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/wasi_snapshot_preview1.reactor.wasm.zst"
    ))))?)
}

/// Support libraries from the WASI SDK that extensions may depend on.  Each is
/// linked only when a linked library names it in its `dylink.0` needed list.
pub fn toolchain_support_libraries() -> Result<Vec<(String, Vec<u8>)>> {
    Ok(vec![(
        "libsetjmp.so".to_owned(),
        zstd::decode_all(Cursor::new(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/libsetjmp.so.zst"
        ))))?,
    )])
}

/// Returns the names in a module's `dylink.0` needed list.
fn needed_libraries(module: &[u8]) -> Result<Vec<String>> {
    let mut needed = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(module) {
        if let wasmparser::Payload::CustomSection(section) = payload?
            && let wasmparser::KnownCustom::Dylink0(reader) = section.as_known()
        {
            for subsection in reader {
                if let wasmparser::Dylink0Subsection::Needed(names) = subsection? {
                    needed.extend(names.into_iter().map(String::from));
                }
            }
        }
    }
    Ok(needed)
}

/// Adds every support library that a linked library needs, directly or
/// through another support library.
///
/// A support library is a shared library that is not a Python extension, such
/// as `libjpeg.so` shipped next to the extension using it.  It is linked under
/// its file name, which is the name its dependents use, and is not visible to
/// `dlopen`.  Support libraries that nothing needs are not linked, so they do
/// not change the component.  A needed name that remains unresolved is reported
/// by the linker as a missing library.
pub fn add_support_libraries(
    libraries: &mut Vec<Library>,
    support: &[PathBuf],
    toolchain: &[(String, Vec<u8>)],
) -> Result<()> {
    let mut candidates: IndexMap<String, Vec<(String, Vec<u8>)>> = IndexMap::new();
    for path in support {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("non-UTF-8 path")?
            .to_owned();
        let module = fs::read(path).with_context(|| path.display().to_string())?;
        candidates
            .entry(name)
            .or_default()
            .push((path.display().to_string(), module));
    }
    let mut index = 0;
    while index < libraries.len() {
        for needed in needed_libraries(&libraries[index].module)? {
            if libraries.iter().any(|library| library.name == needed) {
                continue;
            }
            let module = if let Some(found) = candidates.get(&needed) {
                let (first_path, first) = &found[0];
                if let Some((other_path, _)) = found.iter().find(|(_, module)| module != first) {
                    bail!(
                        "support library `{needed}` needed by `{}` has different contents at \
                         {first_path} and {other_path}",
                        libraries[index].name
                    );
                }
                first.clone()
            } else if let Some((_, module)) = toolchain.iter().find(|(name, _)| *name == needed) {
                module.clone()
            } else {
                continue;
            };
            libraries.push(Library {
                name: needed,
                module,
                dl_openable: false,
            });
        }
        index += 1;
    }

    Ok(())
}

pub fn bundle_libraries(
    library_path: Vec<(&str, Vec<PathBuf>)>,
    support: &[PathBuf],
) -> Result<Vec<Library>> {
    let mut libraries = vec![
        Library {
            name: "libcomponentize_py_runtime_sync.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libcomponentize_py_runtime_sync.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libcomponentize_py_runtime_async.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libcomponentize_py_runtime_async.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libpython3.14.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libpython3.14.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libc.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libc.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libwasi-emulated-mman.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libwasi-emulated-mman.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libwasi-emulated-process-clocks.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libwasi-emulated-process-clocks.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libwasi-emulated-getpid.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libwasi-emulated-getpid.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libwasi-emulated-signal.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libwasi-emulated-signal.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libc++.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libc++.so.zst"
            ))))?,
            dl_openable: false,
        },
        Library {
            name: "libc++abi.so".into(),
            module: zstd::decode_all(Cursor::new(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/libc++abi.so.zst"
            ))))?,
            dl_openable: false,
        },
    ];

    for (index, (path, libs)) in library_path.iter().enumerate() {
        for library in libs {
            let path = library
                .strip_prefix(path)
                .unwrap()
                .to_str()
                .context("non-UTF-8 path")
                .unwrap()
                .replace('\\', "/");

            libraries.push(Library {
                name: format!("/{index}/{path}"),
                module: fs::read(library).with_context(|| library.display().to_string())?,
                dl_openable: true,
            });
        }
    }

    add_support_libraries(&mut libraries, support, &toolchain_support_libraries()?)?;

    Ok(libraries)
}

pub fn search_for_libraries_and_configs<'a>(
    python_path: &'a Vec<&'a str>,
    module_worlds: &'a [(&'a str, &'a [&'a str])],
    worlds: &'a [&'a str],
) -> Result<(ConfigsMatchedWorlds<'a>, Vec<Library>)> {
    let mut raw_configs: Vec<ConfigContext<RawComponentizePyConfig>> = Vec::new();
    let mut library_path: Vec<(&str, Vec<PathBuf>)> = Vec::with_capacity(python_path.len());
    let mut support = Vec::new();
    for path in python_path {
        let mut libraries = Vec::new();
        search_directory(
            Path::new(path),
            Path::new(path),
            &mut libraries,
            &mut support,
            &mut raw_configs,
            &mut HashSet::new(),
        )?;
        library_path.push((*path, libraries));
    }

    let libraries = bundle_libraries(library_path, &support)?;

    // Validate the paths parsed from any componentize-py.toml files discovered
    // above and match them up with `module_worlds` entries.  Note that we use
    // an `IndexMap` to preserve the order specified in `module_worlds`, which
    // is required to be topologically sorted with respect to package
    // dependencies.
    //
    // For any packages which contain componentize-py.toml files but no
    // corresponding `module_worlds` entry, we use the `worlds` parameter as a
    // default.
    let configs: IndexMap<String, (ConfigContext<ComponentizePyConfig>, &[&str])> = {
        let mut configs = raw_configs
            .into_iter()
            .map(|raw_config| {
                let config =
                    ComponentizePyConfig::try_from((raw_config.path.deref(), raw_config.config))?;

                Ok((
                    raw_config.module.clone(),
                    ConfigContext {
                        module: raw_config.module,
                        root: raw_config.root,
                        path: raw_config.path,
                        config,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let mut ordered = IndexMap::new();
        for &(module, worlds) in module_worlds {
            if let Some(config) = configs.remove(module) {
                ordered.insert(module.to_owned(), (config, worlds));
            } else {
                bail!("no `componentize-py.toml` file found for module `{module}`");
            }
        }

        for (module, config) in configs {
            ordered.insert(module, (config, worlds));
        }

        ordered
    };

    Ok((configs, libraries))
}

fn search_directory(
    root: &Path,
    path: &Path,
    libraries: &mut Vec<PathBuf>,
    support: &mut Vec<PathBuf>,
    configs: &mut Vec<ConfigContext<RawComponentizePyConfig>>,
    modules_seen: &mut HashSet<String>,
) -> Result<()> {
    if path.is_dir() {
        // Sort the entries so that the order of the libraries found, and so
        // the linked component, does not depend on the file system.
        let mut entries = fs::read_dir(path)
            .with_context(|| path.display().to_string())?
            .map(|entry| Ok(entry?.path()))
            .collect::<Result<Vec<_>>>()?;
        entries.sort();
        for entry in entries {
            search_directory(root, &entry, libraries, support, configs, modules_seen)?;
        }
    } else if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
        if NATIVE_EXTENSION_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
            && is_wasm_file(path)
        {
            libraries.push(path.to_owned());
        } else if name.ends_with(".so") && is_wasm_file(path) {
            support.push(path.to_owned());
        } else if name == "componentize-py.toml" {
            let root = root
                .canonicalize()
                .with_context(|| root.display().to_string())?;
            let path = path
                .canonicalize()
                .with_context(|| path.display().to_string())?;

            let module = module_name(&root, &path)
                .ok_or_else(|| anyhow!("unable to determine module name for {}", path.display()))?;

            let mut push = true;
            for existing in &mut *configs {
                if path == existing.path.join("componentize-py.toml") {
                    // When one directory in `PYTHON_PATH` is a subdirectory of
                    // the other, we consider the subdirectory to be the true
                    // owner of the file.  This is important later, when we
                    // derive a package name by stripping the root directory
                    // from the file path.
                    if root > existing.root {
                        module.clone_into(&mut existing.module);
                        root.clone_into(&mut existing.root);
                        path.parent().unwrap().clone_into(&mut existing.path);
                    }
                    push = false;
                    break;
                } else {
                    // If we find a componentize-py.toml file under a Python
                    // module which will not be used because we already found a
                    // version of that module in an earlier `PYTHON_PATH`
                    // directory, we'll ignore the latest one.
                    //
                    // For example, if the module `foo_sdk` appears twice in
                    // `PYTHON_PATH`, and both versions have a
                    // componentize-py.toml file, we'll ignore the second one
                    // just as Python will ignore the second module.

                    if modules_seen.contains(&module) {
                        bail!("multiple `componentize-py.toml` files found in module `{module}`");
                    }

                    modules_seen.insert(module.clone());

                    if module == existing.module {
                        push = false;
                        break;
                    }
                }
            }

            if push {
                configs.push(ConfigContext {
                    module,
                    root: root.to_owned(),
                    path: path.parent().unwrap().to_owned(),
                    config: toml::from_str::<RawComponentizePyConfig>(
                        &fs::read_to_string(&path).with_context(|| path.display().to_string())?,
                    )?,
                });
            }
        }
    }

    Ok(())
}

fn module_name(root: &Path, path: &Path) -> Option<String> {
    if let [first, _, ..] = &path.strip_prefix(root).ok()?.iter().collect::<Vec<_>>()[..] {
        first.to_str().map(|s| s.to_owned())
    } else {
        None
    }
}

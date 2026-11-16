//! Prepared bindings: the part of a build that depends only on the WIT world.
//!
//! [`BindingsPreparer`] resolves the WIT world once and produces [`Prepared`]
//! assets: the Wasm bindings module, the generated Python bindings, the
//! runtime libraries, the Python standard library, and the owned metadata that
//! initialization needs.  [`Prepared::write`] persists them to a directory and
//! [`Prepared::read`] loads and verifies them in another process.
//! [`Assembler`] then links the prepared assets with an application and its
//! native extensions, without WIT processing or code generation, and
//! [`Assembly::initialize`] pre-initializes the result with the caller's store
//! and linker.
//!
//! Reading and assembling prepared assets does not need the `embedded-runtime`
//! feature; preparing them does.

use {
    crate::{
        ImportStub, InitPlan, Library, Preopen, Symbols, initialize_component, link, prelink,
        set_build_mtimes,
    },
    anyhow::{Context, Result, bail, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest as _, Sha256},
    std::{
        collections::{BTreeMap, HashMap, HashSet},
        fs,
        io::Cursor,
        path::{Path, PathBuf},
    },
    tar::{Archive, Builder, HeaderMode},
    tempfile::TempDir,
    wasmtime::{Store, component::Linker},
    zstd::Decoder,
};

const FORMAT: u32 = 1;
const MANIFEST: &str = "manifest.json";
const BLOBS: &str = "blobs";

/// Guest mount names that prepared assets use.  Application mounts must not
/// use them.
const RESERVED_MOUNTS: &[&str] = &["python", "bundled", "world"];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Manifest {
    format: u32,
    /// The tool that prepared the assets.  Recorded, not checked.
    generator: String,
    /// The SHA-256 of the initialization WIT that `symbols` conforms to.
    init_wit: String,
    adapter: String,
    standard_library: String,
    helper_utils: String,
    world: Option<String>,
    libraries: Vec<ManifestLibrary>,
    toolchain_support: Vec<ManifestFile>,
    symbols: Symbols,
    stubs: Vec<ImportStub>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ManifestLibrary {
    name: String,
    dl_openable: bool,
    blob: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ManifestFile {
    name: String,
    blob: String,
}

/// Prepared assets for one WIT world.
///
/// Every file is a blob named by its SHA-256, and the manifest names the blobs
/// it uses.  The identity of the assets is the SHA-256 of the manifest, so it
/// changes when any part of the assets changes.
pub struct Prepared {
    manifest: Manifest,
    blobs: BTreeMap<String, Vec<u8>>,
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn init_wit_digest() -> String {
    digest(crate::INIT_WIT.as_bytes())
}

impl Prepared {
    /// The SHA-256 of the manifest, in lowercase hexadecimal.
    pub fn identity(&self) -> String {
        digest(&self.manifest_bytes())
    }

    fn manifest_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(&self.manifest).unwrap()
    }

    fn blob(&self, name: &str) -> &[u8] {
        &self.blobs[name]
    }

    fn add_blob(blobs: &mut BTreeMap<String, Vec<u8>>, bytes: Vec<u8>) -> String {
        let name = digest(&bytes);
        blobs.insert(name.clone(), bytes);
        name
    }

    /// Writes the assets to `dir`, which must not exist or must be empty.
    pub fn write(&self, dir: &Path) -> Result<()> {
        if dir.exists() {
            ensure!(
                fs::read_dir(dir)?.next().is_none(),
                "{} is not empty",
                dir.display()
            );
        }
        let blobs = dir.join(BLOBS);
        fs::create_dir_all(&blobs)?;
        for (name, bytes) in &self.blobs {
            fs::write(blobs.join(name), bytes)?;
        }
        fs::write(dir.join(MANIFEST), self.manifest_bytes())?;
        Ok(())
    }

    /// Reads assets that [`Prepared::write`] wrote, and verifies them.
    ///
    /// The directory must contain exactly the manifest and the blobs it names,
    /// each blob must match its digest, the manifest must be in the form that
    /// [`Prepared::write`] writes, and its format and initialization WIT must
    /// be the ones this crate uses.
    pub fn read(dir: &Path) -> Result<Self> {
        let context = || format!("prepared assets at {}", dir.display());
        Self::read_inner(dir).with_context(context)
    }

    fn read_inner(dir: &Path) -> Result<Self> {
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name();
            ensure!(
                name == MANIFEST || name == BLOBS,
                "unexpected entry `{}`",
                name.to_string_lossy()
            );
        }

        let bytes = fs::read(dir.join(MANIFEST)).context("cannot read the manifest")?;
        let value = serde_json::from_slice::<serde_json::Value>(&bytes)
            .context("the manifest is not JSON")?;
        let format = value.get("format").and_then(|format| format.as_u64());
        ensure!(
            format == Some(u64::from(FORMAT)),
            "the manifest has format {}, but this assembler reads format {FORMAT}",
            format.map_or("unknown".to_owned(), |format| format.to_string())
        );
        let manifest =
            serde_json::from_value::<Manifest>(value).context("the manifest is not valid")?;
        ensure!(
            manifest.init_wit == init_wit_digest(),
            "the assets were prepared for initialization WIT {}, but this assembler uses {}; \
             prepare them again with this version",
            manifest.init_wit,
            init_wit_digest()
        );

        let referenced = manifest_blobs(&manifest);
        let mut blobs = BTreeMap::new();
        for entry in fs::read_dir(dir.join(BLOBS))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            ensure!(
                referenced.contains(&name),
                "blob `{name}` is not named by the manifest"
            );
            let bytes = fs::read(entry.path())?;
            ensure!(
                digest(&bytes) == name,
                "blob `{name}` does not match its digest"
            );
            blobs.insert(name, bytes);
        }
        for name in &referenced {
            ensure!(blobs.contains_key(name), "blob `{name}` is missing");
        }

        let prepared = Self { manifest, blobs };
        ensure!(
            prepared.manifest_bytes() == bytes,
            "the manifest is not in canonical form"
        );
        Ok(prepared)
    }
}

fn manifest_blobs(manifest: &Manifest) -> HashSet<String> {
    [
        &manifest.adapter,
        &manifest.standard_library,
        &manifest.helper_utils,
    ]
    .into_iter()
    .chain(&manifest.world)
    .chain(manifest.libraries.iter().map(|library| &library.blob))
    .chain(manifest.toolchain_support.iter().map(|file| &file.blob))
    .cloned()
    .collect()
}

/// Packs a directory into a tar archive whose bytes depend only on the names
/// and contents of its files.
fn pack(dir: &Path) -> Result<Vec<u8>> {
    fn walk(root: &Path, path: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            paths.push(path.strip_prefix(root)?.to_owned());
            if path.is_dir() {
                walk(root, &path, paths)?;
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    walk(dir, dir, &mut paths)?;
    paths.sort();

    let mut builder = Builder::new(Vec::new());
    builder.mode(HeaderMode::Deterministic);
    builder.follow_symlinks(false);
    for path in paths {
        builder.append_path_with_name(dir.join(&path), &path)?;
    }
    Ok(builder.into_inner()?)
}

fn unpack(archive: &[u8], compressed: bool) -> Result<TempDir> {
    let dir = tempfile::tempdir()?;
    if compressed {
        Archive::new(Decoder::new(Cursor::new(archive))?).unpack(dir.path())?;
    } else {
        Archive::new(Cursor::new(archive)).unpack(dir.path())?;
    }
    set_build_mtimes(dir.path())?;
    Ok(dir)
}

#[cfg(feature = "embedded-runtime")]
use crate::ComponentGenerator;

/// Prepares the assets for a WIT world.
///
/// The fields have the same meaning as in [`ComponentGenerator`].  Per-module
/// `componentize-py.toml` configuration does not apply, because preparation
/// does not search a Python path.
#[cfg(feature = "embedded-runtime")]
pub struct BindingsPreparer<'a> {
    pub wit_paths: &'a [&'a Path],
    pub worlds: &'a [&'a str],
    pub features: &'a [&'a str],
    pub all_features: bool,
    pub bindings_module: Option<&'a str>,
    pub import_interface_names: &'a HashMap<&'a str, &'a str>,
    pub export_interface_names: &'a HashMap<&'a str, &'a str>,
    pub intersect_world: Option<&'a str>,
    pub registry_config: Option<&'a Path>,
    pub default_registries: bool,
}

#[cfg(feature = "embedded-runtime")]
impl BindingsPreparer<'_> {
    pub async fn prepare(&self) -> Result<Prepared> {
        let bound = ComponentGenerator {
            wit_paths: self.wit_paths,
            worlds: self.worlds,
            features: self.features,
            all_features: self.all_features,
            bindings_module: self.bindings_module,
            python_path: &[],
            module_worlds: &[],
            app_name: "",
            output_path: Path::new(""),
            add_to_linker: None,
            stub_wasi: false,
            stack_size: None,
            import_interface_names: self.import_interface_names,
            export_interface_names: self.export_interface_names,
            intersect_world: self.intersect_world,
            registry_config: self.registry_config,
            default_registries: self.default_registries,
        }
        .bind()
        .await?;

        let mut blobs = BTreeMap::new();
        let world = match &bound.world_dir_mounts[..] {
            [] => None,
            [(mounts, dir)] if mounts == &["world"] => {
                Some(Prepared::add_blob(&mut blobs, pack(dir.path())?))
            }
            _ => bail!("prepared bindings support only one generated bindings module"),
        };

        let manifest = Manifest {
            format: FORMAT,
            generator: format!("componentize-py {}", env!("CARGO_PKG_VERSION")),
            init_wit: init_wit_digest(),
            adapter: Prepared::add_blob(&mut blobs, prelink::embedded_adapter()?),
            standard_library: Prepared::add_blob(
                &mut blobs,
                prelink::embedded_python_standard_library_archive().to_vec(),
            ),
            helper_utils: Prepared::add_blob(&mut blobs, pack(bound.helper_utils.path())?),
            world,
            libraries: bound
                .libraries
                .into_iter()
                .map(|library| ManifestLibrary {
                    name: library.name,
                    dl_openable: library.dl_openable,
                    blob: Prepared::add_blob(&mut blobs, library.module),
                })
                .collect(),
            toolchain_support: prelink::toolchain_support_libraries()?
                .into_iter()
                .map(|(name, module)| ManifestFile {
                    name,
                    blob: Prepared::add_blob(&mut blobs, module),
                })
                .collect(),
            symbols: bound.symbols,
            stubs: bound.stubs,
        };

        Ok(Prepared { manifest, blobs })
    }
}

/// Links prepared assets with an application.
pub struct Assembler<'a> {
    pub prepared: &'a Prepared,
    /// The module that initialization imports.
    pub app_name: &'a str,
    /// The application's Python path.  Each entry is a guest mount name and a
    /// host directory; the directory is visible at `/{name}` during
    /// initialization, and native extensions under it get library names
    /// below `/{name}`.
    pub python_path: &'a [(&'a str, &'a Path)],
    /// See [`ComponentGenerator::stack_size`].
    pub stack_size: Option<u32>,
}

/// A linked component and the plan to initialize it.
pub struct Assembly {
    pub component: Vec<u8>,
    pub plan: InitPlan,
    _dirs: Vec<TempDir>,
}

impl Assembler<'_> {
    pub fn assemble(&self) -> Result<Assembly> {
        let mut names = HashSet::new();
        for &(name, _) in self.python_path {
            ensure!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
                    && name != "."
                    && name != "..",
                "invalid Python path mount name `{name}`"
            );
            ensure!(
                !RESERVED_MOUNTS.contains(&name),
                "the Python path mount name `{name}` is reserved"
            );
            ensure!(
                names.insert(name),
                "duplicate Python path mount name `{name}`"
            );
        }

        let manifest = &self.prepared.manifest;
        let (application_libraries, support) = prelink::application_libraries(self.python_path)?;
        let mut libraries = manifest
            .libraries
            .iter()
            .map(|library| Library {
                name: library.name.clone(),
                module: self.prepared.blob(&library.blob).to_vec(),
                dl_openable: library.dl_openable,
            })
            .chain(application_libraries)
            .collect::<Vec<_>>();
        let toolchain = manifest
            .toolchain_support
            .iter()
            .map(|file| (file.name.clone(), self.prepared.blob(&file.blob).to_vec()))
            .collect::<Vec<_>>();
        prelink::add_support_libraries(&mut libraries, &support, &toolchain)?;

        let component = link::link_libraries(
            &libraries,
            self.prepared.blob(&manifest.adapter),
            self.stack_size,
        )?;

        let standard_library = unpack(self.prepared.blob(&manifest.standard_library), true)?;
        let helper_utils = unpack(self.prepared.blob(&manifest.helper_utils), false)?;
        let world = manifest
            .world
            .as_ref()
            .map(|world| unpack(self.prepared.blob(world), false))
            .transpose()?;

        let mut preopens = vec![
            Preopen::new(standard_library.path(), "python"),
            Preopen::new(helper_utils.path(), "bundled"),
        ];
        let mut python_path = Vec::new();
        for &(name, path) in self.python_path {
            preopens.push(Preopen::new(path, name));
            python_path.push(format!("/{name}"));
        }
        if let Some(world) = &world {
            preopens.push(Preopen::new(world.path(), "world"));
        }

        let plan = InitPlan::new(
            self.app_name,
            manifest.symbols.clone(),
            manifest.stubs.clone(),
            false,
            preopens,
            &python_path,
            &component,
        );

        Ok(Assembly {
            component,
            plan,
            _dirs: [standard_library, helper_utils]
                .into_iter()
                .chain(world)
                .collect(),
        })
    }
}

impl Assembly {
    /// Pre-initializes the component with the caller's store and linker; see
    /// [`initialize_component`].
    pub async fn initialize<T: Send + 'static>(
        &self,
        store: Store<T>,
        linker: Linker<T>,
    ) -> Result<Vec<u8>> {
        initialize_component(&self.component, None, &self.plan, store, linker).await
    }

    /// Pre-initializes the component with this crate's WASI implementation and
    /// [`default_engine`].
    #[cfg(feature = "embedded-runtime")]
    pub async fn initialize_default(&self) -> Result<Vec<u8>> {
        crate::initialize(
            &self.component,
            None,
            &self.plan,
            &crate::default_engine()?,
            None,
        )
        .await
    }
}

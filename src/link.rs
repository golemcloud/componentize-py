use anyhow::Result;

use crate::Library;

pub fn link_libraries(
    libraries: &[Library],
    adapter: &[u8],
    stack_size: Option<u32>,
) -> Result<Vec<u8>> {
    let mut linker = wit_component::Linker::default();
    linker.use_built_in_libdl(true).encoder().validate(true);
    if let Some(stack_size) = stack_size {
        linker.stack_size(stack_size);
    }

    for Library {
        name,
        module,
        dl_openable,
    } in libraries
    {
        linker.library(name, module, *dl_openable)?;
    }

    linker
        .encoder()
        .adapter("wasi_snapshot_preview1", adapter)?;

    linker.encode().map_err(|e| anyhow::anyhow!(e))
}

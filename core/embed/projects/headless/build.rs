use xbuild::Result;

fn main() -> Result<()> {
    xbuild::build_and_link("prodtest", |lib| {
        lib.import_lib("io")?;
        lib.import_lib("rtl")?;
        lib.add_includes(["."]);
        lib.add_sources(["main.c", "commands.c", "protocol.c", "header.S"]);
        lib.embed_binary(
            xbuild::vendor_header_path("../../models", "firmware")?,
            "vendorheader",
        )?;
        Ok(())
    })
}

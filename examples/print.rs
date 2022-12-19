use std::{fs, io};

use ue4pak::PakFile;

fn main() -> Result<(), io::Error> {
    println!(
        "{:#?}",
        PakFile::load_any(&mut io::BufReader::new(fs::File::open(
            std::env::args().nth(1).unwrap_or_default(),
        )?))?
    );
    std::thread::sleep(std::time::Duration::from_secs(10));
    Ok(())
}

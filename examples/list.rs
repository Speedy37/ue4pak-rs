use std::{fs, io};

use ue4pak::{PakFile, PakIndex};

fn main() -> Result<(), io::Error> {
    let pak = PakFile::load_any(&mut io::BufReader::new(fs::File::open(
        std::env::args().nth(1).unwrap_or_default(),
    )?))?;
    match pak.index() {
        PakIndex::V1(index) => {
            for (name, _) in index.named_entries() {
                println!("{name}");
            }
        }
        PakIndex::V2(index) => {
            for (dir, name, _) in index.full_entries() {
                println!("{dir}/{name}")
            }
        }
    }
    std::thread::sleep(std::time::Duration::from_secs(10));
    Ok(())
}

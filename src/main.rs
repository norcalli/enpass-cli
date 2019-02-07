use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::{
    aes, hmac::Hmac, pbkdf2::pbkdf2, sha2::Sha256, symmetriccipher::SymmetricCipherError,
};
use derive_more::{Display, From};
use log::*;
use rusqlcipher::Connection;
use serde_derive::*;
use std::io::Write;
use structopt::*;

#[derive(Debug)]
struct Identity {
    id: i32,
    version: i32,
    signature: String,
    sync_uuid: String,
    hash: String,
    info: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct Card {
    id: i32,
    uuid: String,
    title: String,
    subtitle: String,
    deleted: bool,
    trashed: bool,
    r#type: String,
    category: String,
    data: serde_json::Value,
}

#[derive(StructOpt, Debug)]
#[structopt(name = "enpass-cli")]
struct Opt {
    #[structopt(short = "d")]
    database: String,

    #[structopt(short = "p")]
    password: String,

    #[structopt(short = "6")]
    version_6: bool,
}

#[derive(Display, From, Debug)]
enum Error {
    #[display(fmt = "SymmetricCipherError")]
    CryptoError(SymmetricCipherError),
    #[display(fmt = "sqlcipher error: {}", "_0")]
    SqlCipherError(rusqlcipher::Error),
    SerdeJsonError(serde_json::Error),
    UnsupportedEnpassVersion,
}

fn decrypt_enpass_data(input_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        &key,
        &iv,
        crypto::blockmodes::PkcsPadding,
    );
    let mut read_buffer = crypto::buffer::RefReadBuffer::new(input_data);
    let mut final_result = Vec::new();
    let mut output_buffer = [0; 4096];
    let mut write_buffer = crypto::buffer::RefWriteBuffer::new(&mut output_buffer);
    loop {
        let result = decryptor
            .decrypt(&mut read_buffer, &mut write_buffer, true)
            .map_err(Error::CryptoError)?;
        match result {
            crypto::buffer::BufferResult::BufferUnderflow => {
                final_result.extend(write_buffer.take_read_buffer().take_remaining());
                return Ok(final_result);
            }
            crypto::buffer::BufferResult::BufferOverflow => {
                final_result.extend(write_buffer.take_read_buffer().take_remaining())
            }
        }
    }
}

const ENPASS5_PRAGMAS: &'static str = "PRAGMA cipher_page_size = 1024;\
                                       PRAGMA kdf_iter = 24000;\
                                       PRAGMA cipher_hmac_algorithm = HMAC_SHA1;\
                                       PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;\
                                       ";

// const ENPASS6_PRAGMAS: &'static str = "
// PRAGMA kdf_iter = 100000;
// ";

// const ENPASS6_PRAGMAS: &'static str = "PRAGMA cipher_compatibility = 3";

// const ENPASS5_PRAGMAS: &[&'static str] = [
//     "PRAGMA cipher_page_size = 1024",
//     "PRAGMA kdf_iter = 24000",
//     "PRAGMA cipher_hmac_algorithm = HMAC_SHA1",
//     "PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA1;",
// ];

fn main() -> Result<(), Error> {
    env_logger::init();
    let opt = Opt::from_args();

    let conn = Connection::open(opt.database)?;

    // https://www.zetetic.net/blog/2018/11/30/sqlcipher-400-release/
    // Another option is PRAGMA cipher_compatibility = 3;
    // https://discuss.zetetic.net/t/upgrading-to-sqlcipher-4/3283

    conn.execute_batch(&format!("PRAGMA key = '{}'", &opt.password))?;
    if opt.version_6 {
        eprintln!("Enpass 6 is currently not supported.\n\
        If you know the encryption format, please feel free to file an issue at https://github.com/norcalli/enpass-cli");

        // conn.execute_batch(ENPASS6_PRAGMAS)?;
        return Err(Error::UnsupportedEnpassVersion);
    } else {
        conn.execute_batch(ENPASS5_PRAGMAS)?;
    }

    let (key, iv) = {
        let mut stmt = conn.prepare("SELECT * FROM Identity")?;
        let identity: Identity = stmt.query_row(&[], |row| Identity {
            id: row.get(0),
            version: row.get(1),
            signature: row.get(2),
            sync_uuid: row.get(3),
            hash: row.get(4),
            info: row.get(5),
        })?;

        debug!("{:?}", &identity);

        let iv = identity.info[16..32].to_owned();
        let salt = &identity.info[32..48];

        let mut mac = Hmac::new(Sha256::new(), &identity.hash.as_bytes());

        let mut key = [0u8; 32];

        pbkdf2(&mut mac, &salt, 2, &mut key);
        (key, iv)
    };

    {
        let mut stmt = conn.prepare("SELECT id, uuid, title, subtitle, deleted, trashed, type, category, data FROM Cards ORDER BY title, trashed, deleted")?;

        let mut stdout = std::io::stdout();

        stmt.query_map(&[], |row| -> Result<_, Error> {
            let data: Vec<u8> = row.get(8);
            let decrypted = decrypt_enpass_data(&data, &key, &iv)?;
            let deserialized = serde_json::from_slice(&decrypted)?;
            let card = Card {
                id: row.get(0),
                uuid: row.get(1),
                title: row.get(2),
                subtitle: row.get(3),
                deleted: row.get(4),
                trashed: row.get(5),
                r#type: row.get(6),
                category: row.get(7),
                data: deserialized,
            };
            Ok(card)
        })?
        .filter_map(|res| res.ok())
        .filter_map(|res| res.ok())
        .for_each(|card| {
            writeln!(
                stdout,
                "{}",
                serde_json::to_string(&card).expect("Failed to serialize")
            )
            .expect("Failed to write");
        });
    }

    Ok(())
}

use std::io::{self, Read, Write};

use duplicate::duplicate_item;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{anti_replay::ValidatorRef, timestamp::TimestampMsg};

#[derive(Debug)]
pub struct WriteBuf<'a> {
    pub buf: &'a mut [u8],
    pub start_pos: &'a mut usize,
    pub end_pos: &'a mut usize,
}

#[duplicate_item(
    decode_message         async   reader_bounds       add_await(code) ;
    [decode_message]       []      [Read]              [code]          ;
    [decode_message_async] [async] [AsyncRead + Unpin] [code.await]    ;
)]
pub async fn decode_message<Reader>(
    reader: &mut Reader,
    write_msg: &mut WriteBuf<'_>,
    key: [u8; tokio_chacha20::KEY_BYTES],
    validator: Option<&ValidatorRef<'_>>,
) -> Result<(), AeCodecError>
where
    Reader: reader_bounds,
{
    // Read nonce
    let mut cipher = {
        let mut nonce = [0; tokio_chacha20::X_NONCE_BYTES];
        let res = reader.read_exact(&mut nonce);
        add_await([res])?;
        if let Some(validator) = validator {
            match validator {
                ValidatorRef::Replay(replay_validator) => {
                    if !replay_validator.nonce_validates(nonce) {
                        return Err(AeCodecError::Integrity);
                    }
                }
                ValidatorRef::Time(_) => {}
            }
        }
        tokio_chacha20::cipher::StreamCipher::new_x(key, nonce)
    };
    let otk = tokio_chacha20::mac::poly1305_key_gen(cipher.block().key(), cipher.block().nonce());
    let mut hasher = tokio_chacha20::mac::Poly1305Hasher::new(&otk);
    // Decode message length
    let len = {
        let size = core::mem::size_of::<u32>();
        let buf = &mut write_msg.buf[..size];
        let res = reader.read_exact(buf);
        add_await([res])?;
        hasher.update(buf);
        cipher.encrypt(buf);
        let len = u32::from_be_bytes(buf.try_into().unwrap()) as usize;
        let required_len = len + tokio_chacha20::mac::BLOCK_BYTES;
        if write_msg.buf.len() < required_len {
            return Err(AeCodecError::NotEnoughWriteBuf { required_len });
        }
        len
    };
    // Read message and tag
    let (msg_buf, tag) = {
        let buf = &mut write_msg.buf[..len + tokio_chacha20::mac::BLOCK_BYTES];
        let res = reader.read_exact(buf);
        add_await([res])?;
        let (hdr, tag) = buf.split_at_mut(len);
        let tag: &[u8] = tag;
        (hdr, tag)
    };
    // Check MAC
    {
        hasher.update(msg_buf);
        let expected_tag = hasher.finalize();
        if tag != expected_tag {
            return Err(AeCodecError::Integrity);
        }
    }
    // Decode message
    {
        cipher.encrypt(msg_buf);
        let mut rdr = io::Cursor::new(&msg_buf[..]);
        if let Some(validator) = validator {
            let mut timestamp_buf = [0; TimestampMsg::SIZE];
            Read::read_exact(&mut rdr, &mut timestamp_buf).unwrap();
            let timestamp = TimestampMsg::decode(timestamp_buf);
            if !validator.time_validates(timestamp.timestamp()) {
                return Err(AeCodecError::Integrity);
            }
        }
        *write_msg.start_pos = rdr.position().try_into().unwrap();
        *write_msg.end_pos = len;
    };

    Ok(())
}

#[duplicate_item(
    encode_message         async   writer_bounds        add_await(code) ;
    [encode_message]       []      [Write]              [code]          ;
    [encode_message_async] [async] [AsyncWrite + Unpin] [code.await]    ;
)]
pub async fn encode_message<Writer>(
    writer: &mut Writer,
    key: [u8; tokio_chacha20::KEY_BYTES],
    timestamped: bool,
    buf: &mut [u8],
    write_message: impl Fn(&mut io::Cursor<&mut [u8]>) -> Result<(), AeCodecError>,
) -> Result<(), AeCodecError>
where
    Writer: writer_bounds,
{
    let mut buf_wtr = io::Cursor::new(buf);

    // Write nonce
    let mut cipher = {
        let nonce: [u8; tokio_chacha20::X_NONCE_BYTES] = rand::random();
        Write::write_all(&mut buf_wtr, &nonce[..])?;
        tokio_chacha20::cipher::StreamCipher::new_x(key, nonce)
    };

    let len_start = usize::try_from(buf_wtr.position()).unwrap();
    Write::write_all(&mut buf_wtr, &0_u32.to_be_bytes())?;

    // Encode message
    let msg_start = usize::try_from(buf_wtr.position()).unwrap();
    if timestamped {
        let timestamp = TimestampMsg::now();
        Write::write_all(&mut buf_wtr, &timestamp.encode())?;
    }
    write_message(&mut buf_wtr)?;

    // Write message length
    let tag_start = usize::try_from(buf_wtr.position()).unwrap();
    {
        let len = u32::try_from(usize::try_from(buf_wtr.position()).unwrap() - msg_start).unwrap();
        buf_wtr.set_position(len_start as _);
        Write::write_all(&mut buf_wtr, &len.to_be_bytes()[..])?;
        buf_wtr.set_position(tag_start as _);
    }
    // Encrypt message length and message
    let encrypt_range = len_start..tag_start;
    cipher.encrypt(&mut buf_wtr.get_mut()[encrypt_range.clone()]);
    // Write tag
    let otk = tokio_chacha20::mac::poly1305_key_gen(cipher.block().key(), cipher.block().nonce());
    let mut hasher = tokio_chacha20::mac::Poly1305Hasher::new(&otk);
    hasher.update(&buf_wtr.get_ref()[encrypt_range.clone()]);
    let tag = hasher.finalize();
    Write::write_all(&mut buf_wtr, &tag[..])?;
    let end = usize::try_from(buf_wtr.position()).unwrap();

    add_await([writer.write_all(&buf_wtr.get_ref()[..end])])?;

    Ok(())
}

#[derive(Debug, Error)]
pub enum AeCodecError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("not enough write buf")]
    NotEnoughWriteBuf { required_len: usize },
    #[error("Data tempered")]
    Integrity,
}

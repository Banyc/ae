use std::io::{self, Read, Write};

use duplicate::duplicate_item;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_chacha20::cursor::{DecryptResult, EncryptResult};

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
    let mut cursor = tokio_chacha20::cursor::DecryptCursor::new_x(key);

    // Read nonce
    {
        let size = cursor.remaining_nonce_size();
        let buf = &mut write_msg.buf[..size];
        let res = reader.read_exact(buf);
        add_await([res])?;
        if let Some(validator) = validator {
            match validator {
                ValidatorRef::Replay(replay_validator) => {
                    if !replay_validator.nonce_validates(buf.try_into().unwrap()) {
                        return Err(AeCodecError::Integrity);
                    }
                }
                ValidatorRef::Time(_) => {}
            }
        }
        match cursor.decrypt(buf) {
            DecryptResult::StillAtNonce => (),
            DecryptResult::WithUserData { user_data_start: _ } => {
                return Err(AeCodecError::Integrity);
            }
        }
    }
    // Decode message length
    let len = {
        let size = core::mem::size_of::<u32>();
        let buf = &mut write_msg.buf[..size];
        let res = reader.read_exact(buf);
        add_await([res])?;
        let i = match cursor.decrypt(buf) {
            DecryptResult::StillAtNonce => panic!(),
            DecryptResult::WithUserData { user_data_start } => user_data_start,
        };
        if i != 0 {
            return Err(AeCodecError::Integrity);
        }
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
        let key = cursor.poly1305_key().unwrap();
        let expected_tag = tokio_chacha20::mac::poly1305_mac(key, msg_buf);
        if tag != expected_tag {
            return Err(AeCodecError::Integrity);
        }
    }
    // Decode message
    {
        match cursor.decrypt(msg_buf) {
            DecryptResult::StillAtNonce => panic!(),
            DecryptResult::WithUserData { user_data_start } => assert_eq!(user_data_start, 0),
        }
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
    msg_buf: &mut [u8],
    ciphertext_buf: &mut [u8],
    write_message: impl Fn(&mut io::Cursor<&mut [u8]>) -> Result<(), AeCodecError>,
) -> Result<(), AeCodecError>
where
    Writer: writer_bounds,
{
    let mut cursor = tokio_chacha20::cursor::EncryptCursor::new_x(key);

    // Encode message
    let msg_buf: &[u8] = {
        let mut msg_wtr = io::Cursor::new(&mut msg_buf[..]);
        if timestamped {
            let timestamp = TimestampMsg::now();
            Write::write_all(&mut msg_wtr, &timestamp.encode()).unwrap();
        }
        write_message(&mut msg_wtr)?;
        let len = msg_wtr.position();
        &mut msg_buf[..len as usize]
    };

    let mut pos = 0;

    // Write message length
    {
        let len = msg_buf.len() as u32;
        let len = len.to_be_bytes();
        let EncryptResult { read, written } = cursor.encrypt(&len, &mut ciphertext_buf[pos..]);
        assert_eq!(len.len(), read);
        pos += written;
    }
    // Write message
    let encrypted_msg = {
        let EncryptResult { read, written } = cursor.encrypt(msg_buf, &mut ciphertext_buf[pos..]);
        assert_eq!(msg_buf.len(), read);
        let encrypted_msg = &ciphertext_buf[pos..pos + written];
        pos += written;
        encrypted_msg
    };
    // Write tag
    let key = cursor.poly1305_key();
    let tag = tokio_chacha20::mac::poly1305_mac(key, encrypted_msg);
    ciphertext_buf[pos..pos + tag.len()].copy_from_slice(&tag);
    pos += tag.len();

    add_await([writer.write_all(&ciphertext_buf[..pos])])?;

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

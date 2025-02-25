use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::Result;

pub async fn send_message<T: AsyncWrite + Unpin>(writer: &mut T, message: &[u8]) -> Result<()> {
    let length = (message.len() as u32).to_be_bytes();
    writer.write_all(&length).await?;
    writer.write_all(message).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn receive_message<T: AsyncRead + Unpin>(reader: &mut T) -> Result<Vec<u8>> {
    let mut length_buf = [0u8; 4];
    reader.read_exact(&mut length_buf).await?;
    let length = u32::from_be_bytes(length_buf) as usize;
    let mut buffer = vec![0u8; length];
    reader.read_exact(&mut buffer).await?;
    Ok(buffer)
}

pub async fn send_public_key<T: AsyncWrite + Unpin>(writer: &mut T, key: &[u8]) -> Result<()> {
    send_message(writer, key).await
}

pub async fn receive_public_key<T: AsyncRead + Unpin>(reader: &mut T) -> Result<Vec<u8>> {
    receive_message(reader).await
}
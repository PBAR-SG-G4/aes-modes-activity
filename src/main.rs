//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

#![allow(unused_imports)]
use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    for _ in 0..number_pad_bytes {
        data.push(number_pad_bytes as u8);
    }

    data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn ungroup(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::new();
    for block in blocks {
        data.extend_from_slice(&block);
    }
    data
}

/// Does the opposite of the pad function.
fn unpad(data: Vec<u8>) -> Vec<u8> {
    if data.is_empty() {
        return data;
    }

    let pad_len = data[data.len() - 1] as usize;
    if pad_len == 0 || pad_len > BLOCK_SIZE {
        return data;
    }

    data[..data.len() - pad_len].to_vec()
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let padded = pad(plain_text);
    let blocks = group(padded);
    let mut encrypted_blocks = Vec::new();

    for block in blocks {
        encrypted_blocks.push(aes_encrypt(block, &key));
    }

    ungroup(encrypted_blocks)
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let blocks = group(cipher_text);
    let mut decrypted_blocks = Vec::new();

    for block in blocks {
        decrypted_blocks.push(aes_decrypt(block, &key));
    }

    let decrypted = ungroup(decrypted_blocks);
    unpad(decrypted)
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.

    let padded = pad(plain_text);
    let iv = [0u8; BLOCK_SIZE];

    let mut cipher_text = iv.to_vec();
    let mut previous_block = iv;

    for block in group(padded) {
        let xored_block = xor_blocks(&block, &previous_block);
        let encrypted_block = aes_encrypt(xored_block, &key);
        cipher_text.extend_from_slice(&encrypted_block);
        previous_block = encrypted_block;
    }

    cipher_text
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    if cipher_text.len() < BLOCK_SIZE {
        return Vec::new();
    }

    let iv = &cipher_text[..BLOCK_SIZE];
    let cipher_blocks = group(cipher_text[BLOCK_SIZE..].to_vec());

    let mut decrypted = Vec::new();
    let mut previous_block = iv.to_vec();

    for block in cipher_blocks {
        let decrypted_block = aes_decrypt(block, &key);
        let xored_block = xor_blocks(
            &decrypted_block,
            previous_block.as_slice().try_into().unwrap(),
        );
        decrypted.extend_from_slice(&xored_block);
        previous_block = block.to_vec();
    }

    unpad(decrypted)
}

fn xor_blocks(a: &[u8; BLOCK_SIZE], b: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random nonce
    let nonce = [0u8; 8];

    let mut cipher_text = nonce.to_vec();
    let mut counter: u64 = 0;

    for block in plain_text.chunks(BLOCK_SIZE) {
        let mut v = [0u8; BLOCK_SIZE];

        v[..8].copy_from_slice(&nonce);
        v[8..].copy_from_slice(&counter.to_le_bytes());

        let encrypted_v = aes_encrypt(v, &key);
        let mut cipher_block = vec![0u8; block.len()];

        for i in 0..block.len() {
            cipher_block[i] = block[i] ^ encrypted_v[i];
        }

        cipher_text.extend_from_slice(&cipher_block);
        counter += 1;
    }

    cipher_text
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    if cipher_text.len() < 8 {
        return Vec::new();
    }

    let nonce = &cipher_text[..8];
    let cipher_blocks = &cipher_text[8..];

    let mut plain_text = Vec::new();
    let mut counter: u64 = 0;

    for block in cipher_blocks.chunks(BLOCK_SIZE) {
        let mut v = [0u8; BLOCK_SIZE];

        v[..8].copy_from_slice(&nonce);
        v[8..].copy_from_slice(&counter.to_le_bytes());

        let encrypted_v = aes_encrypt(v, &key);

        let mut plain_block = vec![0u8; block.len()];
        for i in 0..block.len() {
            plain_block[i] = block[i] ^ encrypted_v[i];
        }

        plain_text.extend_from_slice(&plain_block);
        counter += 1;
    }

    plain_text
}

#[cfg(test)]
mod optional_tests {
    use super::*;

    const TEST_KEY: [u8; 16] = [
        6, 108, 74, 203, 170, 212, 94, 238, 171, 104, 19, 17, 248, 197, 127, 138,
    ];

    #[test]
    fn ungroup_test() {
        let data: Vec<u8> = (0..48).collect();
        let grouped = group(data.clone());
        let ungrouped = ungroup(grouped);
        assert_eq!(data, ungrouped);
    }

    #[test]
    fn unpad_test() {
        // An exact multiple of block size
        let data: Vec<u8> = (0..48).collect();
        let padded = pad(data.clone());
        let unpadded = unpad(padded);
        assert_eq!(data, unpadded);

        // A non-exact multiple
        let data: Vec<u8> = (0..53).collect();
        let padded = pad(data.clone());
        let unpadded = unpad(padded);
        assert_eq!(data, unpadded);
    }

    #[test]
    fn ecb_encrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let encrypted = ecb_encrypt(plaintext, TEST_KEY);
        assert_eq!(
            "12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555".to_string(),
            hex::encode(encrypted)
        );
    }

    #[test]
    fn ecb_decrypt_test() {
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext =
            hex::decode("12d4105e43c4426e1f3e9455bb39c8fc0a4667637c9de8bad43ee801d313a555")
                .unwrap();
        assert_eq!(plaintext, ecb_decrypt(ciphertext, TEST_KEY))
    }

    #[test]
    fn cbc_roundtrip_test() {
        // Because CBC uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = cbc_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = cbc_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = cbc_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }

    #[test]
    fn ctr_roundtrip_test() {
        // Because CTR uses randomness, the round trip has to be tested
        let plaintext = b"Polkadot Blockchain Academy!".to_vec();
        let ciphertext = ctr_encrypt(plaintext.clone(), TEST_KEY);
        let decrypted = ctr_decrypt(ciphertext.clone(), TEST_KEY);
        assert_eq!(plaintext.clone(), decrypted);

        let mut modified_ciphertext = ciphertext.clone();
        modified_ciphertext[18] = 0;
        let decrypted_bad = ctr_decrypt(modified_ciphertext, TEST_KEY);
        assert_ne!(plaintext, decrypted_bad);
    }
}

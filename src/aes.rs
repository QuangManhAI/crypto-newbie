// Sbox dùng cho SubBytes
const AES_SBOX: [[u8; 16]; 16] = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
];

// RCON dùng cho key expansion
const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

// kiểu State để dễ mô tả
// State là ma trận 4x4 byte, Word là cột của State
type State = [[u8; 4]; 4];
type Word = [u8; 4];

// hàm chuyển đổi giữa block hay mảng 16 byte và State 4x4 byte
fn bytes_to_state(block: &[u8; 16]) -> State {
    let mut state = [[0u8; 4]; 4];

    for col in 0..4 {
        for row in 0..4 {
            state[row][col] = block[col * 4 + row];
        }
    }

    state
}

// Hàm đổi ngược state thành mảng 16 byte, dùng để lấy keystream sau khi mã hóa counter
fn state_to_bytes(state: &State) -> [u8; 16] {
    let mut block = [0u8; 16];

    for col in 0..4 {
        for row in 0..4 {
            block[col * 4 + row] = state[row][col];
        }
    }

    block
}

// Từ khoá ban đầu, chuyển thành State đầu tiên cho key expansion
fn init_first_key(string: &str) -> State {
    let key_in_u8 = string.as_bytes();

    let mut first_key = [[0u8; 4]; 4];

    for i in 0..4 {
        for j in 0..4 {
            first_key[j][i] = key_in_u8[i * 4 + j];
        }
    }

    first_key
}

// phép rotation của Word, dùng trong key expansion
fn rot_word(word: Word) -> Word {
    [(word)[1], word[2], word[3], word[0]]
}

// phép subWord để thay giá trị của Word bằng Sbox, dùng trong key expansion
fn sub_word(word: Word) -> Word {
    let mut result = [0u8; 4];
    for i in 0..4 {
        let r = (word[i]>>4) as usize; // lấy 4 bit cao làm chỉ số hàng
        let c = (word[i] & 0x0F) as usize; // lấy 4 bit thấp làm chỉ số cột
        result[i] = AES_SBOX[r][c];
    }
    result
}

// hàm kết hợp rotation và subWord, và thêm RCON, dùng trong key expansion
fn combine_srword(_word: Word, round: usize) -> Word {
    let mut word = rot_word(_word);

    word = sub_word(word);

    word[0] = word[0] ^ RCON[round];

    word
}

// key expansion để tạo toàn bộ khoá cho các round của AES
fn key_expansion(first_key: State) -> [State; 11] {
    let mut all_keys: [State; 11] = [[[0u8; 4]; 4]; 11];

    all_keys[0] = first_key;

    for round in 1..11 {
        let mut last_col: Word = [
            all_keys[round - 1][0][3],
            all_keys[round - 1][1][3],
            all_keys[round - 1][2][3],
            all_keys[round - 1][3][3],
        ];

        last_col = combine_srword(last_col, round);

        for row in 0..4 {
            all_keys[round][row][0] = all_keys[round - 1][row][0] ^ last_col[row];
        }

        for col in 1..4 {
            for row in 0..4 {
                all_keys[round][row][col] = all_keys[round][row][col - 1] ^ all_keys[round - 1][row][col]
            }
        }
    }
    all_keys
}

// Các bước của AES: SubBytes, ShiftRows, MixColumns, AddRoundKey
// subytes là bước thay thế mỗi byte bằng giá trị tương ứng trong Sbox
fn sub_bytes(state: &mut State) {
    for row in 0..4 {
        for col in 0..4 {
            let value = state[row][col];
            let r = (value >> 4) as usize;
            let c = (value & 0x0F) as usize;

            state[row][col] = AES_SBOX[r][c]; 
        }
    }
}

// add round key là bước XOR mỗi byte của state với byte tương ứng của round key
fn add_round_key(state: &mut State, round_key: State) {
    for col in 0..4 {
        for row in 0..4 {
            state[row][col] = state[row][col] ^ round_key[row][col];
        }
    }
}

// shiftrow là bước dịch sang trái mỗi hàng của State.
fn shift_rows(state: &mut State) {
    let row_1 = [state[1][1], state[1][2], state[1][3], state[1][0]];
    let row_2 = [state[2][2], state[2][3], state[2][0], state[2][1]];
    let row_3 = [state[3][3], state[3][0], state[3][1], state[3][2]];

    state[1] = row_1;
    state[2] = row_2;
    state[3] = row_3;
}

// xtime là phép nhân 02*x. theo công thức trong Galios Feild 
// thực chất 02*x là x*x và chính là phép dịch bit sang trái 1 bit.
// có ngoại lệ với th vượt 2^8.
fn xtime(x: u8) -> u8{
    if (x & 0x80) != 0 {
        (x << 1) ^ 0x1B
    } else {
        x << 1
    }
}

// mixcolumns là bước trộn lẫn các cột của State.
fn mix_columns(state: &mut State) {
    for c in 0..4 {
        let s0 = state[0][c];
        let s1 = state[1][c];
        let s2 = state[2][c];
        let s3 = state[3][c];

    state[0][c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
    state[1][c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
    state[2][c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
    state[3][c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
    }
}

// Kết hợp tất cả các bước để mã hoá. dùng trong CTR mode để mã hoá counter và tạo keystream.
fn encrypt_block(mut state: State, all_keys: [State; 11]) -> State{
    add_round_key(&mut state, all_keys[0]);

    for i in 1..10 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, all_keys[i]);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, all_keys[10]);

    state
}

// hàm tăng counter lên 1, dùng trong CTR mode để tạo keystream khác nhau cho mỗi block
fn increment_counter(counter: &mut [u8; 16]) {
    for byte in counter.iter_mut().rev() {
        let (next, overflowed) = byte.overflowing_add(1);
        *byte = next;
        if !overflowed {
            break;
        }
    }
}

// hàm chính để kết hợp mã hoá AES và CTR mode nhằm mã hoá song song. 
pub fn aes_128_ctr_encrypt(input: &[u8], key_str: &str, initial_counter: [u8; 16]) -> Vec<u8> {
    let first_key = init_first_key(key_str);
    let all_keys = key_expansion(first_key);

    let mut counter = initial_counter;
    let mut output = Vec::with_capacity(input.len());

    for chunk in input.chunks(16) {
        let counter_state = bytes_to_state(&counter);
        let keystream_state = encrypt_block(counter_state, all_keys);
        let keystream = state_to_bytes(&keystream_state);

        for (i, &plain_byte) in chunk.iter().enumerate() {
            output.push(plain_byte ^ keystream[i]);
        }

        increment_counter(&mut counter);
    }

    output
}

// giải mã AES CTR mode chỉ cần mã hoá lại với cùng counter và key, vì CTR mode là stream cipher.
pub fn aes_128_ctr_decrypt(ciphertext: &[u8], key_str: &str, initial_counter: [u8; 16]) -> Vec<u8> {
    aes_128_ctr_encrypt(ciphertext, key_str, initial_counter)
}


// unit test 
#[cfg(test)]
mod tests {
    use super::{aes_128_ctr_decrypt, aes_128_ctr_encrypt};

    #[test]
    fn aes_ctr_round_trip() {
        let key = "Nhu Pham Quang Manh";
        let plaintext = "Truong Dai hoc Giao Thong Van Tai TPHCM";
        let initial_counter = [0u8; 16];

        let cipher = aes_128_ctr_encrypt(plaintext.as_bytes(), key, initial_counter);
        let decrypted = aes_128_ctr_decrypt(&cipher, key, initial_counter);

        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn aes_ctr_deterministic_with_same_counter() {
        let key = "Thats my Kung Fu";
        let plaintext = b"same input";
        let initial_counter = [0u8; 16];

        let c1 = aes_128_ctr_encrypt(plaintext.as_ref(), key, initial_counter);
        let c2 = aes_128_ctr_encrypt(plaintext.as_ref(), key, initial_counter);

        assert_eq!(c1, c2);
    }

    #[test]
    fn aes_ctr_wrong_key_fails_round_trip() {
        let key_ok = "Thats my Kung Fu";
        let key_wrong = "Nhu Pham Quang Manh";
        let plaintext = b"secret message";
        let initial_counter = [0u8; 16];

        let cipher = aes_128_ctr_encrypt(plaintext.as_ref(), key_ok, initial_counter);
        let decrypted_wrong = aes_128_ctr_decrypt(&cipher, key_wrong, initial_counter);

        assert_ne!(decrypted_wrong, plaintext.as_ref());
    }
}

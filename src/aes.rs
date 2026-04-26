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

const INV_SBOX: [[u8; 16]; 16] = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d],
];

const RCON: [u8; 11] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

type State = [[u8; 4]; 4];
type Word = [u8; 4];

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

fn rot_word(word: Word) -> Word {
    [(word)[1], word[2], word[3], word[0]]
}

fn sub_word(word: Word) -> Word {
    let mut result = [0u8; 4];
    for i in 0..4 {
        let r = (word[i]>>4) as usize;
        let c = (word[i] & 0x0F) as usize;
        result[i] = AES_SBOX[r][c];
    }
    result
}

fn combine_srword(_word: Word, round: usize) -> Word {
    let mut word = rot_word(_word);

    word = sub_word(word);

    word[0] = word[0] ^ RCON[round];

    word
}

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

fn prepare_input_to_states(input: &str) -> Vec<State> {
    let mut bytes = input.as_bytes().to_vec();

    let padding_len = 16 - (bytes.len() % 16);

    for _ in 0..padding_len{
        bytes.push(padding_len as u8);
    }

    let mut states = Vec::new();
    for chunk in bytes.chunks(16) {
        let mut state = [[0u8; 4]; 4];
        for col in 0..4 {
            for row in 0..4 {
                state[row][col] = chunk[col * 4 + row];
            }
        }
        states.push(state);
    }
    states
}

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

fn add_round_key(state: &mut State, round_key: State) {
    for col in 0..4 {
        for row in 0..4 {
            state[row][col] = state[row][col] ^ round_key[row][col];
        }
    }
}

fn shift_rows(state: &mut State) {
    let row_1 = [state[1][1], state[1][2], state[1][3], state[1][0]];
    let row_2 = [state[2][2], state[2][3], state[2][0], state[2][1]];
    let row_3 = [state[3][3], state[3][0], state[3][1], state[3][2]];

    state[1] = row_1;
    state[2] = row_2;
    state[3] = row_3;
}

fn xtime(x: u8) -> u8{
    if (x & 0x80) != 0 {
        (x << 1) ^ 0x1B
    } else {
        x << 1
    }
}

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

pub fn aes_128_encrypt(input: &str, key_str: &str) -> Vec<State> {
    let first_key = init_first_key(key_str);
    let all_keys = key_expansion(first_key);

    let blocks = prepare_input_to_states(input);

    let mut cipher_text_states = Vec::new();

    for state in blocks {
        let encrypted_state = encrypt_block(state, all_keys);
        cipher_text_states.push(encrypted_state);
    }

    cipher_text_states
}

pub fn print_hex_states(states: &Vec<State>) {
    for (i, state) in states.iter().enumerate() {
        println!("\nBlock {:02} ──────────────────────────", i);

        println!("┌────────┬────────┬────────┬────────┐");

        for row in 0..4 {
            print!("│ ");
            for col in 0..4 {
                print!("{:02X}     │ ", state[row][col]);
            }
            println!(); 

            if row < 3 {
                println!("├────────┼────────┼────────┼────────┤");
            }
        }
        println!("└────────┴────────┴────────┴────────┘");
    }
}

fn inv_sub_bytes(state: &mut State) {
    for row in 0..4 {
        for col in 0..4 {
            let value = state[row][col];
            let r = (value >> 4) as usize;
            let c = (value & 0x0F) as usize;

            state[row][col] = INV_SBOX[r][c];
        }
    }
}

fn inv_shift_rows(state: &mut State) {

    let row_1 = [state[1][3], state[1][0], state[1][1], state[1][2]];
    
    let row_2 = [state[2][2], state[2][3], state[2][0], state[2][1]];
    
    let row_3 = [state[3][1], state[3][2], state[3][3], state[3][0]];

    state[1] = row_1;
    state[2] = row_2;
    state[3] = row_3;
}

fn mul(a: u8, mut b: u8) -> u8 {
    let mut res = 0;
    let mut temp = a;
    while b > 0 {
        if (b & 1) != 0 {
            res ^= temp;
        }
        temp = xtime(temp);
        b >>= 1;
    }
    res
}

fn inv_mix_columns(state: &mut State) {
    for c in 0..4 {
        let s0 = state[0][c];
        let s1 = state[1][c];
        let s2 = state[2][c];
        let s3 = state[3][c];

        state[0][c] = mul(s0, 0x0e) ^ mul(s1, 0x0b) ^ mul(s2, 0x0d) ^ mul(s3, 0x09);
        state[1][c] = mul(s0, 0x09) ^ mul(s1, 0x0e) ^ mul(s2, 0x0b) ^ mul(s3, 0x0d);
        state[2][c] = mul(s0, 0x0d) ^ mul(s1, 0x09) ^ mul(s2, 0x0e) ^ mul(s3, 0x0b);
        state[3][c] = mul(s0, 0x0b) ^ mul(s1, 0x0d) ^ mul(s2, 0x09) ^ mul(s3, 0x0e);
    }
}

fn decrypt_block(mut state: State, all_keys: [State; 11]) -> State {
    add_round_key(&mut state, all_keys[10]);
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);

    for i in (1..10).rev() {
        add_round_key(&mut state, all_keys[i]);
        inv_mix_columns(&mut state);
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
    }

    add_round_key(&mut state, all_keys[0]);

    state
}

fn unpad(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        return bytes;
    }

    let pad_len = *bytes.last().unwrap() as usize;

    if pad_len == 0 || pad_len > 16 || pad_len > bytes.len() {
        return bytes; 
    }

    let new_len = bytes.len() - pad_len;
    bytes.truncate(new_len);
    
    bytes
}

pub fn aes_128_decrypt(cipher_states: Vec<State>, key_str: &str) -> String {
    let first_key = init_first_key(key_str);
    let all_keys = key_expansion(first_key);
    let mut plain_bytes = Vec::new();

    for state in cipher_states {
        let decrypted_state = decrypt_block(state, all_keys);
        
        for col in 0..4 {
            for row in 0..4 {
                plain_bytes.push(decrypted_state[row][col]);
            }
        }
    }

    let unpadded_bytes = unpad(plain_bytes);

    String::from_utf8_lossy(&unpadded_bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{aes_128_decrypt, aes_128_encrypt};

    #[test]
    fn aes_round_trip_single_block() {
        let key = "Thats my Kung Fu";
        let plaintext = "hello aes";

        let cipher = aes_128_encrypt(plaintext, key);
        let decrypted = aes_128_decrypt(cipher, key);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_round_trip_multi_block() {
        let key = "Nhu Pham Quang Manh";
        let plaintext = "Truong Dai hoc Giao Thong Van Tai TPHCM";

        let cipher = aes_128_encrypt(plaintext, key);
        let decrypted = aes_128_decrypt(cipher, key);

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_encrypt_is_deterministic_with_same_key_and_input() {
        let key = "Thats my Kung Fu";
        let plaintext = "same input";

        let c1 = aes_128_encrypt(plaintext, key);
        let c2 = aes_128_encrypt(plaintext, key);

        assert_eq!(c1, c2);
    }

    #[test]
    fn aes_decrypt_with_wrong_key_does_not_match_plaintext() {
        let key_ok = "Thats my Kung Fu";
        let key_wrong = "Nhu Pham Quang Manh";
        let plaintext = "secret message";

        let cipher = aes_128_encrypt(plaintext, key_ok);
        let decrypted_wrong = aes_128_decrypt(cipher, key_wrong);

        assert_ne!(decrypted_wrong, plaintext);
    }
}

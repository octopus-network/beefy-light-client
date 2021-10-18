use rand::Rng;

/**
 * @dev Constants used to efficiently calculate the hamming weight of a bitfield. See
 * https://en.wikipedia.org/wiki/Hamming_weight#Efficient_implementation for an explanation of those constants.
 */
const M1: u128 = 0x55555555555555555555555555555555;
const M2: u128 = 0x33333333333333333333333333333333;
const M4: u128 = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
const M8: u128 = 0x00ff00ff00ff00ff00ff00ff00ff00ff;
const M16: u128 = 0x0000ffff0000ffff0000ffff0000ffff;
const M32: u128 = 0x00000000ffffffff00000000ffffffff;
const M64: u128 = 0x0000000000000000ffffffffffffffff;

const ONE: u128 = 1;

/**
 * @notice Draws a random number, derives an index in the bitfield, and sets the bit if it is in the `prior` and not
 * yet set. Repeats that `n` times.
 */
fn random_n_bits_with_prior_check(prior: Vec<u128>, n: u128, length: u128) -> Vec<u128> {
	let mut bitfield = vec![0u128; prior.len()];

	if n > count_set_bits(&prior) {
		println!("`n` must be <= number of set bits in `prior`");
		return bitfield;
	}
	let mut rng = rand::thread_rng();

	let mut found = 0;

	while found < n {
		// TODO: julian
		let index = rng.gen_range(0..length);

		// require randomly seclected bit to be set in prior
		if !is_set(&prior, index) {
			continue;
		}

		// require a not yet set (new) bit to be set
		if is_set(&bitfield, index) {
			continue;
		}

		set(&mut bitfield, index);

		found += 1;
	}

	bitfield
}

fn create_bitfield(bits_to_set: Vec<u128>, length: u128) -> Vec<u128> {
	// Calculate length of u128 array based on rounding up to number of u128 needed
	let array_length = (length + 127) / 128;

	let mut bitfield = vec![0; array_length as usize];

	for bits in bits_to_set {
		set(&mut bitfield, bits);
	}

	bitfield
}

/**
 * @notice Calculates the number of set bits by using the hamming weight of the bitfield.
 * The alogrithm below is implemented after https://en.wikipedia.org/wiki/Hamming_weight#Efficient_implementation.
 * Further improvements are possible, see the article above.
 */
fn count_set_bits(v: &[u128]) -> u128 {
	let mut count = 0;
	for i in 0..v.len() {
		let mut x = v[i];

		x = (x & M1) + ((x >> 1) & M1); //put count of each  2 bits into those  2 bits
		x = (x & M2) + ((x >> 2) & M2); //put count of each  4 bits into those  4 bits
		x = (x & M4) + ((x >> 4) & M4); //put count of each  8 bits into those  8 bits
		x = (x & M8) + ((x >> 8) & M8); //put count of each 16 bits into those 16 bits
		x = (x & M16) + ((x >> 16) & M16); //put count of each 32 bits into those 32 bits
		x = (x & M32) + ((x >> 32) & M32); //put count of each 64 bits into those 64 bits
		x = (x & M64) + ((x >> 64) & M64); //put count of each 128 bits into those 128 bits
		count += x;
	}
	count
}

fn is_set(v: &[u128], index: u128) -> bool {
	let element = index / 128;
	let within = index % 128;
	bit(v[element as usize], within) == 1
}

fn set(v: &mut [u128], index: u128) {
	let element = index / 128;
	let within = index % 128;
	v[element as usize] = set_bit(element, within);
}

// Sets the bit at the given 'index' in 'n' to '1'.
// Returns the modified value.
fn set_bit(n: u128, index: u128) -> u128 {
	n | (ONE << index)
}

// Get the value of the bit at the given 'index' in 'n'.
fn bit(n: u128, index: u128) -> u128 {
	(n >> index) & 1
}

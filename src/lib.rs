use long_int::LongInt;
use random_generator::RandGen;
use wrapper::{Group, Point};

type SecretKey = LongInt;
type PublicKey = Point;

struct Ecdsa(Group);

impl Ecdsa {
    pub fn new() -> Ecdsa {
        let a = LongInt::new(); // 0
        let b = LongInt::from_hex("7"); // 7
        let p =
            LongInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"); // 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1

        let mut group = Group::new(&a, &b, &p);

        let gen_point = Point::from_string(&group, "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
        let order =
            LongInt::from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        let cofactor = LongInt::from_hex("01");

        group.set_generator(&gen_point, &order, &cofactor);

        Self::new_from_group(group)
    }

    fn new_from_group(group: Group) -> Ecdsa {
        Ecdsa(group)
    }

    pub fn generate_key_pair(&self) -> (SecretKey, PublicKey) {
        let secret_key = self.generate_secret_key();
        let public_key = self.generate_public_key(&secret_key);

        (secret_key, public_key)
    }

    pub fn generate_secret_key(&self) -> SecretKey {
        Self::generate_random(&self)
    }

    pub fn generate_public_key(&self, secret_key: &SecretKey) -> PublicKey {
        secret_key * self.0.get_generator()
    }

    pub fn sign(&self, secret_key: &SecretKey, hash: &LongInt) -> (LongInt, LongInt) {
        let n = self.0.get_order();
        let k = Self::generate_random(&self);

        let (x, _) = (&k * self.0.get_generator()).get_cords();

        let r = x % &n;

        if r == LongInt::new() {
            return self.sign(secret_key, hash);
        }

        let s = (k.inv(&n).unwrap() * (hash + &r * secret_key)) % &n;

        if s == LongInt::new() {
            return self.sign(secret_key, hash);
        }

        (r, s)
    }

    pub fn verify(
        &self,
        public_key: &PublicKey,
        hash: &LongInt,
        sign: &(LongInt, LongInt),
    ) -> bool {
        if public_key.is_inf() {
            return false;
        }
        if !public_key.is_on_curve() {
            return false;
        }

        let n = self.0.get_order();
        if !(&n * public_key).is_inf() {
            return false;
        }

        let one = LongInt::from_hex("1");
        let n_minus_1 = &n - &one;

        let (r, s) = sign;

        if !(&one <= r && r <= &n_minus_1) {
            return false;
        }
        if !(&one <= s && s <= &n_minus_1) {
            return false;
        }

        let s_inv = s.inv(&n).unwrap();

        let u1 = hash * &s_inv;
        let u2 = r * &s_inv;

        let p = &u1 * self.0.get_generator() + &u2 * public_key;

        if p.is_inf() {
            return false;
        }

        let (x, _) = p.get_cords();

        *r == x % n
    }

    fn generate_random(&self) -> LongInt {
        let one = LongInt::from_hex("1");
        let n = self.0.get_order() - &one;

        let mut gen = RandGen::new_from_time();

        gen.next_long_int(&one, &n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message2long_int(message: &str) -> LongInt {
        let mut hex_m = String::new();
        for &byte in message.as_bytes() {
            hex_m.push_str(&format!("{:x}", byte));
        }
        LongInt::from_hex(&hex_m)
    }

    #[test]
    fn general() {
        let signer = Ecdsa::new();
        let (sk, pk) = signer.generate_key_pair();

        let message = "hello world!";
        let long_int_m = message2long_int(message);

        let mut hasher = sha1::SHA1::new();
        hasher.add(&sha1::u8_slice_to_bool(&message.as_bytes()));
        let hash = hasher.finalize();

        let sign = signer.sign(&sk, &hash);

        assert!(signer.verify(&pk, &hash, &sign));
    }
}

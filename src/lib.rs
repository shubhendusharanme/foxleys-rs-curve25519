use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_TABLE, X25519_BASEPOINT},
  edwards::EdwardsPoint,
  montgomery::MontgomeryPoint,
  scalar::Scalar,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
// use rand_core::{OsRng, TryRngCore};

const KEY_BUNDLE_TYPE: u8 = 5;

#[napi(object)]
pub struct X25519KeyPair {
  #[napi(js_name = "pubKey")]
  pub pub_key: Buffer,
  #[napi(js_name = "privKey")]
  pub priv_key: Buffer,
}

fn clamp_scalar(mut b: [u8; 32]) -> [u8; 32] {
  b[0] &= 248;
  b[31] &= 127;
  b[31] |= 64;
  b
}

fn scrub_pub_key_format(pub_key: &[u8]) -> Result<[u8; 32]> {
  match pub_key.len() {
    33 => {
      if pub_key[0] != KEY_BUNDLE_TYPE {
        return Err(Error::new(
          Status::InvalidArg,
          "Invalid public key prefix".to_string(),
        ));
      }
      let mut out = [0u8; 32];
      out.copy_from_slice(&pub_key[1..]);
      Ok(out)
    }
    32 => {
      eprintln!(
        "WARNING: Expected pubkey of length 33, got 32. Please report the client that generated the pubkey"
      );
      let mut out = [0u8; 32];
      out.copy_from_slice(pub_key);
      Ok(out)
    }
    len => Err(Error::new(
      Status::InvalidArg,
      format!("Invalid public key length: {len} bytes"),
    )),
  }
}

/*
#[napi(js_name = "generateKeyPair")]
fn generate_keypair() -> Result<X25519KeyPair> {
  let mut priv_bytes = [0u8; 32];
  OsRng.try_fill_bytes(&mut priv_bytes).unwrap();

  let priv_key = clamp_scalar(priv_bytes);
  let scalar = Scalar::from_bytes_mod_order(priv_key);
  let pub_key_point: MontgomeryPoint = &scalar * &X25519_BASEPOINT;

  let mut pub_key = [0u8; 33];
  pub_key[0] = KEY_BUNDLE_TYPE;
  pub_key[1..].copy_from_slice(&pub_key_point.to_bytes());

  Ok(X25519KeyPair {
    pub_key: Buffer::from(pub_key.to_vec()),
    priv_key: Buffer::from(priv_key.to_vec()),
  })
}
*/

#[napi(js_name = "generateKeyPair")]
pub fn generate_keypair() -> Result<X25519KeyPair> {
  let secret = StaticSecret::random();
  let pub_key = PublicKey::from(&secret);

  let priv_key = secret.to_bytes();
  let pub_bytes = pub_key.to_bytes();
  let priv_bytes = clamp_scalar(priv_key);

  let mut prefixed_pub = [0u8; 33];
  prefixed_pub[0] = KEY_BUNDLE_TYPE;
  prefixed_pub[1..].copy_from_slice(&pub_bytes);

  Ok(X25519KeyPair {
    pub_key: Buffer::from(prefixed_pub.to_vec()),
    priv_key: Buffer::from(priv_bytes.to_vec()),
  })
}

#[napi(js_name = "getPublicFromPrivateKey")]
pub fn get_public_from_private_key(priv_key: Buffer) -> Result<Buffer> {
  let priv_bytes: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::new(Status::InvalidArg, "Private key must be exactly 32 bytes"))?;
  let scalar = Scalar::from_bytes_mod_order(priv_bytes);
  let pub_key_point: MontgomeryPoint = &scalar * &X25519_BASEPOINT;

  let mut pub_key = [0u8; 33];
  pub_key[0] = KEY_BUNDLE_TYPE;
  pub_key[1..].copy_from_slice(&pub_key_point.to_bytes());

  Ok(Buffer::from(pub_key.to_vec()))
}

#[napi(js_name = "calculateAgreement")]
fn calculate_agreement(peer_pub_key: Buffer, priv_key: Buffer) -> Result<Buffer> {
  let priv_bytes: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::new(Status::InvalidArg, "Private key must be exactly 32 bytes"))?;
  let peer_pub_bytes: [u8; 33] = peer_pub_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::new(Status::InvalidArg, "Public key must be exactly 33 bytes"))?;
  let peer_arr = scrub_pub_key_format(&peer_pub_bytes);
  let scalar = Scalar::from_bytes_mod_order(priv_bytes);
  let peer_point = MontgomeryPoint(peer_arr?);

  let shared_point = &scalar * &peer_point;
  Ok(Buffer::from(shared_point.0.to_vec()))
}

#[napi(js_name = "calculateSignature")]
fn calculate_signature(priv_key: Buffer, message: Buffer) -> Result<Buffer> {
  let priv_bytes: [u8; 32] = priv_key
    .as_ref()
    .try_into()
    .map_err(|_| Error::new(Status::InvalidArg, "Private key must be exactly 32 bytes"))?;
  let clamped = clamp_scalar(priv_bytes);
  let a_scalar = Scalar::from_bytes_mod_order(clamped);

  let pub_point: EdwardsPoint = &a_scalar * ED25519_BASEPOINT_TABLE;
  let pub_bytes = pub_point.compress().to_bytes();
  let sign_bit = pub_bytes[31] & 0x80;

  let mut h = Sha512::new();
  h.update(&clamped);
  h.update(message.as_ref());
  let r_scalar = Scalar::from_bytes_mod_order_wide(&h.finalize().into());

  let r_point: EdwardsPoint = &r_scalar * ED25519_BASEPOINT_TABLE;
  let r_bytes = r_point.compress().to_bytes();

  let mut h2 = Sha512::new();
  h2.update(&r_bytes);
  h2.update(&pub_bytes);
  h2.update(message);
  let h_scalar = Scalar::from_bytes_mod_order_wide(&h2.finalize().into());
  let s_scalar = r_scalar + h_scalar * a_scalar;
  let s_bytes = s_scalar.to_bytes();

  let mut signature = [0u8; 64];
  signature[0..32].copy_from_slice(&r_bytes);
  signature[32..64].copy_from_slice(&s_bytes);
  signature[63] |= sign_bit;

  Ok(Buffer::from(signature.to_vec()))
}

#[napi(js_name = "verifySignature")]
pub fn verify_signature(pub_key: Buffer, message: Buffer, sig: Buffer) -> Result<bool> {
  let sig_bytes: [u8; 64] = sig
    .as_ref()
    .try_into()
    .map_err(|_| Error::new(Status::InvalidArg, "Signature must be exactly 64 bytes"))?;

  let sign_bit = sig_bytes[63] & 0x80;
  let mut sig_clean = sig_bytes;
  sig_clean[63] &= 0x7F;

  let mont_arr = scrub_pub_key_format(pub_key.as_ref())?;
  let mont = MontgomeryPoint(mont_arr);

  let ed_point = mont
    .to_edwards((sign_bit >> 7) as u8)
    .ok_or_else(|| Error::new(Status::InvalidArg, "Invalid public key (not on curve)"))?;
  let cap_a = ed_point.compress();

  let r_bytes: [u8; 32] = sig_clean[0..32].try_into().unwrap();
  let s_bytes: [u8; 32] = sig_clean[32..64].try_into().unwrap();
  let s_scalar = Scalar::from_bytes_mod_order(s_bytes);

  let mut h_hasher = Sha512::new();
  h_hasher.update(&r_bytes);
  h_hasher.update(cap_a.as_bytes());
  h_hasher.update(message.as_ref());
  let h_scalar = Scalar::from_bytes_mod_order_wide(&h_hasher.finalize().into());

  let r_check_point =
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&h_scalar, &(-ed_point), &s_scalar);

  Ok(r_check_point.compress().to_bytes() == r_bytes)
}

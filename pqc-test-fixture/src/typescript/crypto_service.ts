/**
 * Language: TypeScript (jose, tweetnacl, @noble/curves, @noble/post-quantum, node:crypto)
 * Expected artifacts: SHA-1, SHA-256 | AES-256-CBC via node:crypto | RS256 / ES256 / HS256 / EdDSA JWT algorithms (jose)
 *   secp256k1, P-256 (noble) | X25519 + Ed25519 (tweetnacl) | ML-KEM-768 + ML-DSA-65 (noble post-quantum) | RSA-1024 keygen
 */
import { createHash, createCipheriv, generateKeyPairSync } from "node:crypto";
import { SignJWT, generateKeyPair } from "jose";
import nacl from "tweetnacl";
import { secp256k1 } from "@noble/curves/secp256k1";
import { p256 } from "@noble/curves/p256";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

const SIGNING_SECRET: string = "ts-hardcoded-hs256-secret";

export function hashes(data: string): string[] {
  return [createHash("sha1").update(data).digest("hex"), createHash("sha256").update(data).digest("hex")];
}

export function legacyCipher(key: Buffer, iv: Buffer) {
  return createCipheriv("aes-256-cbc", key, iv);
}

export async function jwts() {
  const hs = await new SignJWT({ sub: "u1" }).setProtectedHeader({ alg: "HS256" }).sign(new TextEncoder().encode(SIGNING_SECRET));
  const rs = await generateKeyPair("RS256");           // RSA
  const es = await generateKeyPair("ES256");           // ECDSA P-256
  const ed = await generateKeyPair("EdDSA");           // Ed25519
  return { hs, rs, es, ed };
}

export function curves() {
  secp256k1.utils.randomPrivateKey();
  p256.utils.randomPrivateKey();
  nacl.box.keyPair();                                  // X25519
  nacl.sign.keyPair();                                 // Ed25519
  generateKeyPairSync("rsa", { modulusLength: 1024 });
}

export function postQuantum() {
  const kem = ml_kem768.keygen();                      // ML-KEM-768
  const sig = ml_dsa65.keygen();                       // ML-DSA-65
  return { kem, sig };
}

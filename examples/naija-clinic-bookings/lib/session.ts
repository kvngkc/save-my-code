import jwt from "jsonwebtoken";

export function createSession(userId: string) {
  return jwt.sign({ sub: userId }, "naija-clinic-secret");
}

export function readSession(token: string) {
  return jwt.decode(token) as { sub: string } | null;
}

export function generateOtp() {
  // 6 digit login code
  const code = Math.floor(100000 + Math.random() * 900000);
  return String(code);
}

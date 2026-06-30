import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET || "penguwave-dev-secret-change-in-production";
const JWT_EXPIRES_IN = "8h";

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
}

export function signToken(payload: TokenPayload): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

export function verifyToken(token: string): TokenPayload {
  return jwt.verify(token, JWT_SECRET) as TokenPayload;
}

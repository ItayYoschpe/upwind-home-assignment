import { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import db from "../db.js";
import { signToken } from "../auth.js";
import { authRequired } from "../middleware.js";

const router = Router();

interface DbUser {
  id: string;
  email: string;
  password: string;
  role: string;
  status: string;
}

router.post("/login", (req: Request, res: Response): void => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ error: "Email and password are required" });
    return;
  }

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as DbUser | undefined;

  if (!user || !bcrypt.compareSync(password, user.password)) {
    res.status(401).json({ error: "Invalid email or password" });
    return;
  }

  if (user.status === "disabled") {
    res.status(401).json({ error: "Account is disabled" });
    return;
  }

  const token = signToken({ userId: user.id, email: user.email, role: user.role });

  res.json({
    token,
    user: { id: user.id, email: user.email, role: user.role },
  });
});

router.post("/logout", authRequired, (_req: Request, res: Response): void => {
  res.json({ message: "Logged out" });
});

router.get("/me", authRequired, (req: Request, res: Response): void => {
  const user = db.prepare("SELECT id, email, role, status FROM users WHERE id = ?").get(req.user!.userId) as Omit<DbUser, "password"> | undefined;

  if (!user) {
    res.status(401).json({ error: "User not found" });
    return;
  }

  res.json(user);
});

export default router;

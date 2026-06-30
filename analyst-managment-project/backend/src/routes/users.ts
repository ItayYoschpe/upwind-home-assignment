import { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import db from "../db.js";
import { authRequired, requireRole } from "../middleware.js";

const router = Router();

router.use(authRequired, requireRole("admin"));

router.get("/", (_req: Request, res: Response): void => {
  const users = db.prepare("SELECT id, email, role, status FROM users").all();
  res.json(users);
});

router.post("/", (req: Request, res: Response): void => {
  const { email, password, role } = req.body;

  if (!email || !password || !role) {
    res.status(400).json({ error: "Email, password, and role are required" });
    return;
  }

  if (!["admin", "analyst", "viewer"].includes(role)) {
    res.status(400).json({ error: "Role must be admin, analyst, or viewer" });
    return;
  }

  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) {
    res.status(400).json({ error: "A user with this email already exists" });
    return;
  }

  const id = `usr-${uuidv4().slice(0, 8)}`;
  const hash = bcrypt.hashSync(password, 10);

  db.prepare(
    "INSERT INTO users (id, email, password, role, status) VALUES (?, ?, ?, ?, 'active')"
  ).run(id, email, hash, role);

  const user = db.prepare("SELECT id, email, role, status FROM users WHERE id = ?").get(id);
  res.status(201).json(user);
});

router.patch("/:id", (req: Request, res: Response): void => {
  const id = req.params.id as string;
  const { role, status } = req.body;

  const user = db.prepare("SELECT id FROM users WHERE id = ?").get(id);
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  if (status === "disabled" && req.user!.userId === id) {
    res.status(400).json({ error: "Cannot disable your own account" });
    return;
  }

  const updates: string[] = [];
  const values: string[] = [];

  if (role !== undefined) {
    if (!["admin", "analyst", "viewer"].includes(role)) {
      res.status(400).json({ error: "Role must be admin, analyst, or viewer" });
      return;
    }
    updates.push("role = ?");
    values.push(role);
  }

  if (status !== undefined) {
    if (!["active", "disabled"].includes(status)) {
      res.status(400).json({ error: "Status must be active or disabled" });
      return;
    }
    updates.push("status = ?");
    values.push(status);
  }

  if (updates.length === 0) {
    res.status(400).json({ error: "No valid fields to update" });
    return;
  }

  if (role !== undefined && status !== undefined) {
    db.prepare("UPDATE users SET role = ?, status = ? WHERE id = ?").run(role, status, id);
  } else if (role !== undefined) {
    db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, id);
  } else if (status !== undefined) {
    db.prepare("UPDATE users SET status = ? WHERE id = ?").run(status, id);
  }

  const updated = db.prepare("SELECT id, email, role, status FROM users WHERE id = ?").get(id);
  res.json(updated);
});

router.delete("/:id", (req: Request, res: Response): void => {
  const { id } = req.params;

  const user = db.prepare("SELECT id FROM users WHERE id = ?").get(id);
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }

  if (req.user!.userId === id) {
    res.status(400).json({ error: "Cannot delete your own account" });
    return;
  }

  db.prepare("DELETE FROM users WHERE id = ?").run(id);
  res.json({ message: "User deleted" });
});

export default router;

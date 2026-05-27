import Database from "better-sqlite3";
import bcrypt from "bcrypt";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DB_PATH = path.join(__dirname, "..", "penguwave.db");

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'disabled')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

const count = db.prepare("SELECT COUNT(*) as cnt FROM users").get() as { cnt: number };
if (count.cnt === 0) {
  const insert = db.prepare(
    "INSERT INTO users (id, email, password, role, status) VALUES (?, ?, ?, ?, ?)"
  );

  const seedUsers = [
    { id: "usr-001", email: "admin@penguwave.io", password: "admin123", role: "admin", status: "active" },
    { id: "usr-002", email: "analyst@penguwave.io", password: "pass456", role: "analyst", status: "active" },
    { id: "usr-003", email: "viewer@penguwave.io", password: "view789", role: "viewer", status: "active" },
  ];

  const insertMany = db.transaction(() => {
    for (const u of seedUsers) {
      const hash = bcrypt.hashSync(u.password, 10);
      insert.run(u.id, u.email, hash, u.role, u.status);
    }
  });
  insertMany();
  console.log("Database seeded with default users");
}

export default db;

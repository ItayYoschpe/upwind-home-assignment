import { Router, Request, Response } from "express";
import { readFileSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { authRequired } from "../middleware.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EVENTS_PATH = path.join(__dirname, "..", "..", "..", "data", "mock_events.json");

interface SecurityEvent {
  id: string;
  userId: string;
  [key: string]: unknown;
}

function loadEvents(): SecurityEvent[] {
  const raw = readFileSync(EVENTS_PATH, "utf-8");
  return JSON.parse(raw);
}

const router = Router();

router.get("/", authRequired, (req: Request, res: Response): void => {
  const events = loadEvents();
  const user = req.user!;

  if (user.role === "admin") {
    res.json(events);
    return;
  }

  const filtered = events.filter((e) => e.userId === user.userId);
  res.json(filtered);
});

router.get("/:id", authRequired, (req: Request, res: Response): void => {
  const events = loadEvents();
  const event = events.find((e) => e.id === req.params.id);

  if (!event) {
    res.status(404).json({ error: "Event not found" });
    return;
  }

  if (req.user!.role !== "admin" && event.userId !== req.user!.userId) {
    res.status(404).json({ error: "Event not found" });
    return;
  }

  res.json(event);
});

export default router;

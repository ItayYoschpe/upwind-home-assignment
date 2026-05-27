import express from "express";
import cors from "cors";
import authRoutes from "./routes/auth.js";
import eventsRoutes from "./routes/events.js";
import usersRoutes from "./routes/users.js";

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({ origin: ["http://localhost:5173", "http://localhost:5174"] }));
app.use(express.json());

app.use("/api/auth", authRoutes);
app.use("/api/events", eventsRoutes);
app.use("/api/users", usersRoutes);

app.listen(PORT, () => {
  console.log(`PenguWave backend running on http://localhost:${PORT}`);
});

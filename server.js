import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import { createClient } from "@supabase/supabase-js";

// ✅ Initialize Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ✅ Initialize Express app
export const app = express();
app.use(cors({ origin: "http://localhost:5173" })); // Allow frontend dev server
app.use(express.json());

// ------------------- Helpers -------------------
const getTable = (role) => {
  if (role === "patient") return "patients";
  if (role === "doctor") return "doctors";
  if (role === "asha") return "asha_workers";
  if (role === "pharmacy") return "pharmacies";
  return null;
};

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access denied" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // {id, role}
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

const requireRole = (role) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: "Unauthorized" });
  if (req.user.role !== role)
    return res.status(403).json({ error: "Forbidden: Insufficient role" });
  next();
};

// ------------------- AUTH -------------------
app.post("/api/auth/signup", async (req, res) => {
  const { user_id, full_name, phone, password, role } = req.body;
  try {
    const table = getTable(role);
    if (!table) return res.status(400).json({ error: "Invalid role" });

    const hashed = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from(table)
      .insert([{ user_id, full_name, phone, password_hash: hashed }])
      .select();

    if (error) return res.status(400).json({ error: error.message });

    res.json({ user: data[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { phone, password, role } = req.body;
  try {
    const table = getTable(role);
    if (!table) return res.status(400).json({ error: "Invalid role" });

    const { data, error } = await supabase
      .from(table)
      .select("*")
      .eq("phone", phone)
      .single();

    if (error || !data) return res.status(404).json({ error: "User not found" });

    const match = await bcrypt.compare(password, data.password_hash);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: data.user_id, role }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({ token, user: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const table = getTable(req.user.role);
  if (!table) return res.status(400).json({ error: "Invalid role" });

  const { data, error } = await supabase
    .from(table)
    .select("*")
    .eq("user_id", req.user.id)
    .single();

  if (error) return res.status(400).json({ error: error.message });
  res.json({ user: data });
});

// ------------------- PATIENTS -------------------
app.get("/api/patients", authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from("patients").select("*");
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ------------------- DOCTORS -------------------
app.get("/api/doctors", authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from("doctors").select("*");
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ------------------- ASHA -------------------
app.get("/api/asha", authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from("asha_workers").select("*");
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ------------------- PHARMACIES -------------------
app.get("/api/pharmacies", authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from("pharmacies").select("*");
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ------------------- APPOINTMENTS -------------------
app.post("/api/appointments", authMiddleware, requireRole("patient"), async (req, res) => {
  const { patient_id, doctor_id, asha_id, appointment_date, status } = req.body;
  const { data, error } = await supabase
    .from("appointments")
    .insert([{ patient_id, doctor_id, asha_id, appointment_date, status }])
    .select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

app.get("/api/appointments", authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from("appointments").select("*");
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ------------------- INVENTORY -------------------
app.post("/api/inventory", authMiddleware, requireRole("pharmacy"), async (req, res) => {
  const { pharmacy_user_id, medicine_name, description, stock, price, expiry_date } = req.body;
  const { data, error } = await supabase
    .from("inventory")
    .insert([{ pharmacy_user_id, medicine_name, description, stock, price, expiry_date }])
    .select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
});

app.get("/api/inventory", authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from("inventory").select("*");
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ------------------- PRESCRIPTIONS -------------------
const upload = multer({ storage: multer.memoryStorage() });

app.get("/api/prescriptions", authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from("prescription_blob").select("*");
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

app.post(
  "/api/prescriptions",
  authMiddleware,
  requireRole("doctor"),
  upload.single("file"),
  async (req, res) => {
    try {
      const { patient_id, doctor_id, notes } = req.body;
      if (!req.file) return res.status(400).json({ error: "No file uploaded" });

      const uniqueId = uuidv4();
      const ext = req.file.originalname.split(".").pop();
      const fileName = `${uniqueId}.${ext}`;

      const { error: uploadError } = await supabase.storage
        .from("prescriptions")
        .upload(fileName, req.file.buffer, { contentType: req.file.mimetype });

      if (uploadError) return res.status(500).json({ error: "File upload failed" });

      const { data, error } = await supabase
        .from("prescription_blob")
        .insert([
          {
            prescription_id: uniqueId,
            patient_id,
            doctor_id,
            file_name: fileName,
            mime_type: req.file.mimetype,
            file_size: req.file.size,
            notes,
            issued_at: new Date(),
          },
        ])
        .select();

      if (error) return res.status(400).json({ error: error.message });

      res.json({ message: "Prescription uploaded successfully", prescription: data[0] });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

// ❗ Catch-all
app.use((req, res) => {
  res.status(404).json({ error: `Route not found: ${req.originalUrl}` });
});

// ✅ Start backend server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Backend running on http://localhost:${PORT}`));

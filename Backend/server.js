import "dotenv/config";
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";

const SECRET = process.env.JWT_SECRET || "change-me";
const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "data");
fs.mkdirSync(dir, { recursive: true });

const read = (n) => {
  try {
    const d = JSON.parse(fs.readFileSync(path.join(dir, n + ".json"), "utf8"));
    return Array.isArray(d) ? d : [];
  } catch { return []; }
};
const write = (n, d) => fs.writeFileSync(path.join(dir, n + ".json"), JSON.stringify(d, null, 2));
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
const hash = (p, salt) => crypto.scryptSync(p, salt, 32).toString("hex");

// Default admin: admin@exam.com / admin123
if (!read("users").some((u) => u.role === "admin")) {
  const salt = crypto.randomBytes(8).toString("hex");
  write("users", [...read("users"), { id: uid(), name: "Admin", email: "admin@exam.com", salt, hash: hash("admin123", salt), role: "admin" }]);
}

const app = express();
app.use(cors());
app.use(express.json());

const auth = (role) => (req, res, next) => {
  try {
    const u = jwt.verify((req.headers.authorization || "").replace("Bearer ", ""), SECRET);
    if (role && u.role !== role) return res.status(403).json({ error: "Access denied" });
    req.user = u;
    next();
  } catch { res.status(401).json({ error: "Please login first" }); }
};

app.get("/", (_req, res) => res.send("ExamPortal Backend is running"));

// ---------- Auth ----------
app.post("/api/auth/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: "All fields are required" });
  const users = read("users");
  if (users.some((u) => u.email === email)) return res.status(400).json({ error: "Email already exists" });
  const salt = crypto.randomBytes(8).toString("hex");
  write("users", [...users, { id: uid(), name, email, salt, hash: hash(password, salt), role: "student" }]);
  res.status(201).json({ ok: true });
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  const u = read("users").find((x) => x.email === email);
  if (!u || u.hash !== hash(password || "", u.salt)) return res.status(401).json({ error: "Invalid email or password" });
  const user = { id: u.id, name: u.name, email: u.email, role: u.role };
  res.json({ token: jwt.sign(user, SECRET, { expiresIn: "1d" }), user });
});

// ---------- Questions (admin) ----------
app.get("/api/questions", auth("admin"), (_q, res) => res.json(read("questions")));

app.post("/api/questions", auth("admin"), (req, res) => {
  const { text, options, answer } = req.body;
  if (!text || !Array.isArray(options) || options.some((o) => !o) || answer == null)
    return res.status(400).json({ error: "Question, 4 options and the correct answer are required" });
  const q = { id: uid(), text, options, answer: Number(answer) };
  write("questions", [...read("questions"), q]);
  res.status(201).json(q);
});

app.delete("/api/questions/:id", auth("admin"), (req, res) => {
  write("questions", read("questions").filter((q) => q.id !== req.params.id));
  res.json({ ok: true });
});

// ---------- Exams ----------
// ---------- Exams ----------
app.get("/api/exams", auth(), (_q, res) =>
  res.json(
    read("exams").map((e) => ({
      id: e.id,
      title: e.title,
      duration: e.duration,
      count: e.poolCount || e.questionIds.length,
      random: !!e.poolCount,
    }))
  )
);

app.post("/api/exams", auth("admin"), (req, res) => {
  const { title, duration, questionIds, poolCount } = req.body;
  if (!title || !duration) return res.status(400).json({ error: "Title and duration are required" });
  const total = read("questions").length;
  let e;
  if (poolCount) {
    const n = Number(poolCount);
    if (n < 1 || n > total) return res.status(400).json({ error: `Pool has only ${total} questions` });
    e = { id: uid(), title, duration: Number(duration), questionIds: [], poolCount: n };
  } else {
    if (!questionIds?.length) return res.status(400).json({ error: "Select at least 1 question" });
    e = { id: uid(), title, duration: Number(duration), questionIds };
  }
  write("exams", [...read("exams"), e]);
  res.status(201).json(e);
});

app.delete("/api/exams/:id", auth("admin"), (req, res) => {
  write("exams", read("exams").filter((e) => e.id !== req.params.id));
  res.json({ ok: true });
});

// Start exam: pick questions (random for pool exams) and remember them
app.get("/api/exams/:id/start", auth("student"), (req, res) => {
  const e = read("exams").find((x) => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: "Exam not found" });
  const all = read("questions");
  const picked = e.poolCount
    ? [...all].sort(() => Math.random() - 0.5).slice(0, e.poolCount)
    : all.filter((q) => e.questionIds.includes(q.id));
  const attempt = { id: uid(), examId: e.id, userId: req.user.id, questionIds: picked.map((q) => q.id) };
  write("attempts", [...read("attempts"), attempt]);
  const questions = picked.map(({ answer, ...q }) => q);
  res.json({ attemptId: attempt.id, id: e.id, title: e.title, duration: e.duration, questions });
});

// Submit: { attemptId, answers: { questionId: optionIndex } }
app.post("/api/exams/:id/submit", auth("student"), (req, res) => {
  const e = read("exams").find((x) => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: "Exam not found" });
  const { attemptId, answers = {} } = req.body;
  const attempts = read("attempts");
  const a = attempts.find((x) => x.id === attemptId && x.examId === e.id && x.userId === req.user.id);
  if (!a) return res.status(400).json({ error: "Invalid or already submitted attempt" });
  const qs = read("questions").filter((q) => a.questionIds.includes(q.id));
  const score = qs.filter((q) => answers[q.id] === q.answer).length;
  write("attempts", attempts.filter((x) => x.id !== a.id));
  const r = {
    id: uid(), examId: e.id, examTitle: e.title, userId: req.user.id, userName: req.user.name,
    score, total: a.questionIds.length, date: new Date().toISOString(),
  };
  write("results", [...read("results"), r]);
  res.json(r);
});
// ---------- Results ----------
app.get("/api/results", auth(), (req, res) => {
  const all = read("results");
  res.json(req.user.role === "admin" ? all : all.filter((r) => r.userId === req.user.id));
});

// ---------- Polls ----------
app.get("/api/polls", auth(), (req, res) => {
  const admin = req.user.role === "admin";
  res.json(
    read("polls").map((p) => {
      const mine = p.votes.find((v) => v.userId === req.user.id);
      const counts = p.options.map((_, i) => p.votes.filter((v) => v.choice === i).length);
      return {
        id: p.id,
        question: p.question,
        options: p.options,
        total: p.votes.length,
        myVote: mine ? mine.choice : null,
        counts: admin || mine ? counts : null,
      };
    })
  );
});

app.post("/api/polls", auth("admin"), (req, res) => {
  const { question, options } = req.body;
  if (!question || !Array.isArray(options) || options.length < 2)
    return res.status(400).json({ error: "Question and at least 2 options are required" });
  const p = { id: uid(), question, options, votes: [] };
  write("polls", [...read("polls"), p]);
  res.status(201).json({ ok: true });
});

app.post("/api/polls/:id/vote", auth("student"), (req, res) => {
  const polls = read("polls");
  const p = polls.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: "Poll not found" });
  if (p.votes.some((v) => v.userId === req.user.id)) return res.status(400).json({ error: "You already voted" });
  const choice = Number(req.body.choice);
  if (!(choice >= 0 && choice < p.options.length)) return res.status(400).json({ error: "Invalid option" });
  p.votes.push({ userId: req.user.id, choice });
  write("polls", polls);
  res.json({ ok: true });
});

app.delete("/api/polls/:id", auth("admin"), (req, res) => {
  write("polls", read("polls").filter((p) => p.id !== req.params.id));
  res.json({ ok: true });
});

app.delete("/api/results/:id", auth("admin"), (req, res) => {
  write("results", read("results").filter((r) => r.id !== req.params.id));
  res.json({ ok: true });
});

app.delete("/api/results", auth("admin"), (_req, res) => {
  write("results", []);
  res.json({ ok: true });
});
app.listen(5000, () => console.log("Backend running: http://localhost:5000"));
/* =========================================================
   SIMULATED breach dataset — for educational/demo purposes only.
   None of this is real breach data. Matching is done by simple
   string lookup against these fictional entries.
   ========================================================= */

const BREACH_DATASET = [
  {
    name: "ShopKart Marketplace",
    date: "2024-03-11",
    exposed: ["email", "password (hashed)", "phone"],
    severity: "high",
    records: "18.2M",
    identifiers: ["priya.g@example.com", "test@mail.com", "arjun_k99"]
  },
  {
    name: "QuizZone Trivia App",
    date: "2023-11-02",
    exposed: ["username", "email", "date of birth"],
    severity: "medium",
    records: "2.4M",
    identifiers: ["arjun_k99", "test@mail.com"]
  },
  {
    name: "FitTrack Wellness",
    date: "2025-01-19",
    exposed: ["email", "password (plaintext)", "location history"],
    severity: "critical",
    records: "640K",
    identifiers: ["priya.g@example.com"]
  },
  {
    name: "CampusConnect Forum",
    date: "2022-08-27",
    exposed: ["username", "email", "IP address"],
    severity: "low",
    records: "980K",
    identifiers: ["test@mail.com", "arjun_k99"]
  },
  {
    name: "RapidCourier Logistics",
    date: "2024-09-05",
    exposed: ["email", "phone", "home address"],
    severity: "high",
    records: "5.1M",
    identifiers: ["priya.g@example.com", "arjun_k99"]
  },
  {
    name: "PixelStream Media",
    date: "2023-05-14",
    exposed: ["email", "password (hashed)"],
    severity: "medium",
    records: "3.7M",
    identifiers: ["test@mail.com"]
  }
];

const COMMON_PASSWORDS = [
  "123456", "password", "123456789", "12345678", "12345",
  "qwerty", "abc123", "password1", "111111", "iloveyou",
  "admin", "welcome", "letmein", "monkey", "football",
  "1234567", "sunshine", "princess", "dragon", "qwerty123"
];
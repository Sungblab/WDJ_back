const express = require("express");
const http = require("http");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const cors = require("cors");
const { body, validationResult } = require("express-validator");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const crypto = require("crypto");
dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS 설정
app.use(
  cors({
    origin: process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(",")
      : ["https://wdj.kr", "https://wdjhs.netlify.app"],
    credentials: true,
  })
);

// JWT_SECRET 환경변수 확인 및 설정
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("Error: JWT_SECRET is not set in environment variables.");
  process.exit(1);
}

// MongoDB 연결
const mongoURI = process.env.MONGODB_URI;
if (!mongoURI) {
  console.error("Error: MONGODB_URI is not set in environment variables.");
  process.exit(1);
}

mongoose
  .connect(mongoURI)
  .then(() => console.log("MongoDB 연결 성공 - " + mongoURI))
  .catch((err) => console.error("MongoDB 연결 실패:", err));

// 사용자 모델 정의
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  realName: { type: String, required: true },
  nickname: { type: String, required: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  isAdmin: { type: Boolean, default: false },
  isApproved: { type: Boolean, default: false },
});

const User = mongoose.model("User", UserSchema);

// JWT 검증 미들웨어 수정
const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        message: "인증 토큰이 필요합니다.",
        redirectTo: "/index.html",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await User.findById(decoded.id).select("-password");
    if (!user) {
      return res.status(403).json({
        message: "유효하지 않은 사용자입니다.",
        redirectTo: "/index.html",
      });
    }

    if (!user.isApproved) {
      return res.status(403).json({
        message: "승인되지 않은 사용자입니다.",
        redirectTo: "/index.html",
      });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "토큰이 만료되었습니다.",
        redirectTo: "/index.html",
      });
    }
    return res.status(403).json({
      message: "유효하지 않은 토큰입니다.",
      redirectTo: "/index.html",
    });
  }
};

// 관리자 확인 미들웨어
const isAdmin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ message: "관리자 권한이 필요합니다." });
  }
};

// 미들웨어: 게시판 접근 권한 확인
const checkBoardAccess = (req, res, next) => {
  const { board } = req.params;

  console.log("Checking board access:", {
    board,
    isAdmin: req.user.isAdmin,
  });

  if (board === "all" || req.user.isAdmin) {
    console.log("Access granted: all board or admin");
    return next();
  }

  console.log("Access denied");
  res.status(403).json({ message: "접근 권한이 필요합니다." });
};

// JWT 토큰 생성 함수 수정
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      username: user.username,
      isAdmin: user.isAdmin,
    },
    JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || "1h",
      algorithm: "HS256",
    }
  );
};

// 로그인 API
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({
        message: "사용자명 또는 비밀번호가 일치하지 않습니다.",
      });
    }

    if (!user.isApproved) {
      return res.status(403).json({
        message: "관리자의 승인을 기다리고 있습니다.",
      });
    }

    const token = generateToken(user);

    // httpOnly 쿠키로 토큰 전송
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 3600000, // 1시간
    });

    // 응답에 토큰도 함께 함
    res.json({
      message: "로그인 성공",
      token: token, // 토큰을 응답에 포함
      user: {
        id: user._id,
        username: user.username,
        nickname: user.nickname,
        isAdmin: user.isAdmin,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 관리자 로그인 API
app.post("/api/auth/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({
        message: "사용자명 또는 비밀번호가 일치하지 않습니다.",
      });
    }

    if (!user.isAdmin) {
      return res.status(403).json({
        message: "관리자 권한이 없습니다.",
      });
    }

    const token = generateToken(user);

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 3600000, // 1시간
    });

    res.json({
      message: "관리자 로그인 성공",
      token: token,
      user: {
        id: user._id,
        username: user.username,
        nickname: user.nickname,
        isAdmin: user.isAdmin,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 사용자 등록 API
app.post(
  "/api/register",
  [
    body("username")
      .notEmpty()
      .withMessage("학번/아이디를 입력해주세요.")
      .isLength({ min: 4 })
      .withMessage("학번/아이디는 최소 4자 이상이어야 합니다.")
      .custom((value) => {
        if (isNaN(value) || value.length !== 4) {
          throw new Error("유효하지 않은 학번입니다.");
        }
        return true;
      }),
    body("realName").notEmpty().withMessage("실명을 입력해주세요."),
    body("nickname").notEmpty().withMessage("닉네임을 입력해주세요."),
    body("password")
      .notEmpty()
      .withMessage("비밀번호를 입력해주세요.")
      .isLength({ min: 6 })
      .withMessage("비밀번호는 최소 6자 이상이어야 합니다."),
    body("email")
      .notEmpty()
      .withMessage("이메일 주소를 입력해주세요.")
      .isEmail()
      .withMessage("유효한 이메일 주소를 입력해주세요."),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, realName, nickname, password, email } = req.body;

      let user = await User.findOne({ $or: [{ username }, { email }] });
      if (user) {
        return res
          .status(400)
          .json({ message: "이미 존재하는 학번/아이디 또는 이메일입니다." });
      }

      user = new User({
        username,
        realName,
        nickname,
        password: await bcrypt.hash(password, 10),
        email,
        isApproved: false,
      });

      await user.save();

      res.status(201).json({
        message:
          "사용자 등록 요청이 완료되었습니다. 관리자의 승인을 기다려주세요.",
      });
    } catch (error) {
      next(error);
    }
  }
);

// 사용자 정보 가져오기 API
app.get("/api/user", authenticateToken, async (req, res) => {
  console.log("User info request received for user ID:", req.user.id);
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      console.log("User not found for ID:", req.user.id);
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
    console.log("User info retrieved:", user);
    res.json(user);
  } catch (error) {
    console.error("Error retrieving user info:", error);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 보호된 라우트 예시
app.get("/api/protected", authenticateToken, (req, res) => {
  res.json({ message: "인증된 사용자만 접근 가능한 데이터입니다." });
});

// 관리자용 사용자 목록 조회 API
app.get("/api/admin/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, "-password");
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: "서버 오류" });
  }
});

// 사용자 삭제 API
app.delete(
  "/api/users/:userId",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const userId = req.params.userId;
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }
      await User.findByIdAndDelete(userId);
      res.json({ message: "사용자가 성공적으로 삭제되었습��다." });
    } catch (error) {
      console.error("사용자 삭제 중 오류 발생:", error);
      res.status(500).json({ message: "서버 오류" });
    }
  }
);

// 관리자 권한 토글 API
app.patch(
  "/api/users/:userId/admin",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const userId = req.params.userId;
      const { isAdmin } = req.body;
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }
      user.isAdmin = isAdmin;
      await user.save();
      res.json({
        message: `사용자의 관리자 권한이 ${
          isAdmin ? "부여" : "해제"
        }되었습니다.`,
      });
    } catch (error) {
      console.error("관리자 권한 변경 중 오류 발생:", error);
      res.status(500).json({ message: "서버 오류" });
    }
  }
);

// 승인 대기 중인 사용자 목록 조회 API
app.get(
  "/api/admin/users/pending",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const pendingUsers = await User.find({ isApproved: false }, "-password");
      res.json(pendingUsers);
    } catch (error) {
      console.error("Error fetching pending users:", error);
      res.status(500).json({ message: "서버 오류" });
    }
  }
);

// 사용자 승인 API
app.patch(
  "/api/admin/users/:userId/approve",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const userId = req.params.userId;
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }
      user.isApproved = true;
      await user.save();
      res.json({ message: "사용자가 승인되었습니다." });
    } catch (error) {
      console.error("Error approving user:", error);
      res.status(500).json({ message: "서버 오류" });
    }
  }
);

// 전역 에러 핸들러
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res
    .status(500)
    .json({ message: "서버 내부 오류가 발생했습니다.", error: err.message });
});

app.listen(PORT, () => {
  console.log(`서버가 포트 ${PORT}에서 실행 중입니다.`);
});

// Notice 모델 정의
const NoticeSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: String, default: "관리자" }, // 작성자를 "관리자"로 고정
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  important: { type: Boolean, default: false },
});

const Notice = mongoose.model("Notice", NoticeSchema);

// 공지사항 목록 조회 API
app.get("/api/notices", async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const notices = await Notice.find()
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .populate("author", "username");
    const total = await Notice.countDocuments();
    res.json({
      notices,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
    });
  } catch (error) {
    console.error("공지사항 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 공지사항 생성 API 수정
app.post("/api/notices", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { title, content, important } = req.body;

    const notice = new Notice({
      title,
      content,
      important,
      // author 필드는 기본값인 "관리자"로 설정됨
    });
    await notice.save();
    res.status(201).json({ message: "공지사항이 생성되었습니다.", notice });
  } catch (error) {
    console.error("공지사항 생성 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 공지사항 조회 API
app.get("/api/notices/:id", async (req, res) => {
  try {
    const notice = await Notice.findById(req.params.id);
    if (!notice) {
      return res.status(404).json({ message: "공지사항을 찾을 수 없습니다." });
    }
    res.json(notice);
  } catch (error) {
    console.error("공지사항 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 공지사항 목록 조회 API
app.get("/api/notices", async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const notices = await Notice.find()
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
      .select("title content department author createdAt");
    const total = await Notice.countDocuments();
    res.json({
      notices,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
    });
  } catch (error) {
    console.error("공지사항 목록 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 공지사항 수정 API
app.put("/api/notices/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { title, content, important } = req.body;
    const notice = await Notice.findByIdAndUpdate(
      req.params.id,
      { title, content, important, updatedAt: Date.now() },
      { new: true }
    );
    if (!notice) {
      return res.status(404).json({ message: "공지사항을 찾을 수 없습니다." });
    }
    res.json({ message: "공지사항이 수정되었습니다.", notice });
  } catch (error) {
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 공지사항 삭제 API
app.delete("/api/notices/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const notice = await Notice.findByIdAndDelete(req.params.id);
    if (!notice) {
      return res.status(404).json({ message: "공지사항을 찾을 수 없습니다." });
    }
    res.json({ message: "공지사항이 삭제되었습니다." });
  } catch (error) {
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 비밀번호 초기화 API
app.post(
  "/api/admin/users/:userId/reset-password",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const userId = req.params.userId;
      const { newPassword } = req.body;

      if (!newPassword) {
        return res
          .status(400)
          .json({ message: "새 비밀번호가 제공되지 않았습니다." });
      }

      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }

      // 비밀번호 해싱
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();

      res.json({ message: "비밀번호가 성공적으로 초기화되었습니다." });
    } catch (error) {
      console.error("비밀번호 초기화 중 오류 발생:", error);
      res.status(500).json({
        message: "서버 오류 비밀번호 초기화 중 오류 발생:",
        error: error.message,
      });
    }
  }
);

// 비밀번호 변경 API
app.post("/api/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    console.log("비밀번호 변경 요청 음 :", userId);

    // 사용자 조회
    const user = await User.findById(userId);
    if (!user) {
      console.log("사용자를 찾을 수 없음:", userId);
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    console.log("사용자 찾음:", user.username);

    // 현재 비밀번호 확인
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      console.log("현재 비밀번호 불일치:", user.username);
      return res
        .status(400)
        .json({ message: "현재 비밀번호가 일치하지 않습니다." });
    }

    console.log("현재 비밀번호 확인 완료");

    // 새 비밀번호 해싱
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 비밀번호 업데이트
    user.password = hashedPassword;
    await user.save();

    console.log("비밀번호 변경 성공:", user.username);

    res.json({ message: "비밀번호가 성공적으로 변경되었습니다." });
  } catch (error) {
    console.error("비밀번호 변경 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 청원 모델 정의
const PetitionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  supporters: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  status: {
    type: String,
    enum: ["pending", "active", "expired", "rejected"],
    default: "pending",
  },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date },
});

const Petition = mongoose.model("Petition", PetitionSchema);

// 청원 생성 API
app.post("/api/petitions", authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const author = req.user.id;

    const petition = new Petition({
      title,
      content,
      author,
      expiresAt: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000), // 20일 ��� 만료
    });

    await petition.save();
    res
      .status(201)
      .json({ message: "청원이 성공적으로 생성되었습니다.", petition });
  } catch (error) {
    console.error("청원 생성 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 청원 목목록 조회 API
app.get("/api/petitions", authenticateToken, async (req, res) => {
  try {
    const { status } = req.query;
    let query = {};

    if (status) {
      query.status = status;
    }

    const petitions = await Petition.find(query)
      .sort({ createdAt: -1 })
      .populate("author", "username")
      .select("title content author supporters status createdAt");

    res.json({ petitions });
  } catch (error) {
    console.error("청원 목록 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 청원 상세 조회 API
app.get("/api/petitions/:id", authenticateToken, async (req, res) => {
  try {
    const petition = await Petition.findById(req.params.id)
      .populate("author", "username")
      .populate("supporters", "username");

    if (!petition) {
      return res.status(404).json({ message: "청원을 찾을 수 없습니다." });
    }

    res.json(petition);
  } catch (error) {
    console.error("청원 상세 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 청원 지지 API
app.post("/api/petitions/:id/support", authenticateToken, async (req, res) => {
  try {
    const petition = await Petition.findById(req.params.id);

    if (!petition) {
      return res.status(404).json({ message: "청원을 찾을 수 없습니다." });
    }

    if (petition.status !== "active") {
      return res
        .status(400)
        .json({ message: "성 상태의 청원만 지지할 수 있습니다." });
    }

    if (petition.supporters.includes(req.user.id)) {
      return res.status(400).json({ message: "이미 이 원을 지지하셨습니다." });
    }

    petition.supporters.push(req.user.id);
    await petition.save();

    res.json({
      message: "청원 지지가 완료되었습니다.",
      supportersCount: petition.supporters.length,
    });
  } catch (error) {
    console.error("청원 지 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 청원 상태 변경 API (관리자용)
app.patch(
  "/api/petitions/:id/status",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { status } = req.body;
      const petition = await Petition.findByIdAndUpdate(
        req.params.id,
        { status },
        { new: true }
      );

      if (!petition) {
        return res.status(404).json({ message: "청원원을 찾을 수 없습니다." });
      }

      res.json({ message: "청원 상태가 업데이트되었습니다.", petition });
    } catch (error) {
      console.error("청원 상태 변경 중 오류 발생:", error);
      res.status(500).json({ message: "서버 오류", error: error.message });
    }
  }
);

// 청원 만료 체크 함수
async function checkExpiredPetitions() {
  try {
    const expiredPetitions = await Petition.find({
      status: "active",
      expiresAt: { $lte: new Date() },
    });

    for (const petition of expiredPetitions) {
      petition.status = "expired";
      await petition.save();
    }

    console.log(`${expiredPetitions.length}개의 청원이 만료되었습니다.`);
  } catch (error) {
    console.error("청원 만료 체크 중 오류 발생:", error);
  }
}

// 청원 삭제 API (관리자용)
app.delete(
  "/api/petitions/:id",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const petition = await Petition.findByIdAndDelete(req.params.id);

      if (!petition) {
        return res.status(404).json({ message: "청원을 찾을 수 없습니다." });
      }

      res.json({ message: "청원이 성공적으로 삭제되었습니다." });
    } catch (error) {
      console.error("청원 삭제 중 오류:", error);
      res.status(500).json({ message: "서버 오류", error: error.message });
    }
  }
);

// 매일 자정에 청원 만료 체크 실행
setInterval(checkExpiredPetitions, 24 * 60 * 60 * 1000);

// 서버 시작 시 한 번 실행
checkExpiredPetitions();

// IP 주소 마스킹 함수 수정
function maskIP(ip) {
  if (!ip) return "";
  // IPv6 형식(::ffff:127.0.0.1)에서 IPv4 부분만 추출
  const ipv4Match = ip.match(/(?::(\d+\.\d+\.\d+\.\d+))$/);
  const ipv4 = ipv4Match ? ipv4Match[1] : ip;

  const parts = ipv4.split(".");
  if (parts.length !== 4) return "";
  return `${parts[0]}.${parts[1]}`; // 앞의 부분만 표시
}

// ��짜 포맷팅 함수 수정
function formatDate(dateString) {
  try {
    const date = new Date(dateString);

    // 유효한 날짜인지 확확인
    if (isNaN(date.getTime())) {
      return "날짜 없음";
    }

    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, "0");
    const day = String(date.getDate()).padStart(2, "0");
    const hours = String(date.getHours()).padStart(2, "0");
    const minutes = String(date.getMinutes()).padStart(2, "0");

    return `${year}-${month}-${day} ${hours}:${minutes}`;
  } catch (error) {
    console.error("Date formatting error:", error);
    return "날짜 오류";
  }
}

// 사용자 목록 렌더링 함수 수정
function renderUsers(users) {
  const tbody = document.getElementById("userList");
  tbody.innerHTML = "";

  users.forEach((user) => {
    const tr = document.createElement("tr");
    tr.className = "border-b border-gray-700 hover:bg-gray-800";

    // createdAt이 존재하는지 확인하고 포맷팅
    const formattedDate = user.createdAt
      ? formatDate(user.createdAt)
      : "날짜 없음";

    tr.innerHTML = `
      <td class="p-3">
        <input type="checkbox" class="user-checkbox rounded bg-gray-700 border-gray-600"
          value="${user._id}" ${selectedUsers.has(user._id) ? "checked" : ""}>
      </td>
      <td class="p-3 text-gray-300">${user.username}</td>
      <td class="p-3 text-gray-300">${user.realName}</td>
      <td class="p-3 text-gray-300">${user.email}</td>
      <td class="p-3 text-gray-300">${formattedDate}</td>
      <td class="p-3">
        <span class="px-2 py-1 rounded-full text-xs ${
          user.isApproved
            ? "bg-green-500 text-white"
            : "bg-yellow-500 text-white"
        }">
          ${user.isApproved ? "승인됨" : "대기중"}
        </span>
      </td>
      <td class="p-3">
        <span class="px-2 py-1 rounded-full text-xs ${
          user.isAdmin ? "bg-blue-500 text-white" : "bg-gray-500 text-white"
        }">
          ${user.isAdmin ? "관리자" : "일반"}
        </span>
      </td>
      <td class="p-3">
        <div class="flex space-x-2">
          <button class="admin-btn bg-red-600 text-white px-3 py-1 rounded-lg text-sm hover:bg-red-700"
            onclick="deleteUser('${user._id}')">
            삭제
          </button>
          <button class="admin-btn bg-yellow-600 text-white px-3 py-1 rounded-lg text-sm hover:bg-yellow-700"
            onclick="toggleAdmin('${user._id}', ${user.isAdmin})">
            ${user.isAdmin ? "관리자 해제" : "관리자 지정"}
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// 게시글 목록 모델 정의
const PostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  board: { type: String, required: true },
  views: { type: Number, default: 0 },
  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Comment" }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  isAnonymous: { type: Boolean, default: false },
  anonymousNick: { type: String },
  anonymousPassword: { type: String },
  ipAddress: { type: String },
  upvoteCount: { type: Number, default: 0 },
  downvoteCount: { type: Number, default: 0 },
  score: { type: Number, default: 0 },
});

// 투표 처리 시 사용할 가상 필드 추가
PostSchema.virtual("voteCount").get(function () {
  return {
    upvotes: this.upvoteCount || 0,
    downvotes: this.downvoteCount || 0,
    score: (this.upvoteCount || 0) - (this.downvoteCount || 0),
  };
});

const Post = mongoose.model("Post", PostSchema);

// 댓글 모델 정의
const CommentSchema = new mongoose.Schema({
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // optional for anonymous
  post: { type: mongoose.Schema.Types.ObjectId, ref: "Post", required: true },
  createdAt: { type: Date, default: Date.now },
  isAnonymous: { type: Boolean, default: false },
  anonymousNick: { type: String },
  anonymousPassword: { type: String },
  ipAddress: { type: String },
  isDeleted: { type: Boolean, default: false },
  deletedAt: { type: Date },
  deletedBy: { type: String },
  lastEditedAt: { type: Date },
  editCount: { type: Number, default: 0 },
});

const Comment = mongoose.model("Comment", CommentSchema);

// 보안 헤더 설정
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  next();
});

// 환경변수에 NEIS API 키키 추가
const NEIS_API_KEY = process.env.NEIS_API_KEY;
const SCHOOL_CODE = "8490065";
const OFFICE_CODE = "Q10";

// 급식 정보 조회 API
app.get("/api/meals", async (req, res) => {
  try {
    const { date } = req.query;
    const response = await axios.get(
      "https://open.neis.go.kr/hub/mealServiceDietInfo",
      {
        params: {
          KEY: NEIS_API_KEY,
          Type: "json",
          ATPT_OFCDC_SC_CODE: OFFICE_CODE,
          SD_SCHUL_CODE: SCHOOL_CODE,
          MLSV_YMD: date,
        },
      }
    );

    // NEIS API가 데이터가 없을 때 RESULT 객체를 반환하는 경우 처리
    if (response.data.RESULT?.CODE === "INFO-200") {
      // 데이터가 없는 경우 빈 배열 반환
      return res.json([]);
    }

    const meals = response.data.mealServiceDietInfo
      ? response.data.mealServiceDietInfo[1].row
      : [];

    res.json(meals);
  } catch (error) {
    console.error("급식 정보 조회 중 오류:", error);
    // 오류 발생 시에도 빈 배열 반환
    res.json([]);
  }
});

// 학사일정 조회 API
app.get("/api/schedule", async (req, res) => {
  try {
    const { year, month } = req.query;
    const fromDate = `${year}${String(month).padStart(2, "0")}01`;
    const toDate = `${year}${String(month).padStart(2, "0")}${new Date(
      year,
      month,
      0
    ).getDate()}`;

    const response = await axios.get(
      "https://open.neis.go.kr/hub/SchoolSchedule",
      {
        params: {
          KEY: NEIS_API_KEY,
          Type: "json",
          ATPT_OFCDC_SC_CODE: OFFICE_CODE,
          SD_SCHUL_CODE: SCHOOL_CODE,
          AA_FROM_YMD: fromDate,
          AA_TO_YMD: toDate,
        },
      }
    );

    // NEIS API가 데이터가 없을 때 RESULT 객체를 반환하는 경우 처리
    if (response.data.RESULT?.CODE === "INFO-200") {
      // 데이터가 없는 경우 빈 배열 반환
      return res.json([]);
    }

    const schedules = response.data.SchoolSchedule
      ? response.data.SchoolSchedule[1].row
      : [];

    res.json(schedules);
  } catch (error) {
    console.error("학사일정 조회 중 오류:", error);
    // 오류 발생 시 빈 배열 반환
    res.json([]);
  }
});

// processPost 함수 수정
function processPost(post) {
  return {
    ...post,
    ipAddress: post.isAnonymous ? maskIP(post.ipAddress) : null,
    author: post.isAnonymous
      ? { nickname: post.anonymousNick || "익명" }
      : post.author || { nickname: "익명" },
    score: (post.upvoteIPs?.length || 0) - (post.downvoteIPs?.length || 0),
    upvotes: post.upvoteIPs?.length || 0,
    downvotes: post.downvoteIPs?.length || 0,
  };
}

// 게시글 목록 조회 API
app.get("/api/posts", async (req, res) => {
  try {
    const { page = 1, limit = 15, board = "all", sort = "latest" } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (board !== "all") {
      query.board = board;
    }

    // 정렬 옵션
    let sortOption = {};
    switch (sort) {
      case "oldest":
        sortOption = { createdAt: 1 };
        break;
      case "best":
        sortOption = { score: -1 };
        break;
      case "views":
        sortOption = { views: -1 };
        break;
      default: // latest
        sortOption = { createdAt: -1 };
    }

    // 일주일 내 게시글 중 추천수 상위 3개 조회
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const bestPosts = await Post.find({
      ...query,
      createdAt: { $gte: oneWeekAgo },
      score: { $gt: 0 },
    })
      .sort({ score: -1 })
      .limit(3)
      .populate("author", "username nickname")
      .lean();

    // 일반 게시글 검색
    const posts = await Post.find(query)
      .sort(sortOption)
      .skip(skip)
      .limit(Number(limit))
      .populate("author", "username nickname")
      .lean();

    // 전체 게시글 수 계산
    const totalPosts = await Post.countDocuments(query);

    // 검검색 결과 처리
    const processedBestPosts = bestPosts.map((post) => ({
      ...post,
      ipAddress: post.isAnonymous ? maskIP(post.ipAddress) : null,
      author: post.isAnonymous
        ? { nickname: post.anonymousNick || "익명" }
        : post.author,
      score: post.score,
      upvotes: post.upvotes,
      downvotes: post.downvotes,
    }));

    const processedPosts = posts.map((post) => ({
      ...post,
      ipAddress: post.isAnonymous ? maskIP(post.ipAddress) : null,
      author: post.isAnonymous
        ? { nickname: post.anonymousNick || "익명" }
        : post.author,
      score: post.score || 0,
      upvotes: post.upvoteCount || 0,
      downvotes: post.downvoteCount || 0,
    }));

    res.json({
      bestPosts: processedBestPosts,
      posts: processedPosts,
      currentPage: Number(page),
      totalPages: Math.ceil(totalPosts / limit),
      totalPosts,
    });
  } catch (error) {
    console.error("게시글 목록 조회 중 오류:", error);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 게시글 상성 조회 API 추가
app.get("/api/posts/:id", async (req, res) => {
  try {
    const postId = req.params.id;

    // ObjectId 유효성 검사
    if (!mongoose.Types.ObjectId.isValid(postId)) {
      return res
        .status(400)
        .json({ message: "유효하지 않은 게시글 ID입니다." });
    }

    const clientIP = req.ip;
    const post = await Post.findById(postId)
      .populate("author", "username nickname realName")
      .populate({
        path: "comments",
        populate: { path: "author", select: "username nickname" },
      });

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    // 조회수 증가 (IP 기반)
    if (!post.viewIPs?.includes(clientIP)) {
      post.views = (post.views || 0) + 1;
      if (!post.viewIPs) post.viewIPs = [];
      post.viewIPs.push(clientIP);
      await post.save();
    }

    // 응답 데이터 가공
    const processedPost = {
      ...post.toObject(),
      ipAddress: post.isAnonymous ? maskIP(post.ipAddress) : null,
      author: post.isAnonymous
        ? { nickname: post.anonymousNick || "익명" }
        : {
            username: post.author?.username,
            nickname: post.author?.nickname,
            realName: post.author?.realName,
          },
      comments: post.comments.map((comment) => ({
        ...comment.toObject(),
        ipAddress: comment.isAnonymous ? maskIP(comment.ipAddress) : null,
        author: comment.isAnonymous
          ? { nickname: comment.anonymousNick || "익명" }
          : comment.author,
      })),
    };

    res.json(processedPost);
  } catch (error) {
    console.error("게시글 조회 중 오류:", error);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 게시글 수정 API
app.put("/api/posts/:id", authenticateToken, async (req, res) => {
  try {
    const { title, content, password } = req.body;
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    // 관리자는 모든 게시글 수정 가능 (비밀번호 체크 없이)
    const isAdmin = req.user && req.user.isAdmin;

    if (isAdmin) {
      // 관리자는 즉시 수정 가능
      post.title = title;
      post.content = content;
      post.updatedAt = new Date();
      await post.save();
      return res.json({ message: "게시글이 수정되었습니다." });
    }

    // 일반 사용자 권한 체크
    if (post.isAnonymous) {
      if (
        !password ||
        !(await bcrypt.compare(password, post.anonymousPassword))
      ) {
        return res
          .status(403)
          .json({ message: "비밀번호가 일치하지 않습니다." });
      }
    } else if (
      !req.user ||
      post.author.toString() !== req.user._id.toString()
    ) {
      return res.status(403).json({ message: "수정 권한이 없습니다." });
    }

    // 권한 체크 통과 후 수정
    post.title = title;
    post.content = content;
    post.updatedAt = new Date();
    await post.save();

    res.json({ message: "게시글이 수정되었습니다." });
  } catch (error) {
    console.error("게시글 수정 중 오류:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 게시글 삭제 API
app.delete("/api/posts/:id", async (req, res) => {
  try {
    const { password } = req.body;
    const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    let isAuthorized = false;

    // 토큰이 있는 경우 (로그인 사용자)
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);

        // 관리자이거나 자신의 게시글인 경우 권한 부여
        if (
          user &&
          (user.isAdmin ||
            (post.author && post.author.toString() === user._id.toString()))
        ) {
          isAuthorized = true;
        }
      } catch (error) {
        console.error("Token verification failed:", error);
      }
    }

    // 익명 게시글인 경우 비밀번호 확인
    if (!isAuthorized && post.isAnonymous) {
      if (!password) {
        return res.status(400).json({ message: "비밀번호를 입력해주세요." });
      }
      const isPasswordValid = await bcrypt.compare(
        password,
        post.anonymousPassword
      );
      if (!isPasswordValid) {
        return res
          .status(403)
          .json({ message: "비밀번호가 일치하지 않습니다." });
      }
      isAuthorized = true;
    }

    if (!isAuthorized) {
      return res.status(403).json({ message: "삭제 권한이 없습니다." });
    }

    await Post.findByIdAndDelete(post._id);
    await Comment.deleteMany({ post: post._id });

    res.json({ message: "게시글이 삭제되었습니다." });
  } catch (error) {
    console.error("게시글 삭제 중 오류:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 실제 IP 가져오기 API
app.get(
  "/api/posts/:postId/ip",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const post = await Post.findById(req.params.postId);
      if (!post) {
        return res.status(404).json({
          success: false,
          message: "게시글을 찾을 수 없습니다.",
        });
      }

      // IPv6 형식에서 IPv4 추출
      const ipv4Match = post.ipAddress?.match(/(?::(\d+\.\d+\.\d+\.\d+))$/);
      const ip = ipv4Match ? ipv4Match[1] : post.ipAddress;

      res.json({
        success: true,
        ip: ip || "IP 정보 없음",
      });
    } catch (error) {
      console.error("IP 조회 실패:", error);
      res.status(500).json({
        success: false,
        message: "서버 오류",
      });
    }
  }
);

// 실제 작성자 정보 가져오기 API
app.get(
  "/api/posts/:postId/author",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const post = await Post.findById(req.params.postId).populate(
        "author",
        "username realName nickname"
      );

      if (!post) {
        return res.status(404).json({
          success: false,
          message: "게시글을 찾을 수 없습니다.",
        });
      }

      let responseData;
      if (post.isAnonymous) {
        responseData = {
          success: true,
          author: "익명",
          nickname: post.anonymousNick || "익명",
          ip: post.ipAddress || "IP 정보 없음",
        };
      } else if (post.author) {
        responseData = {
          success: true,
          author: post.author.realName || "알 수 없음",
          nickname: post.author.nickname || "알알 수 없음",
          username: post.author.username || "알 수 없음음",
        };
      } else {
        responseData = {
          success: true,
          author: "삭제된 사용자",
          nickname: "알 수 없음",
          username: "알 수 없음",
        };
      }

      res.json(responseData);
    } catch (error) {
      console.error("작성자 조회 실패:", error);
      res.status(500).json({
        success: false,
        message: "서버 오류",
      });
    }
  }
);

// 게시글 추천/비추천 API
app.post("/api/posts/:postId/vote", async (req, res) => {
  try {
    const { type } = req.body;
    const clientIP = req.ip;
    const post = await Post.findById(req.params.postId);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    // 자신의 게시글에는 투표할 수 없음
    if (post.ipAddress === clientIP) {
      return res
        .status(400)
        .json({ message: "자신의 게시글에는 투표할 수 없습니다." });
    }

    // 이미 투표했는지 확인
    const existingVote = await Vote.findOne({
      post: post._id,
      voterId: clientIP,
      isActive: true,
    });

    let updatedPost;

    if (existingVote) {
      if (existingVote.voteType === type) {
        // 같은 유형의 투표 취소
        existingVote.isActive = false;
        await existingVote.save();

        updatedPost = await Post.findByIdAndUpdate(
          post._id,
          {
            $inc: {
              [`${type}voteCount`]: -1,
              score: type === "up" ? -1 : 1,
            },
          },
          { new: true }
        );
      } else {
        // 다른 유형으로 변경
        existingVote.voteType = type;
        await existingVote.save();

        updatedPost = await Post.findByIdAndUpdate(
          post._id,
          {
            $inc: {
              [`${type}voteCount`]: 1,
              [`${type === "up" ? "down" : "up"}voteCount`]: -1,
              score: type === "up" ? 2 : -2,
            },
          },
          { new: true }
        );
      }
    } else {
      // 새로운 투표
      const vote = new Vote({
        post: post._id,
        voterId: clientIP,
        voteType: type,
      });
      await vote.save();

      updatedPost = await Post.findByIdAndUpdate(
        post._id,
        {
          $inc: {
            [`${type}voteCount`]: 1,
            score: type === "up" ? 1 : -1,
          },
        },
        { new: true }
      );
    }

    // 베스트글 체크 (10추천 이상)
    const isBest = updatedPost.score >= 10;
    if (isBest !== post.isBest) {
      updatedPost = await Post.findByIdAndUpdate(
        post._id,
        { isBest },
        { new: true }
      );
    }

    res.json({
      success: true,
      upvotes: updatedPost.upvoteCount || 0,
      downvotes: updatedPost.downvoteCount || 0,
      score: updatedPost.score || 0,
      isBest: updatedPost.isBest,
    });
  } catch (error) {
    console.error("투표 처리 중 오류:", error);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 댓글 작성 API 수정
app.post("/api/posts/:postId/comments", async (req, res) => {
  try {
    const { content, isAnonymous, anonymousNick, anonymousPassword } = req.body;
    const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
    const post = await Post.findById(req.params.postId);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    let commentData = {
      content,
      post: post._id,
      createdAt: new Date(),
      ipAddress: req.ip, // IP 주소 저장 추가
    };

    // 로그인한 사용자인 경우
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (user) {
          commentData.author = user._id;
          commentData.isAnonymous = false;
        }
      } catch (error) {
        console.error("Token verification failed:", error);
      }
    } else {
      // 비로그인 사용자인 경우
      if (!anonymousPassword) {
        return res
          .status(400)
          .json({ message: "익명 게시글 작성 시 비밀번호는 필수입니다." });
      }
      commentData.isAnonymous = true;
      commentData.anonymousNick = anonymousNick || "익명";
      commentData.anonymousPassword = await bcrypt.hash(anonymousPassword, 10);
      commentData.ipAddress = req.ip;
    }

    const comment = new Comment(commentData);
    await comment.save();

    // 게시글의 댓글 목록에 추가
    post.comments.push(comment._id);
    await post.save();

    // 생성된 댓글 정보를 가져와서 응답
    const populatedComment = await Comment.findById(comment._id).populate(
      "author",
      "username nickname"
    );

    const processedComment = {
      ...populatedComment.toObject(),
      ipAddress: populatedComment.isAnonymous
        ? maskIP(populatedComment.ipAddress)
        : null,
      author: populatedComment.isAnonymous
        ? { nickname: populatedComment.anonymousNick || "익명" }
        : populatedComment.author,
    };

    res.status(201).json({
      success: true,
      comment: processedComment,
    });
  } catch (error) {
    console.error("댓글 작성 중 오류:", error);
    res.status(500).json({ success: false, message: "서버 오류" });
  }
});

// 댓글 삭제 API 수정
app.delete("/api/comments/:commentId", async (req, res) => {
  try {
    const { password } = req.body;
    const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
    const comment = await Comment.findById(req.params.commentId);

    if (!comment) {
      return res.status(404).json({ message: "댓글을 찾을 수 없습니다." });
    }

    let isAuthorized = false;

    // 토큰이 있는 경우 (로그인 사용자)
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);

        // 관리자이거나 자신의 댓글인 경우 권한 부여
        if (
          user &&
          (user.isAdmin ||
            (comment.author &&
              comment.author.toString() === user._id.toString()))
        ) {
          isAuthorized = true;
        }
      } catch (error) {
        console.error("Token verification failed:", error);
      }
    }

    // 익명 댓글인 경우 비밀번호 확인
    if (!isAuthorized && comment.isAnonymous) {
      if (!password) {
        return res.status(400).json({ message: "비밀번호를 입력해주세요." });
      }
      const isPasswordValid = await bcrypt.compare(
        password,
        comment.anonymousPassword
      );
      if (!isPasswordValid) {
        return res
          .status(403)
          .json({ message: "비밀번호가 일치하지 않습니다." });
      }
      isAuthorized = true;
    }

    if (!isAuthorized) {
      return res.status(403).json({ message: "삭제 권한이 없습니다." });
    }

    // 댓글 삭제 및 게시글에서 댓글 ID 제거
    await Comment.findByIdAndDelete(comment._id);
    await Post.updateOne(
      { _id: comment.post },
      { $pull: { comments: comment._id } }
    );

    res.json({ message: "댓글이 삭제되었습니다." });
  } catch (error) {
    console.error("댓글 삭제 중 오류:", error);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 게시글 비밀번호 검증 API 추가
app.post("/api/posts/:id/verify-password", async (req, res) => {
  try {
    const { password } = req.body;
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    if (!post.isAnonymous) {
      return res.status(400).json({ message: "익명 게시글 아닙니다." });
    }

    if (!password) {
      return res.status(400).json({ message: "비밀번호를 입력해주세요." });
    }

    const isPasswordValid = await bcrypt.compare(
      password,
      post.anonymousPassword
    );
    if (!isPasswordValid) {
      return res.status(403).json({ message: "비밀번호가 일치하지 않습니다." });
    }

    res.json({ message: "비밀번호가 확인되었었습니다." });
  } catch (error) {
    console.error("비밀번호 검증 중 오류:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 게시글 검색 API 수정
app.get("/api/posts/search", async (req, res) => {
  try {
    const { query, type, page = 1, limit = 15 } = req.query;
    const skip = (page - 1) * limit;

    // 검색 쿼리 구성
    let searchQuery = {};

    if (query) {
      switch (type) {
        case "title":
          searchQuery.title = { $regex: query, $options: "i" };
          break;
        case "content":
          searchQuery.content = { $regex: query, $options: "i" };
          break;
        case "author":
          // 작성자 검색 - 익명 닉네임과 실제 사용자 닉네임 모두 검색
          searchQuery.$or = [
            { anonymousNick: { $regex: query, $options: "i" } },
            { "author.nickname": { $regex: query, $options: "i" } },
          ];
          break;
        default: // 제목+내용 (all)
          searchQuery.$or = [
            { title: { $regex: query, $options: "i" } },
            { content: { $regex: query, $options: "i" } },
          ];
      }
    }

    // 베스트글 조회 (일주일 내 게시글 중 추천수 높은 글)
    const oneWeekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const bestPosts = await Post.find({
      ...searchQuery,
      createdAt: { $gte: oneWeekAgo },
      score: { $gt: 0 },
    })
      .sort({ score: -1 })
      .limit(4)
      .populate("author", "username nickname")
      .lean();

    // 일반 게시글 검색
    const posts = await Post.find(searchQuery)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .populate("author", "username nickname")
      .lean();

    // 전체 검색 결과 수
    const totalPosts = await Post.countDocuments(searchQuery);

    // 검검색 결과 처리
    const processedBestPosts = bestPosts.map((post) => ({
      ...post,
      ipAddress: post.isAnonymous ? maskIP(post.ipAddress) : null,
      author: post.isAnonymous
        ? { nickname: post.anonymousNick || "익명" }
        : post.author,
      score: post.score,
      upvotes: post.upvotes,
      downvotes: post.downvotes,
    }));

    const processedPosts = posts.map((post) => ({
      ...post,
      ipAddress: post.isAnonymous ? maskIP(post.ipAddress) : null,
      author: post.isAnonymous
        ? { nickname: post.anonymousNick || "익명" }
        : post.author,
      score: post.score || 0,
      upvotes: post.upvoteCount || 0,
      downvotes: post.downvoteCount || 0,
    }));

    res.json({
      bestPosts: processedBestPosts,
      posts: processedPosts,
      currentPage: Number(page),
      totalPages: Math.ceil(totalPosts / limit),
      totalPosts,
    });
  } catch (error) {
    console.error("게색 중 오류:", error);
    res.status(500).json({ message: "검색 처리 중 오류가 발생했습니다." });
  }
});

// Vote 모델 수정
const VoteSchema = new mongoose.Schema({
  post: { type: mongoose.Schema.Types.ObjectId, ref: "Post", required: true },
  voteType: { type: String, enum: ["up", "down"], required: true },
  votedAt: { type: Date, default: Date.now },
  voterId: { type: String, required: true }, // IP 주소 저장
  isActive: { type: Boolean, default: true }, // 투표 활성화 상태
});

const Vote = mongoose.model("Vote", VoteSchema);

// 게시글 추천/비추천 API 수정
app.post("/api/posts/:postId/vote", async (req, res) => {
  try {
    const { type } = req.body;
    const clientIP = req.ip;
    const post = await Post.findById(req.params.postId);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    // 자신의 게시글에는 투표할 수 없음
    if (post.ipAddress === clientIP) {
      return res
        .status(400)
        .json({ message: "자신의 게시글에는 투표할 수 없습니다." });
    }

    // 이미 투표했는지 확인
    const existingVote = await Vote.findOne({
      post: post._id,
      voterId: clientIP,
      isActive: true,
    });

    let updatedPost;

    if (existingVote) {
      if (existingVote.voteType === type) {
        // 같은 유형의 투표 취소
        existingVote.isActive = false;
        await existingVote.save();

        updatedPost = await Post.findByIdAndUpdate(
          post._id,
          {
            $inc: {
              [`${type}voteCount`]: -1,
              score: type === "up" ? -1 : 1,
            },
          },
          { new: true }
        );
      } else {
        // 다른 유형으로 변경
        existingVote.voteType = type;
        await existingVote.save();

        updatedPost = await Post.findByIdAndUpdate(
          post._id,
          {
            $inc: {
              [`${type}voteCount`]: 1,
              [`${type === "up" ? "down" : "up"}voteCount`]: -1,
              score: type === "up" ? 2 : -2,
            },
          },
          { new: true }
        );
      }
    } else {
      // 새로운 투표
      const vote = new Vote({
        post: post._id,
        voterId: clientIP,
        voteType: type,
      });
      await vote.save();

      updatedPost = await Post.findByIdAndUpdate(
        post._id,
        {
          $inc: {
            [`${type}voteCount`]: 1,
            score: type === "up" ? 1 : -1,
          },
        },
        { new: true }
      );
    }

    // 베스트글 체크 (10추천 이상)
    const isBest = updatedPost.score >= 10;
    if (isBest !== post.isBest) {
      updatedPost = await Post.findByIdAndUpdate(
        post._id,
        { isBest },
        { new: true }
      );
    }

    res.json({
      success: true,
      upvotes: updatedPost.upvoteCount || 0,
      downvotes: updatedPost.downvoteCount || 0,
      score: updatedPost.score || 0,
      isBest: updatedPost.isBest,
    });
  } catch (error) {
    console.error("투표 처리 중 오류:", error);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 댓읩인 페이지 게시글 프리뷰 API 추가
app.get("/api/posts/preview", async (req, res) => {
  try {
    // 최근 게시글 3개만 가져오기
    const posts = await Post.find()
      .sort({ createdAt: -1 })
      .limit(3)
      .populate("author", "username nickname")
      .lean();

    // 응답 데이터 가공
    const processedPosts = posts.map((post) => ({
      _id: post._id,
      title: post.title,
      author: post.isAnonymous
        ? { nickname: post.anonymousNick || "익명" }
        : post.author,
      isAnonymous: post.isAnonymous,
      createdAt: post.createdAt,
    }));

    res.json({ posts: processedPosts });
  } catch (error) {
    console.error("게시글 프리뷰 조회 중 오류:", error);
    res.status(500).json({ message: "서버 오류" });
  }
});

// 관리자 통계 API
app.get(
  "/api/admin/statistics",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const totalUsers = await User.countDocuments();
      const pendingUsers = await User.countDocuments({ isApproved: false });
      const adminUsers = await User.countDocuments({ isAdmin: true });
      const totalPosts = await Post.countDocuments();
      const totalComments = await Comment.countDocuments();
      const totalPetitions = await Petition.countDocuments();

      res.json({
        totalUsers,
        pendingUsers,
        adminUsers,
        totalPosts,
        totalComments,
        totalPetitions,
      });
    } catch (error) {
      console.error("통계 조회 중 오류:", error);
      res.status(500).json({ message: "서버 오류" });
    }
  }
);

// 관리자용 사용자 검색 API
app.get(
  "/api/auth/admin/users/search",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { page = 1, limit = 10, filter = "all", search = "" } = req.query;
      const skip = (page - 1) * limit;

      // 검색 쿼리 구성
      let query = {};

      // 필터 적용
      if (filter === "admin") {
        query.isAdmin = true;
      } else if (filter === "user") {
        query.isAdmin = false;
        query.isApproved = true;
      } else if (filter === "pending") {
        query.isApproved = false;
      }

      // 검색어 적용
      if (search) {
        query.$or = [
          { username: { $regex: search, $options: "i" } },
          { realName: { $regex: search, $options: "i" } },
          { email: { $regex: search, $options: "i" } },
        ];
      }

      // 사용자 목록 조회
      const users = await User.find(query)
        .select("-password")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(Number(limit));

      // 전체 사용자 수
      const total = await User.countDocuments(query);

      res.json({
        users,
        currentPage: Number(page),
        totalPages: Math.ceil(total / limit),
        total,
      });
    } catch (error) {
      console.error("사용자 검색 중 오류:", error);
      res.status(500).json({ message: "서버 오류" });
    }
  }
);

// 일괄 처리 API
app.post(
  "/api/admin/users/bulk",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { action, userIds } = req.body;

      if (!Array.isArray(userIds) || userIds.length === 0) {
        return res.status(400).json({ message: "선택된 사용자가 없습니다." });
      }

      if (action === "delete") {
        await User.deleteMany({ _id: { $in: userIds } });
        res.json({ message: `${userIds.length}명의 사용자가 삭제되었습니다.` });
      } else if (action === "approve") {
        await User.updateMany(
          { _id: { $in: userIds } },
          { $set: { isApproved: true } }
        );
        res.json({ message: `${userIds.length}명의 사용자가 승인되었습니다.` });
      } else {
        res.status(400).json({ message: "잘못된 작업입니다." });
      }
    } catch (error) {
      console.error("일괄 처리 중 오류:", error);
      res.status(500).json({ message: "서버 오류" });
    }
  }
);

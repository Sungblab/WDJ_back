const express = require("express");
const http = require("http");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const cors = require("cors");
const { body, validationResult } = require("express-validator");

const app = express();
const server = http.createServer(app);
const PORT = 3000;

app.use(bodyParser.json());

// CORS 설정
app.use(
  cors({
    origin: process.env.CORS_ORIGIN
      ? process.env.CORS_ORIGIN.split(",")
      : ["https://wdj.kr", "https://wdjhs.netlify.app"],
    credentials: true,
  })
);

const mongoURI = process.env.MONGODB_URI;

mongoose
  .connect(mongoURI, {})
  .then(() => console.log("MongoDB 연결 성공"))
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

// JWT_SECRET을 직접 지정
const JWT_SECRET = "eOwfeyPmLn9uUnqY";

// JWT 검증 미들웨어 수정
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log("Decoded token:", decoded);

    const user = await User.findById(decoded.id);
    if (!user) {
      console.log("User not found for id:", decoded.id);
      return res.sendStatus(403);
    }

    req.user = {
      id: user._id.toString(), // ObjectId를 문자열로 변환
      username: user.username,
      isAdmin: user.isAdmin,
    };

    console.log("Authenticated user:", req.user);
    next();
  } catch (error) {
    console.error("Authentication error:", error);
    return res.sendStatus(403);
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
  res.status(403).json({ message: "접근 권한이 없습니다." });
};

// 로그인 API
app.post(
  "/api/login",
  [
    body("username").notEmpty().withMessage("사용자명을 입력해주세요."),
    body("password").notEmpty().withMessage("비밀번호를 입력해주세요."),
  ],
  async (req, res, next) => {
    console.log("Login request received:", req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { username, password } = req.body;

      const user = await User.findOne({ username });
      if (!user) {
        console.log("User not found:", username);
        return res.status(400).json({ message: "사용자를 찾을 수 없습니다." });
      }

      if (!user.isApproved) {
        return res
          .status(403)
          .json({ message: "관리자의 승인을 기다리고 있습니다." });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.log("Password mismatch for user:", username);
        return res
          .status(400)
          .json({ message: "비밀번호가 일치하지 않습니다." });
      }

      const token = jwt.sign({ id: user._id }, JWT_SECRET, {
        expiresIn: "1h",
      });

      console.log("Login successful for user:", username);
      res.json({ message: "로그인 성공", token });
    } catch (error) {
      console.error("Error during login:", error);
      next(error);
    }
  }
);

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
      res.json({ message: "사용자가 성공적으로 삭제되었습니다." });
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

// Notice 모델 수정
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
      res.status(500).json({ message: "서버 오류", error: error.message });
    }
  }
);

// 비밀번호 변경 API
app.post("/api/change-password", authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    console.log("비밀번호 변경 요청 받음:", userId);

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
      expiresAt: new Date(Date.now() + 20 * 24 * 60 * 60 * 1000), // 20일 후 만료
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

// 청원 목록 조회 API
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
        .json({ message: "활성 상태의 청원만 지지할 수 있습니다." });
    }

    if (petition.supporters.includes(req.user.id)) {
      return res
        .status(400)
        .json({ message: "이미 이 청원을 지지하셨습니다." });
    }

    petition.supporters.push(req.user.id);
    await petition.save();

    res.json({
      message: "청원 지지가 완료되었습니다.",
      supportersCount: petition.supporters.length,
    });
  } catch (error) {
    console.error("청원 지지 중 오류 발생:", error);
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
        return res.status(404).json({ message: "청원을 찾을 수 없습니다." });
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
      console.error("청원 삭제 중 오류 발생:", error);
      res.status(500).json({ message: "서버 오류", error: error.message });
    }
  }
);

// 매일 자정에 청원 만료 체크 실행
setInterval(checkExpiredPetitions, 24 * 60 * 60 * 1000);

// 서버 시작 시 한 번 실행
checkExpiredPetitions();

// 게시글 모델
const PostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  board: { type: String, required: true },
  views: { type: Number, default: 0 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  comments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Comment" }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  isAnonymous: { type: Boolean, default: false },
});

PostSchema.index({ createdAt: -1 });
PostSchema.index({ likes: -1 });
PostSchema.index({ title: "text", content: "text" });

const Post = mongoose.model("Post", PostSchema);

// 댓글 모델
const CommentSchema = new mongoose.Schema({
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  post: { type: mongoose.Schema.Types.ObjectId, ref: "Post", required: true },
  createdAt: { type: Date, default: Date.now },
  isAnonymous: { type: Boolean, default: false },
});

const Comment = mongoose.model("Comment", CommentSchema);

// 익명 사용자 모델
const AnonymousUserSchema = new mongoose.Schema({
  nickname: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

const AnonymousUser = mongoose.model("AnonymousUser", AnonymousUserSchema);

// 로그인 API
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res
        .status(400)
        .json({ message: "사용자명 또는 비밀번호가 일치하지 않습니다." });
    }

    if (!user.isApproved) {
      return res
        .status(403)
        .json({ message: "관리자의 승인을 기다리고 있습니다." });
    }

    if (user.isBlocked) {
      return res
        .status(403)
        .json({ message: "계정이 차단되었습니다. 관리자에게 문의하세요." });
    }

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({
      token,
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

// 게시글 작성 API 수정
app.post("/api/posts", authenticateToken, async (req, res) => {
  try {
    const { title, content, board, isAnonymous } = req.body;
    const author = req.user.id;

    const post = new Post({
      title,
      content,
      author,
      board,
      isAnonymous,
    });

    await post.save();
    res.status(201).json({ message: "게시글이 작성되었습니다.", post });
  } catch (error) {
    console.error("게시글 작성 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 게시글 목록 조회 API
app.get("/api/posts", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, board } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (board) {
      query.board = board;
    }

    const posts = await Post.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .populate("author", "username nickname")
      .select("title author createdAt views likes comments isAnonymous");

    const formattedPosts = posts.map((post) => ({
      ...post.toObject(),
      author: post.isAnonymous
        ? { username: "익명", nickname: "익명" }
        : post.author,
    }));

    const total = await Post.countDocuments(query);

    res.json({
      posts: formattedPosts,
      currentPage: Number(page),
      totalPages: Math.ceil(total / limit),
      totalPosts: total,
    });
  } catch (error) {
    console.error("게시글 목록 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

app.get("/api/posts/:id", authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id)
      .populate("author", "username nickname")
      .populate({
        path: "comments",
        populate: { path: "author", select: "username nickname" },
      });

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    // 조회수 증가
    post.views += 1;
    await post.save();

    // 익명 게시물 처리 및 isAuthor 확인
    const responsePost = post.toObject();

    // 여기서 req.user.id와 post.author._id를 문자열로 변환하여 비교합니다.
    responsePost.isAuthor = req.user.id === post.author._id.toString();

    console.log("Server isAuthor check:", {
      userId: req.user.id,
      authorId: post.author._id.toString(),
      isAuthor: responsePost.isAuthor,
    });

    if (post.isAnonymous) {
      responsePost.author = { username: "익명", nickname: "익명" };
    }

    // 댓글 처리
    responsePost.comments = responsePost.comments.map((comment) => {
      const isCommentAuthor = req.user.id === comment.author._id.toString();
      if (comment.isAnonymous) {
        comment.author = { username: "익명", nickname: "익명" };
      }
      return { ...comment, isAuthor: isCommentAuthor };
    });

    res.json(responsePost);
  } catch (error) {
    console.error("게시글 상세 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 댓글 목록 조회 API
app.get("/api/posts/:id/comments", authenticateToken, async (req, res) => {
  try {
    const comments = await Comment.find({ post: req.params.id })
      .populate("author", "username nickname")
      .sort({ createdAt: -1 });

    const responseComments = comments.map((comment) => {
      const c = comment.toObject();
      c.author._id = c.author._id.toString(); // ID를 문자열로 변환
      return c;
    });

    res.json(responseComments);
  } catch (error) {
    // ...
  }
});

// 게시글 수정 API
app.put("/api/posts/:id", authenticateToken, async (req, res) => {
  try {
    const { title, content } = req.body;
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    if (post.author.toString() !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ message: "게시글 수정 권한이 없습니다." });
    }

    post.title = title;
    post.content = content;
    post.updatedAt = Date.now();

    await post.save();
    res.json({ message: "게시글이 수정되었습니다.", post });
  } catch (error) {
    console.error("게시글 수정 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 게시글 삭제 API (작성자 본인 또는 관리자만 삭제 가능)
app.delete("/api/posts/:id", authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    // 문자열로 변환하여 비교
    if (post.author.toString() === req.user.id || req.user.isAdmin) {
      await Post.findByIdAndDelete(req.params.id);
      await Comment.deleteMany({ post: req.params.id });
      return res.json({ message: "게시글이 삭제되었습니다." });
    } else {
      return res.status(403).json({ message: "게시글 삭제 권한이 없습니다." });
    }
  } catch (error) {
    console.error("게시글 삭제 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 댓글 작성 API
app.post("/api/posts/:id/comments", authenticateToken, async (req, res) => {
  try {
    const { content, isAnonymous } = req.body;
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    const comment = new Comment({
      content,
      author: req.user.id,
      post: req.params.id,
      isAnonymous,
    });

    await comment.save();
    post.comments.push(comment._id);
    await post.save();

    res.status(201).json({ message: "댓글이 작성되었습니다.", comment });
  } catch (error) {
    console.error("댓글 작성 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 댓글 삭제 API 수정
app.delete("/api/comments/:id", authenticateToken, async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.id);
    if (!comment) {
      return res.status(404).json({ message: "댓글을 찾을 수 없습니다." });
    }

    // 문자열로 변환하여 비교
    if (comment.author.toString() === req.user.id || req.user.isAdmin) {
      await Comment.findByIdAndDelete(req.params.id);
      await Post.findByIdAndUpdate(comment.post, {
        $pull: { comments: comment._id },
      });
      return res.json({ message: "댓글이 삭제되었습니다." });
    } else {
      return res.status(403).json({ message: "댓글 삭제 권한이 없습니다." });
    }
  } catch (error) {
    console.error("댓글 삭제 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 게시글 좋아요 API
app.post("/api/posts/:id/like", authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);

    if (!post) {
      return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
    }

    const index = post.likes.indexOf(req.user.id);
    if (index > -1) {
      // 이미 좋아요를 눌렀다면 취소
      post.likes.splice(index, 1);
    } else {
      // 좋아요 추가
      post.likes.push(req.user.id);
    }

    await post.save();
    res.json({
      message: "좋아요 상태가 변경되었습니다.",
      likes: post.likes.length,
    });
  } catch (error) {
    console.error("좋아요 처리 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 인기 게시글 조회 API
app.get("/api/posts/popular", authenticateToken, async (req, res) => {
  try {
    const popularPosts = await Post.find()
      .sort({ likes: -1 })
      .limit(5)
      .populate("author", "username nickname")
      .select("title author createdAt views likes");

    res.json(popularPosts);
  } catch (error) {
    console.error("인기 게시글 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 게시글 검색 API
app.get("/api/search", authenticateToken, async (req, res) => {
  try {
    const { query, board } = req.query;
    let searchCondition = { $text: { $search: query } };
    if (board && board !== "all") {
      searchCondition.board = board;
    }
    const posts = await Post.find(searchCondition)
      .sort({ createdAt: -1 })
      .limit(20)
      .populate("author", "username nickname");
    res.json(posts);
  } catch (error) {
    console.error("게시글 검색 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류", error: error.message });
  }
});

// 관리자: 사용자 승인 API
app.post(
  "/api/admin/users/:id/approve",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const user = await User.findByIdAndUpdate(
        req.params.id,
        { isApproved: true },
        { new: true }
      );
      if (!user) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }
      res.json({ message: "사용자가 승인되었습니다.", user });
    } catch (error) {
      console.error("사용자 승인 중 오류 발생:", error);
      res.status(500).json({ message: "서버 오류", error: error.message });
    }
  }
);

// 관리자용: 익명 게시글 작성자 확인 API
app.get(
  "/api/admin/posts/:id/reveal-author",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const post = await Post.findById(req.params.id).populate(
        "author",
        "username nickname"
      );

      if (!post) {
        return res.status(404).json({ message: "게시글을 찾을 수 없습니다." });
      }

      const authorInfo = {
        id: post.author._id,
        username: post.author.username,
        nickname: post.author.nickname,
      };

      res.json(authorInfo);
    } catch (error) {
      console.error("작성자 정보 확인 중 오류 발생:", error);
      res.status(500).json({ message: "서버 오류", error: error.message });
    }
  }
);

import Anthropic from '@anthropic-ai/sdk';

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY // 환경 변수에서 API 키를 가져옵니다.
});

const GrammarCheckLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sentence: { type: String, required: true },
  correctedSentence: String,
  isCorrect: Boolean,
  attempts: [{ 
    attempt: String, 
    hint: String, 
    timestamp: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const GrammarCheckLog = mongoose.model('GrammarCheckLog', GrammarCheckLogSchema);

app.post('/api/grammar-check', authenticateToken, async (req, res) => {
  try {
    const { sentence, correctedSentence, attemptCount } = req.body;
    const userId = req.user.id;

    let log = await GrammarCheckLog.findOne({ userId, sentence });
    if (!log) {
      log = new GrammarCheckLog({ userId, sentence });
    }

    const prompt = `당신은 한국어 문법 전문가입니다. 다음 문장을 문법적으로 검사해주세요: 
    
    "${sentence}"

    검사 지침:
    1. 문장의 전반적인 문법 구조를 분석하세요.
    2. 맞춤법, 띄어쓰기, 문장 성분의 호응, 어순 등을 세밀하게 검토하세요.
    3. 문법적 오류가 있다면 다음과 같이 응답해주세요:
       a) 오류의 위치와 종류를 명확히 지적하세요.
       b) 오류를 수정하기 위한 힌트를 제공하세요. 단, 직접적인 정답은 주지 마세요.
       c) 가능하다면 문법 규칙에 대한 간단한 설명을 덧붙이세요.
    4. 문장이 문법적으로 완벽하다면 "이 문장은 문법적으로 완벽합니다."라고 답변하세요.
    5. 답변은 한국어로 해주세요.

    응답 형식:
    [문법 검사 결과]
    [오류 지적 및 힌트]
    [추가 설명 (필요시)]

    주의: 문장의 의미나 내용에 대해서는 언급하지 마세요. 오직 문법적 측면만 다루어 주세요.`;

    const response = await anthropic.completions.create({
      model: "claude-3-sonnet-20240229",  // Claude 3.5 Sonnet 모델 사용
      prompt: prompt,
      max_tokens_to_sample: 500,
    });

    const aiResponse = response.completion.trim();
    const isCorrect = aiResponse.includes('문법적으로 완벽합니다');

    if (correctedSentence) {
      log.attempts.push({ attempt: correctedSentence, hint: aiResponse });
    }

    if (isCorrect || attemptCount >= 3) {
      log.isCorrect = isCorrect;
      log.correctedSentence = isCorrect ? sentence : correctedSentence;
    }

    await log.save();

    res.json({
      isCorrect,
      hint: isCorrect ? '이 문장은 문법적으로 완벽합니다.' : aiResponse,
      correctSentence: attemptCount >= 3 ? correctedSentence : undefined
    });
  } catch (error) {
    console.error('문법 검사 중 오류 발생:', error);
    res.status(500).json({ message: '서버 오류', error: error.message });
  }
});

app.get('/api/admin/grammar-check-logs', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const skip = (page - 1) * limit;

    const logs = await GrammarCheckLog.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(Number(limit))
      .populate('userId', 'username nickname');

    const total = await GrammarCheckLog.countDocuments();

    res.json({
      logs,
      currentPage: Number(page),
      totalPages: Math.ceil(total / limit),
      totalLogs: total
    });
  } catch (error) {
    console.error('문법 검사 로그 조회 중 오류 발생:', error);
    res.status(500).json({ message: '서버 오류', error: error.message });
  }
});

app.get('/api/check-auth', authenticateToken, (req, res) => {
  res.json({ 
    isAuthenticated: true, 
    user: { 
      id: req.user.id, 
      username: req.user.username, 
      isAdmin: req.user.isAdmin 
    } 
  });
});
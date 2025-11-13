import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import OpenAI from 'openai';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(helmet());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true,
  })
);

// Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again after 15 minutes',
});
app.use(limiter);

//
// 🔹 MongoDB Setup
//
mongoose
  .connect(process.env.MONGO_URI, {
    dbName: 'code_explainer',
  })
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err.message));

//
// 🔹 Mongoose Models
//
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
});

const explanationSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  code: { type: String, required: true },
  language: String,
  explanation: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Explanation = mongoose.model('Explanation', explanationSchema);

//
// 🔹 OpenAI Client Setup
//
const client = new OpenAI({
  baseURL: 'https://openrouter.ai/api/v1',
  apiKey: process.env.API_KEY,
});

//
// 🔹 JWT Authentication Middleware
//
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

//
// 🔹 Admin Middleware
//
function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  next();
}

//
// 🔹 Auth Routes
//

// Register (with optional admin code for admin role)
app.post('/api/register', async (req, res) => {
  const { username, password, adminCode } = req.body;
  if (!username || !password)
    return res
      .status(400)
      .json({ error: 'Username and password are required' });

  let role = 'user';
  if (adminCode && adminCode === process.env.ADMIN_CODE) {
    role = 'admin';
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, role });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully', role });
  } catch (err) {
    if (err.code === 11000)
      return res.status(400).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Database error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Login successful', token, role: user.role });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//
// 🔹 Explain Code Route
//
app.post('/api/explain-code', authenticateToken, async (req, res) => {
  try {
    const { code, language } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required' });

    const messages = [
      {
        role: 'user',
        content: `Please explain the following ${
          language || ''
        } code in simple Bangla line by line:\n\n${code}`,
      },
    ];

    const response = await client.chat.completions.create({
      model: 'ibm-granite/granite-4.0-h-micro',
      messages,
    });

    const explanation = response?.choices?.[0]?.message?.content;
    if (!explanation)
      return res
        .status(500)
        .json({ error: 'Failed to get explanation from AI model' });

    await Explanation.create({
      user_id: req.user.id,
      code,
      language,
      explanation,
    });

    res.json({ explanation, language });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//
// 🔹 Get User's Explanations
//
app.get('/api/my-explanations', authenticateToken, async (req, res) => {
  try {
    const explanations = await Explanation.find({ user_id: req.user.id }).sort({
      created_at: -1,
    });
    res.json({ explanations });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

//
// 🔹 Delete Explanation
//
app.delete('/api/explanations/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Explanation.findOneAndDelete({
      _id: id,
      user_id: req.user.id,
    });
    if (!deleted)
      return res
        .status(404)
        .json({ error: 'Explanation not found or not owned by you' });

    res.json({ message: 'Explanation deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

//
// 🔹 Admin Routes
//

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Delete a user (admin only)
app.delete(
  '/api/admin/users/:id',
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const user = await User.findById(id);
      if (!user) return res.status(404).json({ error: 'User not found' });
      if (user.role === 'admin')
        return res.status(403).json({ error: 'Cannot delete admin users' });

      await User.deleteOne({ _id: id });
      await Explanation.deleteMany({ user_id: id }); // Optional: clean up explanations
      res.json({ message: 'User deleted successfully' });
    } catch (err) {
      res.status(500).json({ error: 'Database error' });
    }
  }
);

// Get all explanations (admin only)
app.get(
  '/api/admin/explanations',
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const explanations = await Explanation.find()
        .sort({ created_at: -1 })
        .populate('user_id', 'username');
      res.json({ explanations });
    } catch (err) {
      res.status(500).json({ error: 'Database error' });
    }
  }
);

// Delete any explanation (admin only)
app.delete(
  '/api/admin/explanations/:id',
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const deleted = await Explanation.findByIdAndDelete(id);
      if (!deleted)
        return res.status(404).json({ error: 'Explanation not found' });

      res.json({ message: 'Explanation deleted successfully' });
    } catch (err) {
      res.status(500).json({ error: 'Database error' });
    }
  }
);

//
// 🔹 Start Server
//
const port = process.env.PORT || 5000;
app.listen(port, () =>
  console.log(`🚀 Server running on http://localhost:${port}`)
);

// import express from 'express';
// import cors from 'cors';
// import dotenv from 'dotenv';
// import rateLimit from 'express-rate-limit';
// import helmet from 'helmet';
// import OpenAI from 'openai';
// import mongoose from 'mongoose';
// import bcrypt from 'bcrypt';
// import jwt from 'jsonwebtoken';

// dotenv.config();

// const app = express();

// // Middleware
// app.use(cors());
// app.use(express.json({ limit: '10mb' }));
// app.use(helmet());
// app.use(
//   cors({
//     origin: process.env.FRONTEND_URL || 'http://localhost:5173',
//     credentials: true,
//   })
// );

// // Rate Limiter
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: 100,
//   message: 'Too many requests from this IP, please try again after 15 minutes',
// });
// app.use(limiter);

// //
// // 🔹 MongoDB Setup
// //
// mongoose
//   .connect(process.env.MONGO_URI, {
//     dbName: 'code_explainer',
//   })
//   .then(() => console.log('✅ Connected to MongoDB'))
//   .catch(err => console.error('❌ MongoDB connection error:', err.message));

// //
// // 🔹 Mongoose Models
// //
// const userSchema = new mongoose.Schema({
//   username: { type: String, unique: true, required: true },
//   password: { type: String, required: true },
//   role: { type: String, enum: ['user', 'admin'], default: 'user' },
// });

// const explanationSchema = new mongoose.Schema({
//   user_id: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: 'User',
//     required: true,
//   },
//   code: { type: String, required: true },
//   language: String,
//   explanation: { type: String, required: true },
//   created_at: { type: Date, default: Date.now },
// });

// const User = mongoose.model('User', userSchema);
// const Explanation = mongoose.model('Explanation', explanationSchema);

// //
// // 🔹 OpenAI Client Setup
// //
// const client = new OpenAI({
//   baseURL: 'https://openrouter.ai/api/v1',
//   apiKey: process.env.API_KEY,
// });

// //
// // 🔹 JWT Authentication Middleware
// //
// function authenticateToken(req, res, next) {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader && authHeader.split(' ')[1];
//   if (!token) return res.sendStatus(401);

//   jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
//     if (err) return res.sendStatus(403);
//     req.user = user;
//     next();
//   });
// }

// //
// // 🔹 Admin Middleware
// //
// function isAdmin(req, res, next) {
//   if (req.user.role !== 'admin') return res.sendStatus(403);
//   next();
// }

// //
// // 🔹 Auth Routes
// //

// // Register (with optional admin code for admin role)
// app.post('/api/register', async (req, res) => {
//   const { username, password, adminCode } = req.body;
//   if (!username || !password)
//     return res
//       .status(400)
//       .json({ error: 'Username and password are required' });

//   let role = 'user';
//   if (adminCode && adminCode === process.env.ADMIN_CODE) {
//     role = 'admin';
//   }

//   try {
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const newUser = new User({ username, password: hashedPassword, role });
//     await newUser.save();
//     res.status(201).json({ message: 'User registered successfully', role });
//   } catch (err) {
//     if (err.code === 11000)
//       return res.status(400).json({ error: 'Username already exists' });
//     res.status(500).json({ error: 'Database error' });
//   }
// });

// // Login
// app.post('/api/login', async (req, res) => {
//   const { username, password } = req.body;
//   if (!username || !password)
//     return res.status(400).json({ error: 'Username and password required' });

//   try {
//     const user = await User.findOne({ username });
//     if (!user) return res.status(401).json({ error: 'Invalid credentials' });

//     const valid = await bcrypt.compare(password, user.password);
//     if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

//     const token = jwt.sign(
//       { id: user._id, username: user.username, role: user.role },
//       process.env.JWT_SECRET,
//       { expiresIn: '1h' }
//     );

//     res.json({ message: 'Login successful', token, role: user.role });
//   } catch (err) {
//     res.status(500).json({ error: 'Internal Server Error' });
//   }
// });

// //
// // 🔹 Explain Code Route
// //
// app.post('/api/explain-code', authenticateToken, async (req, res) => {
//   try {
//     const { code, language } = req.body;
//     if (!code) return res.status(400).json({ error: 'Code is required' });

//     const messages = [
//       {
//         role: 'user',
//         content: `Please explain the following ${
//           language || ''
//         } code in simple Bangla line by line:\n\n${code}`,
//       },
//     ];

//     const response = await client.chat.completions.create({
//       model: 'ibm-granite/granite-4.0-h-micro',
//       messages,
//     });

//     const explanation = response?.choices?.[0]?.message?.content;
//     if (!explanation)
//       return res
//         .status(500)
//         .json({ error: 'Failed to get explanation from AI model' });

//     await Explanation.create({
//       user_id: req.user.id,
//       code,
//       language,
//       explanation,
//     });

//     res.json({ explanation, language });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Internal Server Error' });
//   }
// });

// //
// // 🔹 Get User's Explanations
// //
// app.get('/api/my-explanations', authenticateToken, async (req, res) => {
//   try {
//     const explanations = await Explanation.find({ user_id: req.user.id }).sort({
//       created_at: -1,
//     });
//     res.json({ explanations });
//   } catch (err) {
//     res.status(500).json({ error: 'Database error' });
//   }
// });

// //
// // 🔹 Delete Explanation
// //
// app.delete('/api/explanations/:id', authenticateToken, async (req, res) => {
//   try {
//     const { id } = req.params;
//     const deleted = await Explanation.findOneAndDelete({
//       _id: id,
//       user_id: req.user.id,
//     });
//     if (!deleted)
//       return res
//         .status(404)
//         .json({ error: 'Explanation not found or not owned by you' });

//     res.json({ message: 'Explanation deleted successfully' });
//   } catch (err) {
//     res.status(500).json({ error: 'Database error' });
//   }
// });

// //
// // 🔹 Admin Routes
// //

// // Get all users (admin only)
// app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
//   try {
//     const users = await User.find().select('-password');
//     res.json({ users });
//   } catch (err) {
//     res.status(500).json({ error: 'Database error' });
//   }
// });

// // Delete a user (admin only)
// app.delete(
//   '/api/admin/users/:id',
//   authenticateToken,
//   isAdmin,
//   async (req, res) => {
//     try {
//       const { id } = req.params;
//       const user = await User.findById(id);
//       if (!user) return res.status(404).json({ error: 'User not found' });
//       if (user.role === 'admin')
//         return res.status(403).json({ error: 'Cannot delete admin users' });

//       await User.deleteOne({ _id: id });
//       await Explanation.deleteMany({ user_id: id }); // Optional: clean up explanations
//       res.json({ message: 'User deleted successfully' });
//     } catch (err) {
//       res.status(500).json({ error: 'Database error' });
//     }
//   }
// );

// // Get all explanations (admin only)
// app.get(
//   '/api/admin/explanations',
//   authenticateToken,
//   isAdmin,
//   async (req, res) => {
//     try {
//       const explanations = await Explanation.find()
//         .sort({ created_at: -1 })
//         .populate('user_id', 'username');
//       res.json({ explanations });
//     } catch (err) {
//       res.status(500).json({ error: 'Database error' });
//     }
//   }
// );

// // Delete any explanation (admin only)
// app.delete(
//   '/api/admin/explanations/:id',
//   authenticateToken,
//   isAdmin,
//   async (req, res) => {
//     try {
//       const { id } = req.params;
//       const deleted = await Explanation.findByIdAndDelete(id);
//       if (!deleted)
//         return res.status(404).json({ error: 'Explanation not found' });

//       res.json({ message: 'Explanation deleted successfully' });
//     } catch (err) {
//       res.status(500).json({ error: 'Database error' });
//     }
//   }
// );

// //
// // 🔹 Start Server
// //
// const port = process.env.PORT || 5000;
// app.listen(port, () =>
//   console.log(`🚀 Server running on http://localhost:${port}`)
// );

import express from 'express';
import cors from 'cors';
import { Sequelize, DataTypes } from 'sequelize';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'your-fallback-secret-for-dev-only';

const app = express();
const PORT = process.env.PORT || 5000;

// ==========================
// Database connection
// ==========================
console.log('--- Database Connection Debug ---');
if (process.env.DATABASE_URL) {
  console.log('Strategy: Using DATABASE_URL');
  // Mask the URL to avoid leaking credentials in logs
  console.log('URL:', process.env.DATABASE_URL.replace(/:([^:@]+)@/, ':****@'));
} else {
  console.log('Strategy: Using individual environment variables');
  console.log('DB_NAME:', process.env.DB_NAME);
  console.log('DB_USER:', process.env.DB_USER);
  console.log('DB_HOST:', process.env.DB_HOST);
  // Do not log password
}
console.log('---------------------------------');
const sequelize = process.env.DATABASE_URL
  ? new Sequelize(process.env.DATABASE_URL, {
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false
      }
    }
  })
  : new Sequelize(
    process.env.DB_NAME,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
      host: process.env.DB_HOST,
      dialect: 'postgres',
      logging: false,
    }
  );

// ==========================
// Models
// ==========================
const Admin = sequelize.define('Admin', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  email: { type: DataTypes.STRING(100), allowNull: false, unique: true },
  password: { type: DataTypes.STRING(255), allowNull: false },
}, {
  tableName: 'admins',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING(100), allowNull: false },
  email: { type: DataTypes.STRING(100), allowNull: false, unique: true },
  password: { type: DataTypes.STRING(255), allowNull: false },
  isAdmin: { type: DataTypes.BOOLEAN, defaultValue: false },
}, {
  tableName: 'users',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

const Contact = sequelize.define('Contact', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING(100), allowNull: false },
  email: { type: DataTypes.STRING(100), allowNull: false },
  phone: { type: DataTypes.STRING(20), allowNull: true },
  message: { type: DataTypes.TEXT, allowNull: false },
  reply: { type: DataTypes.TEXT, allowNull: true },
  replied_at: { type: DataTypes.DATE, allowNull: true },
}, {
  tableName: 'contacts',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

const ChatMessage = sequelize.define('ChatMessage', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  userEmail: { type: DataTypes.STRING(100), allowNull: false },
  userName: { type: DataTypes.STRING(100), allowNull: false },
  text: { type: DataTypes.TEXT, allowNull: false },
  role: { type: DataTypes.ENUM('user', 'admin'), allowNull: false, defaultValue: 'user' },
}, {
  tableName: 'chat_messages',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

const Project = sequelize.define('Project', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  title: { type: DataTypes.STRING, allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: false },
  technologies: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: false },
  image: { type: DataTypes.STRING, allowNull: true },
  liveUrl: { type: DataTypes.STRING, allowNull: true },
  githubUrl: { type: DataTypes.STRING, allowNull: true },
}, {
  tableName: 'projects',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

const Experience = sequelize.define('Experience', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  title: { type: DataTypes.STRING, allowNull: false },
  company: { type: DataTypes.STRING, allowNull: false },
  duration: { type: DataTypes.STRING, allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: false },
  technologies: { type: DataTypes.ARRAY(DataTypes.STRING), allowNull: false },
}, {
  tableName: 'experiences',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

const Comment = sequelize.define('Comment', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  projectId: { type: DataTypes.INTEGER, allowNull: false },
  userName: { type: DataTypes.STRING, allowNull: false },
  userEmail: { type: DataTypes.STRING, allowNull: false },
  comment: { type: DataTypes.TEXT, allowNull: false },
}, {
  tableName: 'comments',
  timestamps: true,
  createdAt: 'created_at',
  updatedAt: false,
});

// Relationships
Project.hasMany(Comment, { foreignKey: 'projectId', as: 'comments' });
Comment.belongsTo(Project, { foreignKey: 'projectId' });

// ==========================
// Middleware
// ==========================
app.use(cors());
app.use(express.json());

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ success: false, error: 'Access denied. No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(403).json({ success: false, error: 'Access denied. Admin rights required.' });
  }
};

// ==========================
// Routes
// ==========================

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, error: 'All fields are required' });

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) return res.status(400).json({ success: false, error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword });

    res.json({ success: true, message: 'User registered successfully', data: { id: user.id, name: user.name, email: user.email, isAdmin: user.isAdmin } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: 'Email and password are required' });

    // Check Admins first
    const admin = await Admin.findOne({ where: { email } });
    if (admin) {
      const isMatch = await bcrypt.compare(password, admin.password);
      if (isMatch) {
        const token = jwt.sign({ id: admin.id, email: admin.email, isAdmin: true }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ success: true, message: 'Login successful', data: { id: admin.id, email: admin.email, isAdmin: true, token } });
      }
    }

    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ success: false, error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: false }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, message: 'Login successful', data: { id: user.id, name: user.name, email: user.email, isAdmin: false, token } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Contact routes
app.post('/api/contact', authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;
    if (!name || !email || !message)
      return res.status(400).json({ success: false, error: 'Name, email, and message are required' });

    const contact = await Contact.create({ name, email, phone: phone || null, message });
    res.json({ success: true, message: 'Contact form submitted successfully', data: contact });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/contact', authenticateToken, isAdmin, async (req, res) => {
  try {
    const contacts = await Contact.findAll({ order: [['created_at', 'DESC']] });
    res.json({ success: true, data: contacts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/messages/:email', authenticateToken, async (req, res) => {
  try {
    const { email } = req.params;

    // Authorization check: User can only see their own messages, Admins can see any
    if (!req.user.isAdmin && req.user.email !== email) {
      return res.status(403).json({ success: false, error: 'Access denied. You can only view your own messages.' });
    }

    const messages = await Contact.findAll({
      where: { email },
      order: [['created_at', 'DESC']]
    });
    res.json({ success: true, data: messages });
  } catch (error) {
    console.error('Error fetching user messages:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Chat Routes
app.post('/api/chat/send', authenticateToken, async (req, res) => {
  try {
    const { userEmail, userName, text, role } = req.body;
    if (!userEmail || !text || !role) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }
    const newMessage = await ChatMessage.create({ userEmail, userName: userName || 'Admin', text, role });
    res.json({ success: true, data: newMessage });
  } catch (error) {
    console.error('Chat send error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/chat/history/:email', authenticateToken, async (req, res) => {
  try {
    const { email } = req.params;
    const history = await ChatMessage.findAll({
      where: { userEmail: email },
      order: [['created_at', 'ASC']]
    });
    res.json({ success: true, data: history });
  } catch (error) {
    console.error('Chat history error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/chat/admin/conversations', authenticateToken, isAdmin, async (req, res) => {
  try {
    const conversations = await ChatMessage.findAll({
      attributes: [
        'userEmail',
        'userName',
        [sequelize.fn('MAX', sequelize.col('created_at')), 'lastMessageAt']
      ],
      group: ['userEmail', 'userName'],
      order: [[sequelize.literal('"lastMessageAt"'), 'DESC']]
    });
    res.json({ success: true, data: conversations });
  } catch (error) {
    console.error('Admin conversations error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Projects Routes
app.get('/api/projects', async (req, res) => {
  try {
    const projects = await Project.findAll({
      include: [{ model: Comment, as: 'comments' }],
      order: [['created_at', 'DESC']]
    });
    res.json({ success: true, data: projects });
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.get('/api/projects/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const project = await Project.findOne({
      where: { id },
      include: [{ model: Comment, as: 'comments' }]
    });
    if (!project) return res.status(404).json({ success: false, error: 'Project not found' });
    res.json({ success: true, data: project });
  } catch (error) {
    console.error('Error fetching project detail:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/projects', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { title, description, technologies, image, liveUrl, githubUrl } = req.body;
    const project = await Project.create({ title, description, technologies, image, liveUrl, githubUrl });
    res.json({ success: true, data: project });
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/projects/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { userName, userEmail, comment } = req.body;
    const newComment = await Comment.create({ projectId: id, userName, userEmail, comment });
    res.json({ success: true, data: newComment });
  } catch (error) {
    console.error('Error creating comment:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.delete('/api/projects/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await Project.destroy({ where: { id } });
    res.json({ success: true, message: 'Project deleted' });
  } catch (error) {
    console.error('Error deleting project:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Experiences Routes
app.get('/api/experiences', async (req, res) => {
  try {
    const experiences = await Experience.findAll({ order: [['created_at', 'DESC']] });
    res.json({ success: true, data: experiences });
  } catch (error) {
    console.error('Error fetching experiences:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.post('/api/experiences', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { title, company, duration, description, technologies } = req.body;
    const experience = await Experience.create({ title, company, duration, description, technologies });
    res.json({ success: true, data: experience });
  } catch (error) {
    console.error('Error creating experience:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.delete('/api/experiences/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await Experience.destroy({ where: { id } });
    res.json({ success: true, message: 'Experience deleted' });
  } catch (error) {
    console.error('Error deleting experience:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Admin routes
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.findAll({ order: [['created_at', 'DESC']] });
    const admins = await Admin.findAll();

    // Combine users and admins for the admin panel view
    const allUsers = [
      ...admins.map(a => ({
        id: `admin-${a.id}`,
        name: 'Admin User',
        email: a.email,
        isAdmin: true,
        created_at: a.created_at
      })),
      ...users.map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        isAdmin: false,
        created_at: u.created_at
      }))
    ];

    res.json({ success: true, data: allUsers });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.put('/api/contact/:id/reply', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { reply } = req.body;

    if (!reply) return res.status(400).json({ success: false, error: 'Reply content is required' });

    const contact = await Contact.findByPk(id);
    if (!contact) return res.status(404).json({ success: false, error: 'Message not found' });

    await contact.update({
      reply,
      replied_at: new Date()
    });

    res.json({ success: true, message: 'Reply sent successfully', data: contact });
  } catch (error) {
    console.error('Error replying to message:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'Server is running!' }));

// ==========================
// Server start
// ==========================
const startServer = async () => {
  try {
    await sequelize.authenticate();
    console.log('Database connected successfully.');

    await sequelize.sync({ alter: true });
    console.log('Database synced successfully with schema updates.');

    // Admin should be managed directly in the database now.

    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  } catch (error) {
    console.error('Unable to start server:', error);
  }
};

startServer();

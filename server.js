const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/lab_management', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// JWT Secret
const JWT_SECRET = 'your-secret-key-change-this-in-production';

// Models

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true },
  role: { type: String, enum: ['admin', 'department_head', 'lab_manager', 'teacher', 'student'], required: true },
  fullName: String,
  department: String,
  rfidCard: String,
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

const User = mongoose.model('User', userSchema);

// Laboratory Schema
const laboratorySchema = new mongoose.Schema({
  name: { type: String, required: true },
  code: { type: String, required: true, unique: true },
  floor: Number,
  capacity: Number,
  equipment: [{
    name: String,
    quantity: Number,
    description: String
  }],
  manager: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const Laboratory = mongoose.model('Laboratory', laboratorySchema);

// Component Schema
const componentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  code: { type: String, required: true, unique: true },
  category: String,
  description: String,
  quantity: { type: Number, required: true, min: 0 },
  available: { type: Number, required: true, min: 0 },
  location: { type: mongoose.Schema.Types.ObjectId, ref: 'Laboratory' },
  specifications: mongoose.Schema.Types.Mixed,
  image: String,
  createdAt: { type: Date, default: Date.now }
});

const Component = mongoose.model('Component', componentSchema);

// Borrow Request Schema
const borrowRequestSchema = new mongoose.Schema({
  component: { type: mongoose.Schema.Types.ObjectId, ref: 'Component', required: true },
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  quantity: { type: Number, required: true, min: 1 },
  purpose: String,
  borrowDate: { type: Date, default: Date.now },
  expectedReturnDate: { type: Date, required: true },
  actualReturnDate: Date,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'borrowed', 'returned', 'rejected', 'overdue'],
    default: 'pending'
  },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvedDate: Date,
  rejectionReason: String,
  createdAt: { type: Date, default: Date.now }
});

const BorrowRequest = mongoose.model('BorrowRequest', borrowRequestSchema);

// Schedule Schema
const scheduleSchema = new mongoose.Schema({
  laboratory: { type: mongoose.Schema.Types.ObjectId, ref: 'Laboratory', required: true },
  subject: { type: String, required: true },
  teacher: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  group: { type: String, required: true },
  year: String,
  specialization: String,
  dayOfWeek: { type: Number, required: true }, // 0-6 (Sunday-Saturday)
  startTime: { type: String, required: true },
  endTime: { type: String, required: true },
  startDate: Date,
  endDate: Date,
  isRecurring: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

const Schedule = mongoose.model('Schedule', scheduleSchema);

// Door Access Log Schema
const doorAccessSchema = new mongoose.Schema({
  laboratory: { type: mongoose.Schema.Types.ObjectId, ref: 'Laboratory', required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  rfidCard: String,
  action: { type: String, enum: ['open', 'close', 'unauthorized'], required: true },
  timestamp: { type: Date, default: Date.now },
  status: { type: String, enum: ['success', 'failed'] }
});

const DoorAccess = mongoose.model('DoorAccess', doorAccessSchema);

// Middleware for authentication
const authenticate = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      throw new Error();
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      throw new Error();
    }
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Please authenticate' });
  }
};

// Routes

// Authentication
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, email, role, fullName, department } = req.body;
    const user = new User({ username, password, email, role, fullName, department });
    await user.save();
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);
    res.status(201).json({ user: { ...user.toObject(), password: undefined }, token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id, role: user.role }, JWT_SECRET);
    res.json({ user: { ...user.toObject(), password: undefined }, token });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Laboratories
app.get('/api/laboratories', authenticate, async (req, res) => {
  try {
    const labs = await Laboratory.find().populate('manager', 'fullName email');
    res.json(labs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/laboratories', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'department_head' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    const lab = new Laboratory(req.body);
    await lab.save();
    res.status(201).json(lab);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/laboratories/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'department_head' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    const lab = await Laboratory.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(lab);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Components
app.get('/api/components', authenticate, async (req, res) => {
  try {
    const components = await Component.find().populate('location', 'name code');
    res.json(components);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/components', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'lab_manager' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    const component = new Component(req.body);
    await component.save();
    res.status(201).json(component);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/components/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'lab_manager' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    const component = await Component.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(component);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Borrow Requests
app.get('/api/borrow-requests', authenticate, async (req, res) => {
  try {
    let query = {};
    if (req.user.role === 'student') {
      query.student = req.user._id;
    }
    const requests = await BorrowRequest.find(query)
      .populate('component', 'name code')
      .populate('student', 'fullName username')
      .populate('approvedBy', 'fullName')
      .sort('-createdAt');
    res.json(requests);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/borrow-requests', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'student') {
      return res.status(403).json({ error: 'Only students can create borrow requests' });
    }
    const request = new BorrowRequest({
      ...req.body,
      student: req.user._id
    });
    
    // Check component availability
    const component = await Component.findById(req.body.component);
    if (component.available < req.body.quantity) {
      return res.status(400).json({ error: 'Insufficient available quantity' });
    }
    
    await request.save();
    io.emit('newBorrowRequest', request);
    res.status(201).json(request);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/borrow-requests/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'lab_manager' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const request = await BorrowRequest.findById(req.params.id);
    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    if (req.body.status === 'approved') {
      // Update component availability
      await Component.findByIdAndUpdate(request.component, {
        $inc: { available: -request.quantity }
      });
      request.approvedBy = req.user._id;
      request.approvedDate = new Date();
    } else if (req.body.status === 'returned') {
      // Return items
      await Component.findByIdAndUpdate(request.component, {
        $inc: { available: request.quantity }
      });
      request.actualReturnDate = new Date();
    }
    
    request.status = req.body.status;
    if (req.body.rejectionReason) {
      request.rejectionReason = req.body.rejectionReason;
    }
    
    await request.save();
    io.emit('borrowRequestUpdated', request);
    res.json(request);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Schedule
app.get('/api/schedule', authenticate, async (req, res) => {
  try {
    const schedule = await Schedule.find()
      .populate('laboratory', 'name code')
      .populate('teacher', 'fullName')
      .sort({ dayOfWeek: 1, startTime: 1 });
    res.json(schedule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/schedule', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'department_head' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    const scheduleItem = new Schedule(req.body);
    await scheduleItem.save();
    io.emit('scheduleUpdated', scheduleItem);
    res.status(201).json(scheduleItem);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/schedule/:id', authenticate, async (req, res) => {
  try {
    if (req.user.role !== 'department_head' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }
    await Schedule.findByIdAndDelete(req.params.id);
    io.emit('scheduleDeleted', req.params.id);
    res.json({ message: 'Schedule deleted successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Door Access
app.post('/api/door-access', authenticate, async (req, res) => {
  try {
    const { laboratory, rfidCard, action } = req.body;
    
    // Verify if user has access
    let user = null;
    if (rfidCard) {
      user = await User.findOne({ rfidCard });
    }
    
    if (!user && action === 'open') {
      const log = new DoorAccess({
        laboratory,
        user: req.user._id,
        rfidCard,
        action,
        status: 'failed'
      });
      await log.save();
      return res.status(403).json({ error: 'Access denied', log });
    }
    
    // Check if user has scheduled time
    const now = new Date();
    const dayOfWeek = now.getDay();
    const currentTime = now.toTimeString().slice(0, 5);
    
    const schedule = await Schedule.findOne({
      laboratory,
      teacher: user ? user._id : req.user._id,
      dayOfWeek,
      startTime: { $lte: currentTime },
      endTime: { $gte: currentTime }
    });
    
    if (!schedule && action === 'open' && req.user.role !== 'lab_manager' && req.user.role !== 'admin') {
      const log = new DoorAccess({
        laboratory,
        user: req.user._id,
        rfidCard,
        action,
        status: 'failed'
      });
      await log.save();
      return res.status(403).json({ error: 'No scheduled session at this time', log });
    }
    
    const log = new DoorAccess({
      laboratory,
      user: user ? user._id : req.user._id,
      rfidCard,
      action,
      status: 'success'
    });
    await log.save();
    
    io.emit('doorAccess', log);
    res.json({ message: 'Door access granted', log });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get current schedule for display
app.get('/api/current-schedule', async (req, res) => {
  try {
    const now = new Date();
    const dayOfWeek = now.getDay();
    const currentTime = now.toTimeString().slice(0, 5);
    
    const schedule = await Schedule.find({
      dayOfWeek,
      startTime: { $lte: currentTime },
      endTime: { $gte: currentTime }
    })
    .populate('laboratory', 'name code')
    .populate('teacher', 'fullName')
    .sort({ laboratory: 1 });
    
    res.json(schedule);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Socket.IO connection
io.on('connection', (socket) => {
  console.log('New client connected');
  
  socket.on('subscribeToLaboratory', (labId) => {
    socket.join(`lab-${labId}`);
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
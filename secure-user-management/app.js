import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import vulnerableRoutes from './routes/vulnerable.js';
import secureRoutes from './routes/secure.js';

// Setup __dirname equivalent for ES modules
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
app.use('/api/vulnerable', vulnerableRoutes);
app.use('/api/secure', secureRoutes);

// Serve HTML pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Vulnerable routes
app.get('/vulnerable/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'vulnerable', 'register.html'));
});

app.get('/vulnerable/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'vulnerable', 'login.html'));
});

app.get('/vulnerable/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'vulnerable', 'dashboard.html'));
});

// Secure routes
app.get('/secure/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'secure', 'register.html'));
});

app.get('/secure/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'secure', 'login.html'));
});

app.get('/secure/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'secure', 'dashboard.html'));
});

app.get('/secure/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'secure', 'admin.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
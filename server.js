require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Banco de dados em memória (substitua por um banco real em produção)
const users = [
  {
    id: 1,
    name: 'admin',
    email: 'admin@pecinhas.com',
    password: bcrypt.hashSync('Admin123!', 10),
    isAdmin: true,
    createdAt: new Date().toISOString()
  }
];

const SECRET = process.env.JWT_SECRET || 'pecinhas_secret';

// Middleware para autenticação JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token não fornecido' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Registro
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
  }
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: 'Email já cadastrado' });
  }
  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = {
    id: Date.now(),
    name,
    email,
    password: hashedPassword,
    isAdmin: false,
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  res.json({ message: 'Usuário registrado com sucesso' });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ message: 'Usuário ou senha incorretos' });
  }
  if (!bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ message: 'Usuário ou senha incorretos' });
  }
  const token = jwt.sign({ id: user.id, name: user.name, email: user.email, isAdmin: user.isAdmin }, SECRET, { expiresIn: '2h' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, isAdmin: user.isAdmin } });
});

// Painel admin (apenas admin)
app.get('/api/admin', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) {
    return res.status(403).json({ message: 'Acesso negado' });
  }
  res.json({ message: 'Bem-vindo ao painel admin', users });
});

// Perfil do usuário autenticado
app.get('/api/profile', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });
  res.json({ id: user.id, name: user.name, email: user.email, isAdmin: user.isAdmin, createdAt: user.createdAt });
});

// Dados em memória (substitua por banco real em produção)
let reports = [];
let tokens = [];
let adminSettings = {
  maxReportsPerUser: 100,
  reportDelay: 1000,
  maintenanceMessage: '',
  systemEnabled: true
};
let adminLogs = [];

// Listar todos os usuários (admin)
app.get('/api/users', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  res.json(users);
});

// Banir/desbanir usuário
app.post('/api/users/:id/ban', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  const user = users.find(u => u.id == req.params.id);
  if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });
  user.banned = true;
  user.bannedAt = new Date().toISOString();
  res.json({ message: 'Usuário banido com sucesso' });
});
app.post('/api/users/:id/unban', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  const user = users.find(u => u.id == req.params.id);
  if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });
  user.banned = false;
  delete user.bannedAt;
  res.json({ message: 'Usuário desbanido com sucesso' });
});

// Listar tokens
app.get('/api/tokens', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  res.json(tokens);
});
// Adicionar token
app.post('/api/tokens', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: 'Token não pode estar vazio' });
  tokens.push({ token, valid: true, addedAt: new Date().toISOString() });
  res.json({ message: 'Token adicionado com sucesso' });
});
// Remover token
app.delete('/api/tokens/:token', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  tokens = tokens.filter(t => t.token !== req.params.token);
  res.json({ message: 'Token removido com sucesso' });
});

// Listar reports
app.get('/api/reports', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  res.json(reports);
});
// Adicionar report (simulação, normalmente seria feito pelo sistema principal)
app.post('/api/reports', authenticateToken, (req, res) => {
  const report = { ...req.body, id: Date.now(), timestamp: new Date().toISOString() };
  reports.push(report);
  res.json({ message: 'Report adicionado', report });
});

// Estatísticas
app.get('/api/stats', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  const totalUsers = users.length;
  const totalReports = reports.length;
  const activeTokens = tokens.filter(t => t.valid).length;
  const successRate = totalReports > 0 ? ((reports.filter(r => r.success).length / totalReports) * 100).toFixed(1) : '0.0';
  res.json({ totalUsers, totalReports, activeTokens, successRate: successRate + '%' });
});

// Configurações do sistema
app.get('/api/settings', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  res.json(adminSettings);
});
app.post('/api/settings', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  adminSettings = { ...adminSettings, ...req.body };
  res.json({ message: 'Configurações salvas', adminSettings });
});

// Logs do sistema
app.get('/api/logs', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  res.json(adminLogs);
});
app.post('/api/logs', authenticateToken, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Acesso negado' });
  const log = { ...req.body, timestamp: new Date().toISOString() };
  adminLogs.push(log);
  res.json({ message: 'Log adicionado', log });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend seguro rodando em http://localhost:${PORT}`);
}); 
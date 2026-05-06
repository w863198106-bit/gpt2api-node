import jwt from 'jsonwebtoken';
import { User, ApiKey } from '../models/index.js';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// JWT 认证中间件 - 已修改为直接放行
export function authenticateJWT(req, res, next) {
  return next(); 
}

// Session 认证中间件 - 已修改为直接放行
export function authenticateAdmin(req, res, next) {
  return next();
}

// API Key 认证中间件 - 保持原样以保护接口
export function authenticateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.headers.authorization?.replace('Bearer ', '');
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  const keyData = ApiKey.findByKey(apiKey);
  if (!keyData) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  ApiKey.updateUsage(keyData.id);
  req.apiKey = keyData;
  next();
}

// 生成 JWT Token
export function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// 生成 API Key
export function generateApiKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let key = 'sk-';
  for (let i = 0; i < 32; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

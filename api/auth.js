const fileStorage = require('../lib/fileStorage');
const crypto = require('crypto');

module.exports = async (req, res) => {
  // 设置CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { action } = req.query;

  try {
    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;

      switch (action) {
        case 'login':
          await handleLogin(body, res);
          break;
        case 'register':
          await handleRegister(body, res);
          break;
        case 'logout':
          await handleLogout(body, res);
          break;
        case 'check':
          await handleCheckAuth(req, res);
          break;
        default:
          res.status(400).json({ error: '无效的操作' });
      }
    } else {
      res.status(405).json({ error: '方法不允许' });
    }
  } catch (error) {
    console.error('API错误:', error);
    res.status(500).json({ error: '服务器内部错误', details: error.message });
  }
};

async function handleLogin(body, res) {
  const { username, password, fingerprint } = body;

  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }

  // 读取用户数据
  const users = await fileStorage.readFile('users.json');
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  // 验证密码
  const isValidPassword = fileStorage.verifyPassword(password, user.password);
  if (!isValidPassword) {
    return res.status(401).json({ error: '用户名或密码错误' });
  }

  // 更新最后登录时间
  user.lastLogin = new Date().toISOString();
  if (fingerprint) {
    user.fingerprint = fingerprint;
  }
  
  // 保存用户数据
  await fileStorage.writeFile('users.json', users);

  // 生成令牌
  const token = fileStorage.generateToken(user);

  // 记录登录日志
  await fileStorage.appendToFile('audit.log', {
    type: 'login',
    username: user.username,
    ip: req.headers['x-forwarded-for'] || req.connection.remoteAddress,
    userAgent: req.headers['user-agent']
  });

  // 返回用户信息（不包含密码）
  const { password: _, ...userWithoutPassword } = user;
  
  res.json({
    success: true,
    token,
    user: userWithoutPassword,
    message: '登录成功'
  });
}

async function handleRegister(body, res) {
  const { username, password, invitationCode, fingerprint } = body;

  // 验证输入
  if (!username || username.length < 3) {
    return res.status(400).json({ error: '用户名至少需要3个字符' });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({ error: '密码至少需要6个字符' });
  }

  // 检查用户名是否已存在
  const users = await fileStorage.readFile('users.json');
  if (users.some(u => u.username === username)) {
    return res.status(400).json({ error: '用户名已存在' });
  }

  let userType = 'trial';
  
  // 验证邀请码
  if (invitationCode) {
    const invitations = await fileStorage.readFile('invitations.json');
    const validCode = invitations.find(code => 
      code.code === invitationCode && !code.used
    );

    if (!validCode) {
      const usedCode = invitations.find(code => 
        code.code === invitationCode && code.used
      );
      return res.status(400).json({ 
        error: usedCode ? '该邀请码已被使用' : '无效的邀请码' 
      });
    }

    userType = 'registered';
    validCode.used = true;
    validCode.usedBy = username;
    validCode.usedDate = new Date().toISOString();
    await fileStorage.writeFile('invitations.json', invitations);
  }

  // 创建新用户
  const newUser = {
    id: fileStorage.generateId(),
    username,
    password: fileStorage.hashPassword(password),
    userType,
    registrationDate: new Date().toISOString(),
    lastLogin: new Date().toISOString(),
    trialData: {
      count: 0,
      createdAt: new Date().toISOString(),
      firstUse: new Date().toISOString(),
      lastUpdate: new Date().toISOString()
    },
    fingerprint
  };

  users.push(newUser);
  await fileStorage.writeFile('users.json', users);

  // 生成令牌
  const token = fileStorage.generateToken(newUser);

  // 记录注册日志
  await fileStorage.appendToFile('audit.log', {
    type: 'register',
    username: newUser.username,
    userType: newUser.userType,
    invitationCode: invitationCode || 'none'
  });

  // 返回用户信息（不包含密码）
  const { password: _, ...userWithoutPassword } = newUser;

  res.json({
    success: true,
    token,
    user: userWithoutPassword,
    message: '注册成功'
  });
}

async function handleLogout(body, res) {
  // 记录登出日志
  const token = body.token;
  if (token) {
    const payload = fileStorage.verifyToken(token);
    if (payload) {
      await fileStorage.appendToFile('audit.log', {
        type: 'logout',
        username: payload.username,
        timestamp: new Date().toISOString()
      });
    }
  }

  res.json({ success: true, message: '已退出登录' });
}

async function handleCheckAuth(req, res) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '未提供认证令牌' });
  }

  const token = authHeader.substring(7);
  const payload = fileStorage.verifyToken(token);

  if (!payload) {
    return res.status(401).json({ error: '无效的认证令牌' });
  }

  // 获取用户信息
  const users = await fileStorage.readFile('users.json');
  const user = users.find(u => u.id === payload.userId);

  if (!user) {
    return res.status(401).json({ error: '用户不存在' });
  }

  const { password: _, ...userWithoutPassword } = user;
  res.json({ success: true, user: userWithoutPassword });
}

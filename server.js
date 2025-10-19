const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

// ==================== CONFIGURACIÓN ====================
let config = {
  port: 3000,
  documentRoot: path.join(__dirname, 'public'),
  logsFile: path.join(__dirname, 'server.log'),
  errorLogsFile: path.join(__dirname, 'error.log'),
  protectedDirs: {
    '/privado': { user: 'admin', pass: 'password123' }
  }
};

// Credenciales hardcodeadas para login
const ADMIN_CREDENTIALS = {
  user: 'admin',
  pass: 'admin123'
};

// Sesiones de usuarios logueados (en memoria)
const sessions = {};

// ==================== FUNCIONES DE LOGGING ====================
function log(message) {
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}\n`;
  console.log(logMessage);
  fs.appendFileSync(config.logsFile, logMessage);
}

function logError(message) {
  const timestamp = new Date().toISOString();
  const errorMessage = `[${timestamp}] ERROR: ${message}\n`;
  console.error(errorMessage);
  fs.appendFileSync(config.errorLogsFile, errorMessage);
}

function logRequest(ip, method, reqPath, statusCode, size) {
  const message = `${ip} - ${method} ${reqPath} - Status: ${statusCode} - Size: ${size} bytes`;
  log(message);
}

// ==================== GESTIÓN DE SESIONES ====================
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function createSession(user) {
  const token = generateSessionToken();
  sessions[token] = {
    user: user,
    createdAt: Date.now(),
    expiresAt: Date.now() + (3600000) // 1 hora
  };
  return token;
}

function validateSession(token) {
  if (!token || !sessions[token]) return false;
  if (sessions[token].expiresAt < Date.now()) {
    delete sessions[token];
    return false;
  }
  return true;
}

function getCookieToken(req) {
  if (!req.headers.cookie) return null;
  const cookies = req.headers.cookie.split(';');
  for (let cookie of cookies) {
    const parts = cookie.trim().split('=');
    if (parts[0] === 'sessionToken') {
      return decodeURIComponent(parts[1]);
    }
  }
  return null;
}

// ==================== SEGURIDAD ====================
function isPathSafe(requestedPath) {
  const normalizedPath = path.normalize(requestedPath);
  const fullPath = path.join(config.documentRoot, normalizedPath);
  const realPath = path.resolve(fullPath);
  const realDocRoot = path.resolve(config.documentRoot);
  
  return realPath.startsWith(realDocRoot);
}

function checkAuth(reqPath, authHeader) {
  if (!config.protectedDirs[reqPath]) {
    return true;
  }

  if (!authHeader) {
    return false;
  }

  try {
    const auth = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
    const user = auth[0];
    const pass = auth[1];
    
    const protectedDir = config.protectedDirs[reqPath];
    return user === protectedDir.user && pass === protectedDir.pass;
  } catch (e) {
    return false;
  }
}

// ==================== MANEJADORES DE RUTAS ====================
function handleLogin(req, res, clientIp, pathname) {
  let body = '';
  
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', () => {
    try {
      const credentials = JSON.parse(body);
      
      if (credentials.user === ADMIN_CREDENTIALS.user && 
          credentials.pass === ADMIN_CREDENTIALS.pass) {
        
        const token = createSession(credentials.user);
        logRequest(clientIp, 'POST', pathname, 200, body.length);
        log(`Sesión iniciada para usuario: ${credentials.user} desde ${clientIp}`);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, token: token }));
      } else {
        logRequest(clientIp, 'POST', pathname, 401, body.length);
        logError(`Intento de login fallido desde ${clientIp} con usuario: ${credentials.user}`);
        
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Credenciales inválidas' }));
      }
    } catch (e) {
      logError('Error al procesar login: ' + e.message);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Error en el servidor' }));
    }
  });
}

function handleLogout(req, res, clientIp, pathname) {
  const token = getCookieToken(req);
  if (token && sessions[token]) {
    log(`Sesión cerrada para usuario: ${sessions[token].user} desde ${clientIp}`);
    delete sessions[token];
  }
  logRequest(clientIp, 'GET', pathname, 302, 0);
  res.writeHead(302, { 'Location': '/admin', 'Set-Cookie': 'sessionToken=; path=/; max-age=0' });
  res.end();
}

function handleLoginPage(res, clientIp, pathname) {
  logRequest(clientIp, 'GET', pathname, 200, 0);
  
  const html = `
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Login - Servidor Web</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          display: flex; 
          justify-content: center; 
          align-items: center; 
          min-height: 100vh; 
          background: #f5f5f5;
        }
        .login-container { 
          background: white; 
          padding: 40px; 
          border-radius: 8px; 
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px rgba(0, 0, 0, 0.06);
          width: 100%; 
          max-width: 400px;
          border: 1px solid #e5e7eb;
        }
        .login-container h1 { 
          color: #1f2937; 
          margin-bottom: 8px; 
          text-align: center; 
          font-size: 24px;
          font-weight: 600;
        }
        .login-container p { 
          color: #6b7280; 
          text-align: center; 
          margin-bottom: 32px; 
          font-size: 14px;
        }
        .form-group { margin-bottom: 16px; }
        label { 
          display: block; 
          margin-bottom: 6px; 
          color: #374151; 
          font-weight: 500;
          font-size: 14px;
        }
        input[type="text"], input[type="password"] { 
          width: 100%; 
          padding: 10px 12px; 
          border: 1px solid #d1d5db;
          border-radius: 6px; 
          font-size: 14px;
          background: #fafafa;
          transition: all 0.2s;
        }
        input[type="text"]:hover, input[type="password"]:hover { 
          border-color: #bfdbfe;
        }
        input[type="text"]:focus, input[type="password"]:focus { 
          outline: none; 
          border-color: #3b82f6; 
          background: white;
          box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        button { 
          width: 100%; 
          background: #3b82f6; 
          color: white; 
          padding: 10px 16px; 
          border: none; 
          border-radius: 6px; 
          cursor: pointer; 
          font-size: 14px; 
          font-weight: 500; 
          transition: all 0.2s;
          margin-top: 8px;
        }
        button:hover { 
          background: #2563eb;
        }
        button:active {
          background: #1d4ed8;
        }
        .error { 
          color: #dc2626; 
          font-size: 14px; 
          margin-top: 10px; 
          display: none; 
          text-align: center;
          background: #fee2e2;
          padding: 8px 12px;
          border-radius: 6px;
          border: 1px solid #fecaca;
        }
        .info { 
          background: #dbeafe; 
          color: #1e40af; 
          padding: 12px;
          border-radius: 6px; 
          margin-bottom: 20px; 
          font-size: 13px;
          border: 1px solid #bfdbfe;
        }
        .info code { 
          background: #eff6ff; 
          padding: 2px 6px; 
          border-radius: 4px;
          font-family: 'Courier New', monospace;
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <h1>🔐 Servidor Web</h1>
        <p>Panel de Administración</p>
        
        <div class="info">
          <strong>Credenciales de prueba:</strong><br>
          Usuario: <code>admin</code><br>
          Contraseña: <code>admin123</code>
        </div>

        <form id="loginForm">
          <div class="form-group">
            <label for="user">Usuario:</label>
            <input type="text" id="user" name="user" required autofocus>
          </div>
          <div class="form-group">
            <label for="pass">Contraseña:</label>
            <input type="password" id="pass" name="pass" required>
          </div>
          <button type="submit">Iniciar Sesión</button>
          <div class="error" id="error"></div>
        </form>
      </div>

      <script>
        document.getElementById('loginForm').addEventListener('submit', function(e) {
          e.preventDefault();
          const user = document.getElementById('user').value;
          const pass = document.getElementById('pass').value;
          
          fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user, pass })
          })
          .then(r => r.json())
          .then(data => {
            if (data.success) {
              document.cookie = 'sessionToken=' + data.token + '; path=/; max-age=3600';
              window.location.href = '/admin?token=' + data.token;
            } else {
              const errorDiv = document.getElementById('error');
              errorDiv.textContent = data.error || 'Credenciales inválidas';
              errorDiv.style.display = 'block';
            }
          })
          .catch(e => {
            const errorDiv = document.getElementById('error');
            errorDiv.textContent = 'Error: ' + e;
            errorDiv.style.display = 'block';
          });
        });
      </script>
    </body>
    </html>
  `;
  
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html);
}

function handleAdminInterface(res, clientIp, pathname, token) {
  logRequest(clientIp, 'GET', pathname, 200, 0);
  
  const html = `
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Admin - Servidor Web</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          background: #f9fafb;
          min-height: 100vh;
          padding: 20px;
        }
        .container { 
          max-width: 1000px; 
          margin: 0 auto; 
          background: white;
          border-radius: 8px;
          box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px rgba(0, 0, 0, 0.06);
          overflow: hidden;
          border: 1px solid #e5e7eb;
        }
        .header { 
          background: white;
          color: #1f2937;
          padding: 24px;
          text-align: center; 
          display: flex; 
          justify-content: space-between; 
          align-items: center;
          border-bottom: 1px solid #e5e7eb;
        }
        .header h1 { 
          font-size: 24px; 
          margin: 0; 
          flex: 1;
          font-weight: 600;
        }
        .logout-btn { 
          background: white;
          color: #3b82f6; 
          border: 1px solid #3b82f6;
          padding: 8px 16px; 
          border-radius: 6px; 
          cursor: pointer; 
          font-size: 14px;
          font-weight: 500;
          transition: all 0.2s;
        }
        .logout-btn:hover { 
          background: #f3f4f6;
        }
        .content { 
          padding: 24px;
        }
        .section { 
          margin-bottom: 24px; 
          padding: 20px; 
          background: #f9fafb;
          border-radius: 6px; 
          border: 1px solid #e5e7eb;
        }
        .section h2 { 
          color: #1f2937; 
          margin-bottom: 16px; 
          font-size: 16px;
          font-weight: 600;
        }
        .form-group { 
          margin-bottom: 16px; 
        }
        label { 
          display: block; 
          margin-bottom: 6px; 
          color: #374151; 
          font-weight: 500;
          font-size: 14px;
        }
        input, textarea { 
          width: 100%; 
          padding: 10px 12px; 
          border: 1px solid #d1d5db;
          border-radius: 6px; 
          font-size: 14px;
          background: white;
          font-family: 'Courier New', monospace;
          transition: all 0.2s;
        }
        input:hover, textarea:hover {
          border-color: #bfdbfe;
        }
        input:focus, textarea:focus { 
          outline: none; 
          border-color: #3b82f6;
          box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
          background: white;
        }
        button { 
          background: #3b82f6; 
          color: white; 
          padding: 10px 16px; 
          border: none; 
          border-radius: 6px; 
          cursor: pointer; 
          font-size: 14px;
          font-weight: 500;
          transition: all 0.2s;
          margin-top: 8px;
        }
        button:hover { 
          background: #2563eb;
        }
        button:active {
          background: #1d4ed8;
        }
        .info-box { 
          background: white; 
          padding: 12px; 
          border-radius: 6px; 
          margin-top: 12px; 
          border: 1px solid #e5e7eb;
        }
        .info-box p { 
          margin: 6px 0; 
          color: #4b5563; 
          font-size: 13px;
        }
        .info-box strong {
          color: #1f2937;
          font-weight: 600;
        }
        .protected-list { 
          background: white; 
          padding: 12px; 
          border-radius: 6px;
          border: 1px solid #e5e7eb;
        }
        .protected-item { 
          padding: 10px; 
          margin: 8px 0; 
          background: #dbeafe;
          border-left: 3px solid #3b82f6;
          border-radius: 4px;
        }
        .protected-item strong { 
          color: #1e40af;
          font-weight: 600;
        }
        .protected-item, .protected-item br { color: #1e40af; }
        textarea { 
          min-height: 120px; 
          resize: vertical;
          font-size: 13px;
        }
        small {
          display: block;
          color: #6b7280;
          margin-top: 6px;
          font-size: 13px;
        }
        .success { 
          color: #15803d; 
          background: #dcfce7; 
          padding: 12px;
          border-radius: 6px; 
          margin-bottom: 16px; 
          display: none;
          border: 1px solid #bbf7d0;
          font-size: 14px;
          font-weight: 500;
        }
        #logsContainer pre {
          background: white;
          padding: 12px;
          border-radius: 6px;
          border: 1px solid #e5e7eb;
          max-height: 300px;
          overflow-y: auto;
          font-size: 12px;
          font-family: 'Courier New', monospace;
          color: #374151;
          line-height: 1.4;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>⚙️ Panel de Administración</h1>
          <button class="logout-btn" onclick="logout()">🚪 Cerrar Sesión</button>
        </div>
        <div class="content">
          <div class="success" id="successMsg">✅ Configuración guardada correctamente</div>

          <div class="section">
            <h2>📋 Estado del Servidor</h2>
            <div class="info-box">
              <p><strong>Puerto:</strong> <span id="statusPort">${config.port}</span></p>
              <p><strong>Document Root:</strong> ${config.documentRoot}</p>
              <p><strong>Archivo de Logs:</strong> ${config.logsFile}</p>
              <p><strong>Servidor iniciado:</strong> ${new Date().toLocaleString()}</p>
            </div>
          </div>

          <div class="section">
            <h2>🔐 Directorios Protegidos</h2>
            <div class="protected-list" id="protectedList"></div>
          </div>

          <div class="section">
            <h2>⚙️ Configurar Servidor</h2>
            <form id="configForm">
              <div class="form-group">
                <label for="port">Puerto:</label>
                <input type="number" id="port" name="port" value="${config.port}" required>
              </div>
              <div class="form-group">
                <label for="documentRoot">Document Root:</label>
                <input type="text" id="documentRoot" name="documentRoot" value="${config.documentRoot}" required>
              </div>
              <div class="form-group">
                <label for="logsFile">Archivo de Logs:</label>
                <input type="text" id="logsFile" name="logsFile" value="${config.logsFile}" required>
              </div>
              <div class="form-group">
                <label for="protectedDirs">Directorios Protegidos (JSON):</label>
                <textarea id="protectedDirs" name="protectedDirs">${JSON.stringify(config.protectedDirs, null, 2)}</textarea>
                <small>Formato: { "/ruta": { "user": "usuario", "pass": "contraseña" } }</small>
              </div>
              <button type="submit">💾 Guardar Configuración</button>
            </form>
          </div>

          <div class="section">
            <h2>📊 Ver Logs</h2>
            <button onclick="viewLogs()">📖 Ver Logs de Acceso</button>
            <div id="logsContainer" style="margin-top: 15px;"></div>
          </div>
        </div>
      </div>

      <script>
        const token = '${token}';
        
        function loadProtectedDirs() {
          const dirs = ${JSON.stringify(config.protectedDirs)};
          const html = Object.entries(dirs).map(([path, creds]) => 
            \`<div class="protected-item">
              <strong>Ruta:</strong> \${path}<br>
              <strong>Usuario:</strong> \${creds.user}
            </div>\`
          ).join('');
          document.getElementById('protectedList').innerHTML = html;
        }
        
        loadProtectedDirs();

        document.getElementById('configForm').addEventListener('submit', function(e) {
          e.preventDefault();
          const formData = new FormData(this);
          const data = {
            port: parseInt(formData.get('port')),
            documentRoot: formData.get('documentRoot'),
            logsFile: formData.get('logsFile'),
            protectedDirs: JSON.parse(formData.get('protectedDirs'))
          };
          
          fetch('/admin/config?token=' + token, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          })
          .then(r => r.json())
          .then(data => {
            if (data.success) {
              const msg = document.getElementById('successMsg');
              msg.style.display = 'block';
              setTimeout(() => {
                alert('✅ Configuración actualizada. El servidor se reiniciará en el nuevo puerto.');
                msg.style.display = 'none';
              }, 2000);
            } else {
              alert('❌ Error: ' + data.error);
            }
          })
          .catch(e => alert('Error: ' + e));
        });

        function viewLogs() {
          fetch('/admin/logs?token=' + token)
            .then(r => r.text())
            .then(logs => {
              const container = document.getElementById('logsContainer');
              container.innerHTML = '<pre style="background: #f5f5f5; padding: 15px; border-radius: 5px; max-height: 300px; overflow-y: auto; font-size: 12px;">' + escapeHtml(logs) + '</pre>';
            });
        }

        function escapeHtml(text) {
          const div = document.createElement('div');
          div.textContent = text;
          return div.innerHTML;
        }

        function logout() {
          window.location.href = '/logout';
        }
      </script>
    </body>
    </html>
  `;
  
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(html);
}

function handleAdminConfig(res, clientIp, pathname) {
  logRequest(clientIp, 'GET', pathname, 200, 0);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(config, null, 2));
}

function handleUpdateConfig(req, res, clientIp, pathname) {
  let body = '';
  
  req.on('data', chunk => {
    body += chunk.toString();
  });

  req.on('end', () => {
    try {
      const newConfig = JSON.parse(body);
      
      // Validar que sea válido
      if (!newConfig.port || !newConfig.documentRoot || !newConfig.logsFile) {
        throw new Error('Configuración incompleta');
      }

      config = newConfig;
      
      logRequest(clientIp, 'POST', pathname, 200, body.length);
      log('Configuración actualizada');
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Configuración guardada' }));
      
      // Reiniciar servidor con nueva configuración
      setTimeout(() => {
        log('Reiniciando servidor con nueva configuración...');
        server.close(() => {
          startServer();
        });
      }, 1000);
    } catch (e) {
      logError('Error al guardar configuración: ' + e.message);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: e.message }));
    }
  });
}

function handleViewLogs(res, clientIp, pathname) {
  logRequest(clientIp, 'GET', pathname, 200, 0);
  
  fs.readFile(config.logsFile, 'utf8', (err, data) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(err ? 'No hay logs disponibles' : data);
  });
}

// ==================== MANEJADOR PRINCIPAL DE PETICIONES ====================
function handleRequest(req, res) {
  const clientIp = req.socket.remoteAddress;
  const parsedUrl = url.parse(req.url, true);
  let pathname = parsedUrl.pathname;

  // Ruta para login
  if (pathname === '/login' && req.method === 'POST') {
    handleLogin(req, res, clientIp, pathname);
    return;
  }

  // Ruta para logout
  if (pathname === '/logout') {
    handleLogout(req, res, clientIp, pathname);
    return;
  }

  // Ruta para panel admin
  if (pathname === '/admin' || pathname === '/admin/') {
    const token = parsedUrl.query.token || getCookieToken(req);
    if (!validateSession(token)) {
      handleLoginPage(res, clientIp, pathname);
      return;
    }
    handleAdminInterface(res, clientIp, pathname, token);
    return;
  }

  // Rutas protegidas del admin (config, logs)
  if (pathname.startsWith('/admin/')) {
    const token = parsedUrl.query.token || getCookieToken(req);
    if (!validateSession(token)) {
      logRequest(clientIp, req.method, pathname, 401, 0);
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No autorizado' }));
      return;
    }

    if (pathname === '/admin/config' && req.method === 'GET') {
      handleAdminConfig(res, clientIp, pathname);
      return;
    }

    if (pathname === '/admin/config' && req.method === 'POST') {
      handleUpdateConfig(req, res, clientIp, pathname);
      return;
    }

    if (pathname === '/admin/logs' && req.method === 'GET') {
      handleViewLogs(res, clientIp, pathname);
      return;
    }
  }

  // Verificar autenticación para directorios protegidos
  for (let protectedPath in config.protectedDirs) {
    if (pathname === protectedPath || pathname.startsWith(protectedPath + '/')) {
      if (!checkAuth(protectedPath, req.headers.authorization)) {
        logRequest(clientIp, req.method, pathname, 401, 0);
        res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Access restricted"' });
        res.end('Unauthorized');
        return;
      }
      break;
    }
  }

  // Validar seguridad de ruta (fuera del DocumentRoot)
  if (!isPathSafe(pathname)) {
    logRequest(clientIp, req.method, pathname, 403, 0);
    logError(`Intento de acceso fuera del DocumentRoot: ${pathname} desde ${clientIp}`);
    res.writeHead(403, { 'Content-Type': 'text/html' });
    res.end('<h1>403 - Forbidden</h1><p>Acceso denegado: Intento de acceso fuera del DocumentRoot</p>');
    return;
  }

  let filePath = path.join(config.documentRoot, pathname);

  // Si es un directorio, buscar index.html
  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'index.html');
  }

  // Servir archivo
  fs.readFile(filePath, (err, data) => {
    if (err) {
      logRequest(clientIp, req.method, pathname, 404, 0);
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end('<h1>404 - Not Found</h1>');
      return;
    }

    const ext = path.extname(filePath);
    const contentType = getContentType(ext);
    
    logRequest(clientIp, req.method, pathname, 200, data.length);
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}

function getContentType(ext) {
  const types = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.txt': 'text/plain',
    '.pdf': 'application/pdf'
  };
  return types[ext] || 'application/octet-stream';
}

// ==================== INICIALIZACIÓN ====================
function createPublicFolder() {
  if (!fs.existsSync(config.documentRoot)) {
    fs.mkdirSync(config.documentRoot, { recursive: true });
    
    const indexHtml = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Servidor Web</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            display: flex; 
            justify-content: center; 
            align-items: center; 
            height: 100vh; 
            background: #f9fafb;
          }
          .container { 
            text-align: center; 
            background: white; 
            padding: 48px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px rgba(0, 0, 0, 0.06);
            border: 1px solid #e5e7eb;
            max-width: 500px;
          }
          h1 { 
            color: #1f2937; 
            margin-bottom: 12px;
            font-size: 28px;
            font-weight: 600;
          }
          p { 
            color: #6b7280; 
            margin-bottom: 24px;
            font-size: 15px;
            line-height: 1.6;
          }
          a { 
            color: white; 
            background: #3b82f6; 
            padding: 10px 24px; 
            text-decoration: none; 
            border-radius: 6px; 
            display: inline-block;
            font-weight: 500;
            transition: all 0.2s;
            border: 1px solid transparent;
          }
          a:hover { 
            background: #2563eb;
          }
          .status {
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid #e5e7eb;
          }
          .status p {
            font-size: 13px;
            color: #9ca3af;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>✅ Servidor Web</h1>
          <p>Tu servidor está activo y listo para servir contenido.</p>
          <a href="/admin">Ir al Panel de Administración</a>
          <div class="status">
            <p>Accede a /admin para gestionar el servidor</p>
          </div>
        </div>
      </body>
      </html>
    `;
    
    fs.writeFileSync(path.join(config.documentRoot, 'index.html'), indexHtml);
    
    // Crear archivo de ejemplo
    const exampleHtml = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Contenido Público</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f9fafb;
            padding: 24px;
            line-height: 1.6;
            color: #374151;
          }
          .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid #e5e7eb;
            padding: 40px;
          }
          h1 {
            color: #1f2937;
            margin-bottom: 8px;
            font-size: 28px;
            font-weight: 600;
          }
          .subtitle {
            color: #6b7280;
            font-size: 15px;
            margin-bottom: 32px;
          }
          .sections {
            display: grid;
            gap: 24px;
            margin-top: 32px;
          }
          .section {
            border-left: 3px solid #3b82f6;
            padding-left: 20px;
          }
          .section h2 {
            color: #1f2937;
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 8px;
          }
          .section p {
            color: #6b7280;
            font-size: 14px;
          }
          .link-group {
            display: flex;
            gap: 12px;
            margin-top: 32px;
            flex-wrap: wrap;
          }
          a {
            color: white;
            background: #3b82f6;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 500;
            font-size: 14px;
            transition: all 0.2s;
            border: 1px solid transparent;
          }
          a:hover {
            background: #2563eb;
          }
          a.secondary {
            color: #3b82f6;
            background: white;
            border: 1px solid #3b82f6;
          }
          a.secondary:hover {
            background: #f3f4f6;
          }
          code {
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #1f2937;
          }
          .status-badge {
            display: inline-block;
            background: #dcfce7;
            color: #15803d;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 16px;
            border: 1px solid #bbf7d0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="status-badge">✅ Activo</div>
          <h1>Servidor Web Activo</h1>
          <p class="subtitle">Tu servidor está funcionando correctamente y listo para servir contenido.</p>

          <div class="sections">
            <div class="section">
              <h2>📁 Sistema de Archivos</h2>
              <p>Los archivos que coloques en la carpeta <code>public/</code> serán accesibles desde aquí. El servidor protege el acceso fuera de esta carpeta por seguridad.</p>
            </div>

            <div class="section">
              <h2>🔒 Áreas Protegidas</h2>
              <p>Accede a <code>/privado</code> para ver áreas protegidas con autenticación. Usuario: <code>admin</code> | Contraseña: <code>password123</code></p>
            </div>

            <div class="section">
              <h2>⚙️ Administración</h2>
              <p>Usa el panel de administración para cambiar la configuración del servidor, ver logs de acceso y gestionar directorios protegidos.</p>
            </div>

            <div class="section">
              <h2>📊 Características</h2>
              <p>Este servidor incluye: Protocolo HTTP, Logging completo, Seguridad de ruta, Autenticación básica, y Panel admin intuitivo.</p>
            </div>
          </div>

          <div class="link-group">
            <a href="/admin">⚙️ Panel de Administración</a>
            <a href="/privado" class="secondary">🔐 Área Protegida</a>
          </div>
        </div>
      </body>
      </html>
    `;
    
    fs.writeFileSync(path.join(config.documentRoot, 'ejemplo.html'), exampleHtml);
    
    // Crear carpeta protegida
    const protectedDir = path.join(config.documentRoot, 'privado');
    if (!fs.existsSync(protectedDir)) {
      fs.mkdirSync(protectedDir, { recursive: true });
      fs.writeFileSync(path.join(protectedDir, 'index.html'), '<h1>Área Protegida</h1><p>Solo usuarios autenticados pueden acceder aquí.</p>');
    }
  }
}

let server;

function startServer() {
  server = http.createServer(handleRequest);
  
  server.listen(config.port, () => {
    log(`Servidor web iniciado en puerto ${config.port}`);
    log(`Document Root: ${config.documentRoot}`);
    log(`Accede a: http://localhost:${config.port}`);
    log(`Admin: http://localhost:${config.port}/admin`);
  });

  server.on('error', (err) => {
    logError(`Error del servidor: ${err.message}`);
  });
}

// Crear carpetas necesarias
createPublicFolder();

// Iniciar servidor
startServer();
### Prueba 4: Verificar Sistema de Login y Sesiones

**Paso 1# 🌐 Servidor Web Implementado en Node.js

**Trabajo Práctico N°7 - Redes de Datos**  
*Implementación de aplicaciones*

---

## 📋 Tabla de Contenidos

- [Descripción General](#descripción-general)
- [Requisitos del Trabajo Práctico](#requisitos-del-trabajo-práctico)
- [Características Implementadas](#características-implementadas)
- [Instalación y Configuración](#instalación-y-configuración)
- [Uso del Servidor](#uso-del-servidor)
- [Demostración de Funcionalidades](#demostración-de-funcionalidades)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Detalles Técnicos](#detalles-técnicos)

---

## 📖 Descripción General

El servidor cumple con los estándares HTTP y proporciona características de seguridad, administración y registro de accesos necesarias para un entorno de producción educativo.

**Objetivos principales:**
- Servir contenido web mediante protocolo HTTP
- Registrar y auditar acceso a recursos
- Proteger la integridad del servidor mediante medidas de seguridad
- Proporcionar interfaz de administración web intuitiva
- Implementar autenticación para recursos sensibles

---

## 📝 Requisitos del Trabajo Práctico

### 1. Soporte para Protocolo HTTP

**Objetivo:** Escuchar conexiones HTTP y responder a peticiones de clientes.

**Implementación:**
```javascript
const server = http.createServer(handleRequest);
server.listen(config.port, () => {
  log(`🚀 Servidor web iniciado en puerto ${config.port}`);
});
```

**Cómo se cumple:**
- El servidor escucha en el puerto 3000 (configurable)
- Maneja peticiones GET y POST
- Sirve archivos estáticos (HTML, CSS, JS, imágenes, etc.)
- Responde con códigos HTTP estándar (200, 403, 404, 401, etc.)

---

### 2. Registro de Información (Logging)

**Objetivo:** Mantener un registro detallado de todas las actividades del servidor para auditoría y debugging.

**Archivos generados:**
- `server.log` - Registro de accesos HTTP
- `error.log` - Registro de errores del servidor

**Información registrada en cada petición:**
```
[2025-10-19T14:30:45.123Z] 127.0.0.1 - GET /index.html - Status: 200 - Size: 2048 bytes
```

Campos:
- **Marca de tiempo** (ISO 8601)
- **Dirección IP del cliente**
- **Método HTTP** (GET, POST, etc.)
- **Ruta solicitada**
- **Código de respuesta HTTP**
- **Tamaño del archivo servido**

**Función de logging:**
```javascript
function logRequest(ip, method, url, statusCode, size) {
  const message = `${ip} - ${method} ${url} - Status: ${statusCode} - Size: ${size} bytes`;
  log(message);
}
```

---

### 3. Medidas de Seguridad: Bloqueo de Acceso fuera del DocumentRoot

**Objetivo:** Evitar que usuarios malintencionados accedan a archivos del sistema operativo fuera de la carpeta designada.

**Vulnerabilidad prevenida: Path Traversal Attack**

Intentos bloqueados:
- ❌ `localhost:3000/../../../etc/passwd` → **403 Forbidden**
- ❌ `localhost:3000/../../windows/system32/config/sam` → **403 Forbidden**
- ❌ `localhost:3000/../../../../../../../../etc/passwd` → **403 Forbidden**

**Implementación técnica - Función `isPathSafe()`:**
```javascript
function isPathSafe(requestedPath) {
  const normalizedPath = path.normalize(requestedPath);    // Normaliza la ruta
  const fullPath = path.join(config.documentRoot, normalizedPath);  // Crea ruta completa
  const realPath = path.resolve(fullPath);                 // Resuelve ruta real
  const realDocRoot = path.resolve(config.documentRoot);   // Obtiene DocumentRoot real
  
  return realPath.startsWith(realDocRoot);  // Verifica si está dentro del DocumentRoot
}
```

**Ubicación en el código:**
Esta función se ejecuta en el manejador principal `handleRequest()` antes de servir cualquier archivo:

```javascript
function handleRequest(req, res) {
  // ... código anterior ...
  
  // Validar seguridad de ruta
  if (!isPathSafe(pathname)) {
    logRequest(clientIp, req.method, pathname, 403, 0);
    logError(`Intento de acceso fuera del DocumentRoot: ${pathname} desde ${clientIp}`);
    res.writeHead(403, { 'Content-Type': 'text/html' });
    res.end('<h1>403 - Forbidden</h1><p>Acceso denegado: Intento de acceso fuera del DocumentRoot</p>');
    return;  // IMPORTANTE: Detiene la ejecución aquí
  }
  
  // Si llegamos aquí, la ruta es segura
  // ... continúa sirviendo el archivo ...
}
```

**Cómo funciona:**
1. Normaliza la ruta solicitada (convierte `../` en rutas reales)
2. Obtiene la ruta absoluta completa del archivo solicitado
3. Resuelve la ruta real eliminando símbolos especiales
4. Verifica que esté dentro del DocumentRoot usando `startsWith()`
5. Si está fuera → **403 Forbidden** + registro de error
6. Si está dentro → continúa sirviendo el archivo

**Ejemplo de bloqueo:**
```
Usuario solicita: /../../../../etc/passwd
Ruta normalizada: /etc/passwd
Ruta completa: C:\proyecto\public\etc\passwd → Resolviendo...
Ruta real: C:\etc\passwd
DocumentRoot: C:\proyecto\public
¿Comienza con DocumentRoot? NO ❌
Resultado: 403 - Forbidden (bloqueado)
```

---

### 4. Interfaz para Configurar Parámetros del Servidor

**Objetivo:** Permitir la configuración del servidor mediante una interfaz web gráfica.

**Acceso:** `http://localhost:3000/admin`

**Panel de Administración incluye:**

#### 📊 Estado del Servidor
- Puerto actual
- Ruta del DocumentRoot
- Ubicación de archivos de logs
- Hora de inicio del servidor

#### ⚙️ Configurar Servidor
Campos configurables:
- **Puerto:** Número de puerto donde escucha el servidor
- **Document Root:** Ruta a la carpeta de archivos públicos
- **Archivo de Logs:** Ubicación del archivo de registro de accesos
- **Directorios Protegidos:** Configuración JSON de rutas protegidas

#### 🔐 Directorios Protegidos
Muestra la lista de:
- Rutas protegidas
- Usuarios autorizados
- Métodos de autenticación

#### 📊 Ver Logs
- Visualización en tiempo real de los logs de acceso
- Útil para auditoría y debugging

---

### 5. Protección de Directorios mediante Usuario y Contraseña

**Objetivo:** Restringir el acceso a recursos sensibles mediante autenticación.

**Dos niveles de autenticación implementados:**

#### **Nivel 1: Autenticación para Panel Admin**

**Credenciales hardcodeadas:**
- **Usuario:** `admin`
- **Contraseña:** `admin123`

**Flujo de autenticación:**
1. Usuario accede a `http://localhost:3000/admin`
2. Si no tiene sesión válida → Se redirige a página de login
3. Usuario ingresa credenciales
4. Servidor valida y crea sesión con token único
5. Token se guarda en cookie y memoria del servidor
6. Usuario puede acceder al panel

**Sistema de sesiones:**
```javascript
// Generar token único
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Crear sesión con expiración de 1 hora
function createSession(user) {
  const token = generateSessionToken();
  sessions[token] = {
    user: user,
    createdAt: Date.now(),
    expiresAt: Date.now() + (3600000) // 1 hora
  };
  return token;
}

// Validar sesión
function validateSession(token) {
  if (!token || !sessions[token]) return false;
  if (sessions[token].expiresAt < Date.now()) {
    delete sessions[token];  // Sesión expirada
    return false;
  }
  return true;
}
```

**Página de login:**
- Interfaz visual atractiva
- Muestra credenciales de prueba
- Manejo de errores
- Redirección automática tras éxito

#### **Nivel 2: Directorios Protegidos (HTTP Basic Auth)**

**Directorio protegido por defecto:**
- **Ruta:** `/privado`
- **Usuario:** `admin`
- **Contraseña:** `password123`

**Cómo acceder:**
1. Navega a `localhost:3000/privado`
2. Se abre un diálogo de autenticación del navegador
3. Ingresa usuario: `admin`
4. Ingresa contraseña: `password123`
5. Acceso concedido ✅

**Implementación técnica:**
```javascript
function checkAuth(reqPath, authHeader) {
  if (!config.protectedDirs[reqPath]) {
    return true;  // No protegido
  }

  if (!authHeader) {
    return false;  // Sin autenticación
  }

  // Decodificar credenciales básicas
  const auth = Buffer.from(authHeader.split(' ')[1], 'base64')
    .toString().split(':');
  const user = auth[0];
  const pass = auth[1];
  
  const protectedDir = config.protectedDirs[reqPath];
  return user === protectedDir.user && pass === protectedDir.pass;
}
```

---

## 🔐 Comparativa: Dos Métodos de Autenticación

| Característica | Panel Admin | Directorios Protegidos |
|---|---|---|
| **Método** | Sesión + Token | HTTP Basic Auth |
| **Login** | Página personalizada | Diálogo del navegador |
| **Duración** | 1 hora | Por sesión del navegador |
| **Uso** | Administración servidor | Proteger archivos específicos |
| **Credenciales** | `admin/admin123` | `admin/password123` (por defecto) |
| **Configuración** | Via código | Via JSON en panel admin |

---

## 🎯 Características Implementadas

| Característica | Estado | Descripción |
|---|---|---|
| Protocolo HTTP | ✅ | Servidor HTTP completo funcional |
| Logging de Accesos | ✅ | Registra IP, método, URL, estado, tamaño |
| Logging de Errores | ✅ | Captura errores del servidor |
| Prevención Path Traversal | ✅ | Bloquea acceso fuera del DocumentRoot |
| Panel Admin Web | ✅ | Interfaz gráfica de configuración |
| Autenticación Básica | ✅ | Protección con usuario/contraseña |
| Múltiples directorios protegidos | ✅ | Configurable vía JSON |
| Reinicio dinámico | ✅ | Aplica configuración sin detener servidor |
| Soporte MIME types | ✅ | Detecta tipo de contenido automáticamente |

---

## 🚀 Instalación y Configuración

### Requisitos Previos

- **Node.js** v14.0.0 o superior ([Descargar](https://nodejs.org/))
- **npm** (incluido con Node.js)
- Editor de texto o IDE (VS Code recomendado)

### Paso 1: Verificar Instalación de Node.js

```bash
node --version
npm --version
```

Deberías ver versiones válidas.

### Paso 2: Crear Carpeta del Proyecto

```bash
mkdir servidor-web
cd servidor-web
```

### Paso 3: Crear Archivo del Servidor

Crea un archivo llamado `server.js` en la carpeta `servidor-web` y copia el código completo del servidor.

### Paso 4: Iniciar el Servidor

```bash
node server.js
```

**Salida esperada:**
```
[2025-10-19T14:25:30.456Z] 🚀 Servidor web iniciado en puerto 3000
[2025-10-19T14:25:30.457Z] 📁 Document Root: C:\ruta\servidor-web\public
[2025-10-19T14:25:30.458Z] 🌐 Accede a: http://localhost:3000
[2025-10-19T14:25:30.459Z] ⚙️ Admin: http://localhost:3000/admin
```

### Paso 5: Detener el Servidor

Presiona `Ctrl + C` en la terminal.

---

## 📖 Uso del Servidor

### URLs Principales

| URL | Descripción | Ejemplo |
|---|---|---|
| `http://localhost:3000` | Página principal | Muestra index.html |
| `http://localhost:3000/admin` | Panel de administración | Gestiona configuración |
| `http://localhost:3000/privado` | Directorio protegido | Requiere autenticación |
| `http://localhost:3000/admin/logs` | Ver logs de acceso | Visualiza registros |
| `http://localhost:3000/admin/config` | Obtener configuración | JSON de config actual |

### Acciones Básicas

#### 1. Servir Página Web
```
1. Coloca un archivo HTML en: servidor-web/public/
2. Accede desde el navegador: http://localhost:3000/archivo.html
3. El servidor lo sirve automáticamente
```

#### 2. Ver Logs de Acceso
```
1. Opción A: Panel Admin → "📊 Ver Logs"
2. Opción B: Abre el archivo server.log directamente
```

#### 3. Cambiar Configuración
```
1. Accede a: http://localhost:3000/admin
2. Modifica los campos deseados
3. Haz clic en "💾 Guardar Configuración"
4. El servidor se reinicia automáticamente
```

#### 4. Acceder a Área Protegida
```
1. Navega a: http://localhost:3000/privado
2. Ingresa usuario: admin
3. Ingresa contraseña: password123
4. Acceso concedido
```

---

## 🧪 Demostración de Funcionalidades

### Prueba 1: Verificar HTTP Funcional

**Paso 1:** Abre navegador
```
URL: http://localhost:3000
```

**Resultado esperado:** ✅ Página principal carga correctamente

**Registro en server.log:**
```
[2025-10-19T14:30:00.000Z] 127.0.0.1 - GET / - Status: 200 - Size: 1500 bytes
```

---

### Prueba 2: Verificar Logging

**Paso 1:** Realiza varias acciones en el servidor
- Accede a la página principal
- Intenta acceder a un archivo no existente
- Accede al panel admin

**Paso 2:** Revisa los logs

Opción A - Panel Admin:
```
http://localhost:3000/admin → Sección "📊 Ver Logs"
```

Opción B - Archivo directo:
```
Abre: servidor-web/server.log
```

**Registro esperado:**
```
[2025-10-19T14:30:15.123Z] 127.0.0.1 - GET / - Status: 200 - Size: 1500 bytes
[2025-10-19T14:30:18.456Z] 127.0.0.1 - GET /noexiste.html - Status: 404 - Size: 0 bytes
[2025-10-19T14:30:22.789Z] 127.0.0.1 - GET /admin - Status: 200 - Size: 5000 bytes
```

---

### Prueba 3: Verificar Seguridad (Path Traversal)

**Paso 1:** Intenta acceder a archivo fuera del DocumentRoot

```
URL: http://localhost:3000/../../../etc/passwd
```

**Resultado esperado:** ❌ **403 - Forbidden**

**Registro en server.log:**
```
[2025-10-19T14:30:30.000Z] 127.0.0.1 - GET /../../../etc/passwd - Status: 403 - Size: 0 bytes
```

**Registro en error.log:**
```
[2025-10-19T14:30:30.000Z] ERROR: Intento de acceso fuera del DocumentRoot: /../../../etc/passwd desde 127.0.0.1
```

---

### Prueba 4: Verificar Protección por Contraseña

**Paso 1:** Intenta acceder sin autenticación
```
URL: http://localhost:3000/privado
```

**Resultado esperado:** ❌ Diálogo de autenticación aparece

**Registro en server.log:**
```
[2025-10-19T14:31:00.000Z] 127.0.0.1 - GET /privado - Status: 401 - Size: 0 bytes
```

**Paso 2:** Ingresa credenciales
- Usuario: `admin`
- Contraseña: `password123`

**Resultado esperado:** ✅ Acceso concedido

**Registro en server.log:**
```
[2025-10-19T14:31:05.000Z] 127.0.0.1 - GET /privado - Status: 200 - Size: 200 bytes
```

---

### Prueba 5: Verificar Panel de Administración

**Paso 1:** Accede al panel admin
```
URL: http://localhost:3000/admin
```

**Resultado esperado:** ✅ Panel se carga con información del servidor

**Secciones visibles:**
- 📋 Estado del Servidor
- 🔐 Directorios Protegidos
- ⚙️ Configurar Servidor
- 📊 Ver Logs

**Paso 2:** Modifica la configuración
- Ejemplo: Cambia el puerto a 8080
- Haz clic en "💾 Guardar Configuración"

**Resultado esperado:** ✅ Servidor se reinicia automáticamente en nuevo puerto

**Acceso nuevo:** `http://localhost:8080/admin`

---

## 📁 Estructura del Proyecto

```
servidor-web/
│
├── server.js                    ← Código principal del servidor
│
├── public/                      ← Document Root (carpeta de archivos públicos)
│   ├── index.html              ← Página principal
│   └── privado/                ← Directorio protegido por contraseña
│       └── index.html
│
├── server.log                   ← Registro de accesos HTTP
│
└── error.log                    ← Registro de errores

```

**Archivos generados automáticamente:**
- `public/` - Se crea automáticamente en primer inicio
- `server.log` - Se crea en primer acceso
- `error.log` - Se crea cuando ocurre un error

---

## 🔧 Detalles Técnicos

### Tecnologías Utilizadas

- **Lenguaje:** JavaScript (Node.js)
- **Runtime:** Node.js v14+
- **Módulos nativos:** `http`, `fs`, `path`, `url`, `crypto`
- **Sin dependencias externas:** Código 100% puro

### Módulos Node.js Utilizados

```javascript
const http = require('http');      // Crear servidor HTTP
const fs = require('fs');          // Operaciones de archivos
const path = require('path');      // Manipulación de rutas
const url = require('url');        // Parsear URLs
const crypto = require('crypto');  // Operaciones criptográficas
```

### Códigos HTTP Implementados

| Código | Descripción | Cuando se usa |
|---|---|---|
| **200** | OK | Archivo servido exitosamente |
| **401** | Unauthorized | Autenticación requerida pero no válida |
| **403** | Forbidden | Acceso denegado (fuera DocumentRoot) |
| **404** | Not Found | Archivo no existe |

### MIME Types Soportados

```javascript
{
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
}
```

### Autenticación HTTP Básica

Implementa el estándar RFC 7617 (HTTP Basic Authentication):

```
Encabezado: Authorization: Basic base64(usuario:contraseña)
Ejemplo: Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=
```

---

## 📊 Diagrama de Flujo: Manejo de Peticiones

```
Petición HTTP recibida
        ↓
    ¿Es /admin?
      Sí → Mostrar Panel Admin
      No ↓
    ¿Es directorio protegido?
      Sí → ¿Autenticación válida?
           Sí → Servir archivo
           No → 401 Unauthorized
      No ↓
    ¿Ruta está dentro de DocumentRoot?
      Sí → ¿Archivo existe?
           Sí → Servir archivo (200)
           No → 404 Not Found
      No → 403 Forbidden + Registrar error
```

---

## 🎓 Conceptos de Redes Relacionados

### Protocolo HTTP
- **Definición:** Protocolo de transferencia de hipertexto basado en solicitud-respuesta
- **Puerto:** 80 (nuestro servidor usa 3000 por ser desarrollo)
- **Métodos:** GET, POST, PUT, DELETE, etc.
- **Stateless:** Cada petición es independiente

### Seguridad en Servidores Web
- **Path Traversal:** Intento de acceder a archivos fuera de la raíz web
- **Autenticación Básica:** Mecanismo simple de usuario/contraseña
- **Auditoría (Logging):** Registro de acciones para detectar anomalías

### Directorios Virtuales
- **DocumentRoot:** Carpeta raíz donde el servidor sirve archivos públicos
- **Aislamiento:** El servidor no expone archivos fuera de esta carpeta
- **Separación:** Los archivos sensibles del SO quedan inaccesibles

---

## 📝 Notas para la Exposición Académica

### Puntos Clave a Destacar

1. **Implementación desde cero:** El servidor NO usa frameworks, es código puro Node.js
2. **Seguridad:** Demuestra vulnerabilidades comunes y cómo prevenirlas
3. **Auditoría:** Sistema de logging completo para debugging y seguridad
4. **Administración:** Interfaz gráfica para gestionar sin tocar código
5. **HTTP Estándar:** Cumple con protocolos estándar de la industria

### Preguntas Posibles en Defensa

**P: ¿Por qué usar Node.js?**
R: Porque es asincrónico, eficiente para manejar múltiples conexiones y JavaScript permite código simple pero poderoso.

**P: ¿Cómo se previenen ataques de path traversal?**
R: Normalizando las rutas y validando que estén siempre dentro del DocumentRoot con `path.resolve()`.

**P: ¿Qué sucede si se configura mal el DocumentRoot?**
R: El servidor podría quedar no funcional, pero la validación de seguridad sigue protegiendo el acceso.

**P: ¿Por qué logging es importante?**
R: Para auditoría, debugging, detección de patrones sospechosos y compliance normativo.

---

## 📚 Referencias

- [Node.js Documentation](https://nodejs.org/docs/)
- [RFC 7231 - HTTP Semantics](https://tools.ietf.org/html/rfc7231)
- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [HTTP Basic Authentication - RFC 7617](https://tools.ietf.org/html/rfc7617)

---

**Autor:** TP Nº7 - Grupo de Redes de Datos  
**Fecha:** Octubre 2025  
**Licencia:** Educacional (MIT)
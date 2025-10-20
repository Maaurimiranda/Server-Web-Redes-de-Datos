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

## Descripción General

El servidor cumple con los estándares HTTP y proporciona características de seguridad, administración y registro de accesos.

**Objetivos principales:**
- Soporte para protocolo http.
- Registro de información (Logging).
- Medidas de seguridad varias, por ejemplo: bloquear el acceso a cualquier directorio que no esté en el DocumentRoot (en la raíz del sitio Web).
- Interfaz para configurar todos los parámetros del servidor (puede ser vía web)
- Protección de directorios mediante usuario y contraseña.

---

## Requisitos del Trabajo Práctico

### 1. Soporte para Protocolo HTTP

**Objetivo:** Escuchar conexiones HTTP y responder a peticiones de clientes.

**Implementación:**
```javascript
const server = http.createServer(handleRequest);
server.listen(config.port, () => {
  log(`Servidor web iniciado en puerto ${config.port}`);
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

#### Estado del Servidor
- Puerto actual
- Ruta del DocumentRoot
- Ubicación de archivos de logs
- Hora de inicio del servidor

#### Configurar Servidor
Campos configurables:
- **Puerto:** Número de puerto donde escucha el servidor
- **Document Root:** Ruta a la carpeta de archivos públicos
- **Archivo de Logs:** Ubicación del archivo de registro de accesos
- **Directorios Protegidos:** Configuración JSON de rutas protegidas

#### Directorios Protegidos
Muestra la lista de:
- Rutas protegidas
- Usuarios autorizados
- Métodos de autenticación

#### Ver Logs
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
5. Acceso concedido 

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


### Iniciar el Servidor

```bash
node server.js
```

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

## 📝 Notas para la Exposición Académica

### Puntos Clave a Destacar

1. **Implementación desde cero:** El servidor NO usa frameworks, es código puro Node.js
2. **Seguridad:** Demuestra vulnerabilidades comunes y cómo prevenirlas
3. **Auditoría:** Sistema de logging completo para debugging y seguridad
4. **Administración:** Interfaz gráfica para gestionar sin tocar código
5. **HTTP Estándar:** Cumple con protocolos estándar de la industria

---

**Autor:** TP Nº7 - Grupo de Redes de Datos  

# Sistema de Gestión de Usuarios en OpenSearch

Este documento describe cómo el sistema de usuarios de ATTACK-SENTINEL almacena y gestiona la información de usuarios en OpenSearch.

## Descripción General

ATTACK-SENTINEL utiliza un sistema dual de almacenamiento de usuarios:

1. **Archivo JSON local** (`users.json`): Actúa como almacenamiento primario y respaldo.
2. **Índice OpenSearch** (`usuarios`): Almacenamiento principal para búsquedas rápidas y análisis.

Ambos sistemas se mantienen sincronizados automáticamente para garantizar la consistencia de los datos.

## Estructura de Datos de Usuario

Los usuarios se almacenan con la siguiente estructura en OpenSearch:

```json
{
  "username": "usuario",         // Nombre de usuario (en minúsculas, usado como ID)
  "password": "$2b$10$...",     // Contraseña hasheada con bcrypt
  "role": "user",               // Rol: "user" o "admin"
  "email": "usuario@example.com", // Correo electrónico (opcional)
  "createdAt": 1591234567890,   // Timestamp de creación (milisegundos)
  "updatedAt": 1591234567890,   // Timestamp de última actualización
  "googleId": null,             // ID de Google para OAuth (si aplica)
  "resetToken": null,           // Token para restablecimiento de contraseña
  "resetTokenExpires": null,    // Expiración del token de restablecimiento
  "passwordLastChanged": null   // Último cambio de contraseña
}
```

## Flujo de Registro de Usuario

1. El usuario envía datos de registro a `/api/register`.
2. El sistema valida los datos y verifica que el usuario no exista.
3. Se crea un nuevo objeto de usuario con la contraseña hasheada.
4. El usuario se guarda en OpenSearch con su nombre de usuario como ID.
5. El usuario también se añade al archivo `users.json` como respaldo.

## Sincronización y Migración

El sistema incluye herramientas para mantener la sincronización entre ambos almacenamientos:

1. **Migración**: Traslada usuarios desde el archivo JSON a OpenSearch.
2. **Sincronización**: Asegura que ambos sistemas tengan los mismos usuarios.
3. **Verificación**: Comprueba la integridad de los datos de usuario.

## Endpoints de Administración

Los siguientes endpoints están disponibles para gestionar usuarios (requieren autenticación de administrador):

- `GET /api/admin/users-db`: Obtiene todos los usuarios desde OpenSearch.
- `POST /api/admin/migrate-users`: Migra usuarios desde el archivo JSON a OpenSearch.
- `POST /api/admin/sync-users`: Sincroniza usuarios entre ambos almacenamientos.
- `GET /api/admin/check-user-db`: Verifica la integridad de la base de datos de usuarios.
- `DELETE /api/admin/users/:username`: Elimina un usuario de ambos almacenamientos.

## Scripts de Mantenimiento

El sistema incluye varios scripts para gestionar y verificar el almacenamiento de usuarios:

- `check-opensearch.js`: Diagnostica la conectividad y estado de OpenSearch.
- `rebuild-users-index.js`: Reconstruye el índice de usuarios en OpenSearch.
- `test-user-sync.js`: Prueba la sincronización de usuarios entre ambos sistemas.

## Solución de Problemas

Si los usuarios no aparecen correctamente en OpenSearch:

1. Ejecute `node check-opensearch.js` para diagnosticar la conectividad.
2. Utilice el endpoint `/api/admin/check-user-db` para verificar la integridad.
3. Si es necesario, migre los usuarios con `/api/admin/migrate-users`.
4. Para problemas graves, reconstruya el índice con `node rebuild-users-index.js`.

## Consideraciones de Seguridad

- Las contraseñas se almacenan hasheadas con bcrypt.
- El acceso a los endpoints de administración está restringido a usuarios con rol "admin".
- Los timestamps de creación y actualización permiten auditar la actividad de usuarios.
- La información sensible (como contraseñas) se redacta en los logs del sistema.

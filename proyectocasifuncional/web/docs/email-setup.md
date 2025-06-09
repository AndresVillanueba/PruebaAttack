# Configuración del Sistema de Recuperación de Contraseñas

Este documento explica cómo configurar correctamente el sistema de recuperación de contraseñas de ATTACK-SENTINEL para que funcione con un servicio de correo real.

## Requisitos

Para que el sistema funcione correctamente, necesitas:

1. Una cuenta de correo electrónico que permita el envío de correos a través de SMTP
2. Configurar las variables de entorno en el archivo `.env`

## Configuración del Servicio de Correo

### Usando Gmail

Si deseas utilizar Gmail como servicio de correo, sigue estos pasos:

1. Necesitarás una cuenta de Gmail
2. Es recomendable generar una "Contraseña de aplicación" en lugar de usar tu contraseña normal:
   - Ve a [Gestión de tu cuenta de Google](https://myaccount.google.com/)
   - Selecciona "Seguridad" en el menú lateral
   - En "Acceso a Google", habilita la verificación en dos pasos si aún no lo has hecho
   - Luego, busca "Contraseñas de aplicaciones"
   - Genera una nueva contraseña para "Otra aplicación (nombre personalizado)"
   - Usa esta contraseña en la configuración

3. Configura las siguientes variables en el archivo `.env`:

```
EMAIL_USER=tu_correo@gmail.com
EMAIL_PASS=tu_contraseña_de_aplicacion
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_FROM="ATTACK-SENTINEL <tu_correo@gmail.com>"
```

### Usando Otros Proveedores de Correo

Para otros proveedores como Outlook, Yahoo, etc., consulta su documentación específica sobre la configuración SMTP:

```
EMAIL_USER=tu_correo@proveedor.com
EMAIL_PASS=tu_contraseña
EMAIL_HOST=smtp.proveedor.com
EMAIL_PORT=puerto_smtp
EMAIL_FROM="ATTACK-SENTINEL <tu_correo@proveedor.com>"
```

## Prueba del Sistema

Para verificar que el sistema funcione correctamente:

1. Asegúrate de que el servidor esté ejecutándose con las variables de entorno configuradas
2. Intenta recuperar una contraseña con un correo válido
3. Verifica los logs del servidor para confirmar que el correo se envió correctamente
4. Revisa la bandeja de entrada (y la carpeta de spam) del correo utilizado

## Solución de Problemas

Si los correos no se envían:

1. Verifica que las credenciales en `.env` sean correctas
2. Comprueba que el proveedor de correo permita el acceso SMTP desde aplicaciones menos seguras
3. Si usas Gmail, asegúrate de usar una contraseña de aplicación
4. Revisa los logs del servidor para ver errores específicos
5. Prueba con otro servicio SMTP

## Seguridad

Recomendaciones de seguridad:

1. Nunca almacenes las credenciales de correo en el código fuente
2. Utiliza variables de entorno o archivos `.env` que no se suban al control de versiones
3. Considera usar servicios de correo transaccional como SendGrid, Mailgun o Amazon SES para entornos de producción
4. Implementa rate-limiting para prevenir abusos del sistema de recuperación
5. Mantén los tokens con tiempo de expiración corto (actualmente 1 hora)

Si tienes alguna pregunta o problema, contacta al administrador del sistema.

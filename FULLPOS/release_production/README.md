# 📊 Nilkas POS - Sistema de Punto de Venta

**Versión:** 1.0  
**Fecha:** Diciembre 2025  
**Plataforma:** Windows 10/11 (64-bit)

---

## 🚀 Instalación y Ejecución

### Requisitos Mínimos
- **Windows 10 o superior** (64-bit)
- **Visual C++ Redistributable** (incluido en el paquete)
- **1 GB de RAM mínimo**
- **500 MB de espacio en disco**

### Pasos para Ejecutar

1. **Extrae el archivo ZIP** a una carpeta en tu PC
2. **Navega a la carpeta extraída**
3. **Haz doble clic en `nilkas.exe`** para iniciar la aplicación

⚠️ En la primera ejecución, Windows podría mostrar una advertencia de seguridad. Haz clic en "Más información" → "Ejecutar de todas formas".

---

## ✨ Características Principales

### 📦 Módulo de Ventas
- Punto de venta interactivo con catálogo de productos
- Carrito de compras con descuentos por línea e globales
- Cálculo automático de ITBIS
- Métodos de pago: Efectivo, Tarjeta, Transferencia, Mixto
- Soporte para créditos con cliente
- Integración con NCF (Comprobantes Fiscales)
- Impresión automática de tickets

### 📋 Reportes y KPIs
- Reportes de ventas por período (Hoy, Semana, Mes, Año, Personalizado)
- Análisis de ganancias y costos
- Gráficos de tendencias de ventas
- Top productos y clientes
- Métodos de pago por distribución
- Estadísticas comparativas

### 👥 Gestión de Clientes
- Base de datos de clientes
- Historial de compras
- Créditos y seguimiento de pagos
- Contacto y RNC

### 📦 Gestión de Productos
- Catálogo de productos con fotos
- Control de stock
- Categorías y subcategorías
- Precio de costo y venta
- Búsqueda y filtros avanzados

### 💰 Gestión de Préstamos
- Sistema completo de préstamos
- Cálculo de cuotas e intereses
- Seguimiento de pagos
- Análisis de morosos
- Reportes de cobranza

### 💵 Caja
- Sesiones de caja (Abrir/Cerrar)
- Movimientos de efectivo
- Cortes de caja por turno
- Resumen de ingresos y gastos

### 🎨 Personalización
- Múltiples temas de colores (Ocean, Sunset, Forest, Purple, Dark)
- Configuración de fuentes
- Personalización de AppBar y colores de interfaz
- Configuración de impresora térmica
- Configuración de empresa

---

## 🔧 Configuración Inicial Recomendada

1. **Accede a Configuración**
2. **Empresa**: Completa datos de tu negocio
3. **Impresora**: Conecta tu impresora térmica
4. **NCF**: Configura los comprobantes fiscales disponibles
5. **Temas**: Personaliza los colores según tu preferencia

---

## 📱 Atajos de Teclado

| Tecla | Acción |
|-------|--------|
| `Ctrl + N` | Nueva venta |
| `Ctrl + P` | Procesar pago |
| `Ctrl + Q` | Finalizar venta |
| `Ctrl + D` | Aplicar descuento |

---

## 📊 Base de Datos

La aplicación utiliza SQLite local. Los datos se guardan automáticamente en:
```
%APPDATA%\nilkas\app.db
```

Se recomienda hacer copias de seguridad periódicas.

---

## ⚠️ Solución de Problemas

### "No se puede iniciar la aplicación"
- Verifica que tengas instalado Visual C++ Redistributable
- Intenta ejecutar como Administrador
- Reinicia tu PC

### "Impresora no reconocida"
- Verifica que la impresora esté conectada e instalada
- Reconfigura la impresora en Configuración → Impresora

### "Errores de base de datos"
- Elimina la carpeta `%APPDATA%\nilkas` para resetear
- Reinicia la aplicación

---

## 📞 Soporte

Para reportar bugs o solicitar features:
- Documenta el error con captura de pantalla
- Describe los pasos para reproducir el problema
- Especifica tu versión de Windows

---

## 📄 Licencia

Esta aplicación es software propietario. Todos los derechos reservados.

---

**¡Gracias por usar Nilkas POS!**

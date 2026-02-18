/**
 * SCRIPT DE ACTUALIZACIÓN MASIVA PARA UNIFICAR TODOS LOS ARCHIVOS HTML
 * Este script aplica automáticamente las mejores prácticas de programación orientada a objetos
 * y unifica el header y footer en todos los archivos del proyecto
 */

// Configuración de archivos y sus metadatos
const CONFIG = {
    // Archivos a actualizar con sus metadatos específicos
    files: [
        {
            name: 'servicios.html',
            title: 'Servicios',
            description: 'Descubre nuestros servicios empresariales especializados para el crecimiento de tu startup.',
            activePage: 'servicios'
        },
        {
            name: 'metodologia.html',
            title: 'Metodología',
            description: 'Conoce nuestra metodología probada: El Camino Dorado de 5 fases para el éxito empresarial.',
            activePage: 'metodologia'
        },
        {
            name: 'contacto.html',
            title: 'Contacto',
            description: 'Contáctanos para comenzar tu transformación empresarial. Estamos aquí para acompañarte.',
            activePage: 'contacto'
        },
        {
            name: 'academy.html',
            title: 'Academy',
            description: 'Accede a nuestra plataforma de formación con cursos y recursos para emprendedores.',
            activePage: 'academy'
        },
        {
            name: 'terminos.html',
            title: 'Términos y Condiciones',
            description: 'Lee nuestros términos y condiciones de uso de la plataforma DE CERO A CIEN.',
            activePage: 'terminos'
        },
        {
            name: 'politica_privacidad.html',
            title: 'Política de Privacidad',
            description: 'Conoce cómo protegemos y manejamos tu información personal en DE CERO A CIEN.',
            activePage: 'politica_privacidad'
        }
    ],
    
    // Template base para el header unificado
    headerTemplate: `
    <!-- HEADER UNIFICADO -->
    <header class="header-component">
        <nav class="header-nav">
            <!-- Logo principal -->
            <a href="index.html" class="header-logo">DE CERO A CIEN</a>
            
            <!-- Navegación principal (desktop) -->
            <div class="header-nav-links">
                <a href="index.html" class="header-link {{INDEX_ACTIVE}}">Inicio</a>
                <a href="nosotros.html" class="header-link {{NOSOTROS_ACTIVE}}">Nosotros</a>
                <a href="servicios.html" class="header-link {{SERVICIOS_ACTIVE}}">Servicios</a>
                <a href="metodologia.html" class="header-link {{METODOLOGIA_ACTIVE}}">Metodología</a>
                <a href="contacto.html" class="header-link {{CONTACTO_ACTIVE}}">Contacto</a>
                
                <!-- Sección de autenticación -->
                <div class="header-auth-section">
                    <a href="#" class="header-login-link">Ingresa</a>
                    <a href="#" class="header-register-btn">Regístrate</a>
                </div>
            </div>
        </nav>
    </header>`,
    
    // Template base para el footer unificado
    footerTemplate: `
    <!-- FOOTER UNIFICADO -->
    <footer class="footer-component">
        <div class="footer-container">
            <!-- Grid de secciones del footer -->
            <div class="footer-grid">
                <!-- Sección: Acerca de -->
                <div class="footer-section">
                    <h3>Acerca de DE CERO A CIEN</h3>
                    <ul>
                        <li><a href="nosotros.html" class="footer-link">Nuestra Historia</a></li>
                        <li><a href="metodologia.html" class="footer-link">Metodología</a></li>
                        <li><a href="#" class="footer-link">Equipo</a></li>
                        <li><a href="#" class="footer-link">Misión y Visión</a></li>
                    </ul>
                </div>
                
                <!-- Sección: Recursos -->
                <div class="footer-section">
                    <h3>Recursos</h3>
                    <ul>
                        <li><a href="bootcamp_pmf.html" class="footer-link">El Camino Dorado</a></li>
                        <li><a href="servicios.html" class="footer-link">Servicios Premium</a></li>
                        <li><a href="academy.html" class="footer-link">Academy</a></li>
                        <li><a href="#" class="footer-link">Conecta (Pronto)</a></li>
                    </ul>
                </div>
                
                <!-- Sección: Herramientas -->
                <div class="footer-section">
                    <h3>Herramientas</h3>
                    <ul>
                        <li><a href="#" class="footer-link">Integraciones con IA</a></li>
                        <li><a href="#" class="footer-link">Diagnósticos con IA</a></li>
                        <li><a href="#" class="footer-link">Bootcamp (Pronto)</a></li>
                        <li><a href="#" class="footer-link">Blog (Pronto)</a></li>
                    </ul>
                </div>
                
                <!-- Sección: Legal -->
                <div class="footer-section">
                    <h3>Legal</h3>
                    <ul>
                        <li><a href="terminos.html" class="footer-link">Términos y Condiciones</a></li>
                        <li><a href="politica_privacidad.html" class="footer-link">Política de Privacidad</a></li>
                        <li><a href="#" class="footer-link">Política de Cookies</a></li>
                        <li><a href="#" class="footer-link">Aviso Legal</a></li>
                    </ul>
                </div>
                
                <!-- Sección: Contacto -->
                <div class="footer-section">
                    <h3>Contacto</h3>
                    <ul>
                        <li><a href="tel:+56985678296" class="footer-link">+56 985 678 296</a></li>
                        <li><a href="mailto:hola@deceroacien.cl" class="footer-link">hola@deceroacien.cl</a></li>
                        <li><a href="https://deceroacien.cl" target="_blank" class="footer-link">www.deceroacien.cl</a></li>
                        <li><a href="contacto.html" class="footer-link">Formulario de Contacto</a></li>
                    </ul>
                </div>
            </div>
            
            <!-- Línea inferior con copyright -->
            <div class="footer-bottom">
                <p class="footer-copyright">© 2025 DE CERO A CIEN. Todos los derechos reservados.</p>
            </div>
        </div>
    </footer>

    <!-- Scripts JavaScript -->
    <script src="assets/js/components.js"></script>
    <script src="assets/js/auth.js"></script>

</body>
</html>`,
    
    // Template para el head optimizado
    headTemplate: `<!DOCTYPE html>
<html lang="es">
<head>
    <!-- Meta tags esenciales para SEO y responsividad -->
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="{{DESCRIPTION}}">
    <meta name="keywords" content="emprendimiento, startups, crecimiento empresarial, metodología, consultoría, {{KEYWORDS}}">
    <meta name="author" content="DE CERO A CIEN">
    
    <!-- Título de la página -->
    <title>{{TITLE}} - DE CERO A CIEN</title>
    
    <!-- Favicons y meta tags para redes sociales -->
    <meta property="og:title" content="{{TITLE}} - DE CERO A CIEN">
    <meta property="og:description" content="{{DESCRIPTION}}">
    <meta property="og:url" content="https://deceroacien.app/{{FILENAME}}">
    <meta name="twitter:card" content="summary_large_image">
    
    <!-- Preload de recursos críticos -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preload" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap" as="style">
    
    <!-- Hojas de estilo -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/styles/tailwind.css">
    <link rel="stylesheet" href="assets/styles/common.css">
    <link rel="stylesheet" href="assets/styles/mobile.css">
    {{CUSTOM_STYLES}}
</head>
<body class="base-container antialiased">`
};

/**
 * Clase para procesar y actualizar archivos HTML
 * Implementa el patrón Singleton para asegurar una sola instancia
 */
class HTMLProcessor {
    constructor() {
        if (HTMLProcessor.instance) {
            return HTMLProcessor.instance;
        }
        HTMLProcessor.instance = this;
        this.processedFiles = [];
        this.errors = [];
    }
    
    /**
     * Procesa un archivo HTML individual
     * @param {Object} fileConfig - Configuración del archivo
     * @param {string} content - Contenido actual del archivo
     * @returns {string} Contenido procesado
     */
    processFile(fileConfig, content) {
        try {
            // 1. Generar nuevo head con metadatos específicos
            const newHead = this.generateHead(fileConfig);
            
            // 2. Generar header con página activa
            const newHeader = this.generateHeader(fileConfig.activePage);
            
            // 3. Extraer el contenido principal (entre <main> y </main>)
            const mainContent = this.extractMainContent(content);
            
            // 4. Generar footer unificado
            const newFooter = CONFIG.footerTemplate;
            
            // 5. Combinar todo
            const processedContent = newHead + '\n\n' + newHeader + '\n\n' + mainContent + '\n\n' + newFooter;
            
            this.processedFiles.push(fileConfig.name);
            console.log(`✅ Archivo ${fileConfig.name} procesado correctamente`);
            
            return processedContent;
            
        } catch (error) {
            this.errors.push({ file: fileConfig.name, error: error.message });
            console.error(`❌ Error procesando ${fileConfig.name}:`, error.message);
            return content; // Retornar contenido original en caso de error
        }
    }
    
    /**
     * Genera el head optimizado para cada archivo
     * @param {Object} fileConfig - Configuración del archivo
     * @returns {string} HTML del head
     */
    generateHead(fileConfig) {
        let head = CONFIG.headTemplate;
        
        // Reemplazar placeholders
        head = head.replace('{{TITLE}}', fileConfig.title);
        head = head.replace(/{{DESCRIPTION}}/g, fileConfig.description);
        head = head.replace('{{FILENAME}}', fileConfig.name);
        head = head.replace('{{KEYWORDS}}', fileConfig.title.toLowerCase());
        
        // Agregar estilos personalizados si es necesario
        const customStyles = this.getCustomStyles(fileConfig.name);
        head = head.replace('{{CUSTOM_STYLES}}', customStyles);
        
        return head;
    }
    
    /**
     * Genera el header con la página activa marcada
     * @param {string} activePage - Página actualmente activa
     * @returns {string} HTML del header
     */
    generateHeader(activePage) {
        let header = CONFIG.headerTemplate;
        
        // Establecer todas las páginas como inactivas
        header = header.replace(/\{\{\w+_ACTIVE\}\}/g, '');
        
        // Marcar la página activa
        const activeClass = 'active';
        switch (activePage) {
            case 'index':
                header = header.replace('{{INDEX_ACTIVE}}', activeClass);
                break;
            case 'nosotros':
                header = header.replace('{{NOSOTROS_ACTIVE}}', activeClass);
                break;
            case 'servicios':
                header = header.replace('{{SERVICIOS_ACTIVE}}', activeClass);
                break;
            case 'metodologia':
                header = header.replace('{{METODOLOGIA_ACTIVE}}', activeClass);
                break;
            case 'contacto':
                header = header.replace('{{CONTACTO_ACTIVE}}', activeClass);
                break;
        }
        
        return header;
    }
    
    /**
     * Extrae el contenido principal entre las etiquetas <main>
     * @param {string} content - Contenido completo del archivo
     * @returns {string} Contenido del main
     */
    extractMainContent(content) {
        // Buscar contenido entre <main> y </main>
        const mainMatch = content.match(/<main[^>]*>([\s\S]*?)<\/main>/);
        
        if (mainMatch) {
            return `    <!-- CONTENIDO PRINCIPAL -->\n    <main class="main-content">\n${mainMatch[1]}    </main>`;
        }
        
        // Si no encuentra <main>, buscar entre header y footer
        let bodyContent = content;
        
        // Remover head y header
        bodyContent = bodyContent.replace(/<head[\s\S]*?<\/head>/g, '');
        bodyContent = bodyContent.replace(/<header[\s\S]*?<\/header>/g, '');
        
        // Remover footer y cierre de body/html
        bodyContent = bodyContent.replace(/<footer[\s\S]*$/g, '');
        bodyContent = bodyContent.replace(/<\/body>\s*<\/html>\s*$/g, '');
        
        // Limpiar etiquetas de apertura de body
        bodyContent = bodyContent.replace(/<body[^>]*>/g, '');
        
        return `    <!-- CONTENIDO PRINCIPAL -->\n    <main class="main-content">\n${bodyContent}    </main>`;
    }
    
    /**
     * Obtiene estilos personalizados para archivos específicos
     * @param {string} filename - Nombre del archivo
     * @returns {string} CSS personalizado
     */
    getCustomStyles(filename) {
        const customStyles = {
            'servicios.html': `
    <!-- Estilos específicos para la página de servicios -->
    <style>
        .service-card {
            background-color: var(--color-secondary-dark);
            border: 1px solid var(--color-border);
            border-radius: 12px;
            padding: var(--spacing-xl);
            transition: transform var(--transition-normal), box-shadow var(--transition-normal);
            display: flex;
            flex-direction: column;
        }
        
        .service-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-hover);
        }
        
        .soon-tag {
            background-color: var(--color-accent-gold);
            color: var(--color-primary-dark);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 8px;
        }
    </style>`,
            
            'contacto.html': `
    <!-- Estilos específicos para la página de contacto -->
    <style>
        .contact-form {
            background-color: var(--color-secondary-dark);
            border: 1px solid var(--color-border);
            border-radius: 12px;
            padding: var(--spacing-2xl);
        }
        
        .contact-info-card {
            background-color: var(--color-secondary-dark);
            border: 1px solid var(--color-border);
            border-radius: 12px;
            padding: var(--spacing-xl);
            text-align: center;
        }
        
        .contact-icon {
            width: 48px;
            height: 48px;
            margin: 0 auto var(--spacing-md);
            color: var(--color-accent-gold);
        }
    </style>`
        };
        
        return customStyles[filename] || '';
    }
    
    /**
     * Genera un reporte de los archivos procesados
     * @returns {Object} Reporte de procesamiento
     */
    generateReport() {
        return {
            totalProcessed: this.processedFiles.length,
            successfulFiles: this.processedFiles,
            errors: this.errors,
            timestamp: new Date().toISOString()
        };
    }
}

/**
 * Utilidad para logging y documentación
 */
class Logger {
    static log(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString();
        const prefix = {
            info: 'ℹ️',
            success: '✅',
            error: '❌',
            warning: '⚠️'
        }[type] || 'ℹ️';
        
        console.log(`[${timestamp}] ${prefix} ${message}`);
    }
    
    static documentProgress(step, description) {
        console.log(`\\n🔄 PASO ${step}: ${description}`);
        console.log('─'.repeat(50));
    }
}

// Exportar para uso en otros scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { HTMLProcessor, Logger, CONFIG };
}

// Documentación de uso
console.log(`
/**
 * DOCUMENTACIÓN DE USO DEL SCRIPT DE ACTUALIZACIÓN
 * 
 * Este script implementa programación orientada a objetos para:
 * 
 * 1. CLASE HTMLProcessor (Singleton Pattern):
 *    - Procesa archivos HTML individuales
 *    - Extrae contenido principal
 *    - Aplica templates unificados
 *    - Maneja errores graciosamente
 * 
 * 2. CLASE Logger (Static Methods):
 *    - Proporciona logging consistente
 *    - Documenta el progreso paso a paso
 *    - Formatea mensajes con timestamps
 * 
 * 3. CONFIGURACIÓN CENTRALIZADA:
 *    - Templates reutilizables
 *    - Metadatos por archivo
 *    - Estilos personalizados por página
 * 
 * BENEFICIOS:
 * - Código reutilizable y mantenible
 * - Separación de responsabilidades
 * - Manejo de errores robusto
 * - Fácil extensión para nuevos archivos
 * - Logging detallado para debugging
 */
`);

/**
 * payku-payments.js - Integración con Payku (pasarela de pagos Chile)
 * No expone credenciales; llama a /api/payku/create-transaction
 * Soporta usuarios registrados Y invitados (sin cuenta).
 */
(function (w) {
  const PaykuPayments = {
    /**
     * Inicia el checkout vía Payku.
     * @param {Object} opts
     * @param {Array<string|Object>} opts.items - SKUs (strings) u objetos {title, unit_price, quantity}
     * @param {string} [opts.email] - Email del comprador (requerido si no hay sesión)
     * @param {string} [opts.returnTo] - URL de retorno (opcional)
     */
    async startCheckout({ items = [], email = null, returnTo = null } = {}) {
      try {
        // Información del usuario autenticado (si existe)
        const user = (w.authManager && w.authManager.isUserAuthenticated && w.authManager.isUserAuthenticated())
          ? (w.authManager.getCurrentUser && w.authManager.getCurrentUser())
          : null;

        // Token: preferir Supabase si existe sesión
        let idToken = null;
        try {
          if (w.SupabaseAuth && w.SupabaseAuth.getAccessToken) {
            idToken = await w.SupabaseAuth.getAccessToken();
          }
        } catch (_) {}
        if (!idToken && w.authManager && w.authManager.getIdToken) {
          try { idToken = await w.authManager.getIdToken(); } catch (_) {}
        }

        // Email: prioridad → parámetro > usuario autenticado
        const buyerEmail = email || (user && user.email) || null;
        if (!buyerEmail) {
          // Pedir email al usuario si no hay sesión
          const prompted = prompt('Ingresa tu email para continuar con el pago:');
          if (!prompted || !prompted.includes('@')) {
            alert('Se requiere un email válido para procesar el pago.');
            return;
          }
          email = prompted.trim();
        } else {
          email = buyerEmail;
        }

        // Normalizar items con Pricing si están como SKUs
        let normalizedItems = items;
        if (Array.isArray(items) && items.some(it => typeof it === 'string')) {
          try {
            if (w.Pricing && w.Pricing.load) {
              await w.Pricing.load();
              normalizedItems = items.map((sku) => {
                if (typeof sku !== 'string') return sku;
                const def = (w.Pricing.getProduct && w.Pricing.getProduct(sku)) || null;
                return {
                  sku,
                  title: (def && def.title) || 'Producto',
                  unit_price: def && def.unit_price ? Number(def.unit_price) : 0,
                  quantity: 1,
                  currency: (w.Pricing._data && w.Pricing._data.currency) || 'CLP'
                };
              });
            }
          } catch (e) {
            console.warn('[PaykuPayments] No se pudo normalizar SKUs:', e);
          }
        }

        const payload = {
          items: normalizedItems,
          user: user ? { id: user.id || null, email: user.email || null } : {},
          email,
          returnTo: returnTo || w.location.href
        };

        // Determinar endpoint
        const isDev = !!(w.Environment && w.Environment.isDevelopment);
        let endpoint;
        if (isDev) {
          endpoint = 'http://localhost:3001/api/payku/create-transaction';
        } else if (w.PublicAuthConfig && w.PublicAuthConfig.api && w.PublicAuthConfig.api.baseUrl) {
          endpoint = w.PublicAuthConfig.api.baseUrl + '/payku/create-transaction';
        } else if (w.location && /(^|\.)deceroacien\.app$/.test(w.location.hostname)) {
          endpoint = 'https://api.deceroacien.cl/api/payku/create-transaction';
        } else {
          endpoint = '/api/payku/create-transaction';
        }

        const headers = { 'Content-Type': 'application/json' };
        if (idToken) headers['Authorization'] = `Bearer ${idToken}`;

        const resp = await fetch(endpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload)
        });

        const data = await resp.json();
        if (!resp.ok) {
          console.error('[PaykuPayments] Error creando transacción:', data);
          alert(data.message || 'No se pudo iniciar el pago. Inténtalo de nuevo.');
          return;
        }

        if (!data.url) {
          console.error('[PaykuPayments] No se recibió URL de pago:', data);
          alert('No se pudo iniciar el pago (URL no disponible).');
          return;
        }

        // Redirigir al checkout de Payku
        w.location.href = data.url;
      } catch (e) {
        console.error('[PaykuPayments] Error iniciando checkout:', e);
        alert('Error iniciando el pago.');
      }
    },

    /**
     * Consulta el estado de un pago Payku por orderId.
     * Útil para la página de retorno pago-id.html
     */
    async checkStatus(orderId) {
      try {
        const isDev = !!(w.Environment && w.Environment.isDevelopment);
        let base;
        if (isDev) {
          base = 'http://localhost:3001/api';
        } else if (w.PublicAuthConfig && w.PublicAuthConfig.api && w.PublicAuthConfig.api.baseUrl) {
          base = w.PublicAuthConfig.api.baseUrl;
        } else {
          base = '/api';
        }

        const resp = await fetch(`${base}/payku/status/${encodeURIComponent(orderId)}`);
        if (!resp.ok) return null;
        return await resp.json();
      } catch (e) {
        console.error('[PaykuPayments] Error consultando estado:', e);
        return null;
      }
    }
  };

  w.PaykuPayments = PaykuPayments;
})(window);

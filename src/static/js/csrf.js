/*
 * Protecao CSRF no cliente (sem dependencias).
 * - Injeta o campo oculto "csrf_token" em todo <form method="POST">.
 * - Adiciona o cabecalho "X-CSRFToken" em chamadas fetch() de mesma origem que alteram estado.
 * O token vem de <meta name="csrf-token"> renderizado pelo servidor (base.html).
 */
(function () {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (!meta) return;
    var token = meta.getAttribute('content');

    function addTokenToForm(form) {
        if ((form.getAttribute('method') || '').toUpperCase() !== 'POST') return;
        if (form.querySelector('input[name="csrf_token"]')) return;
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'csrf_token';
        input.value = token;
        form.appendChild(input);
    }

    function addTokenToAllForms() {
        document.querySelectorAll('form').forEach(addTokenToForm);
    }

    document.addEventListener('DOMContentLoaded', addTokenToAllForms);
    document.addEventListener('submit', function (e) { addTokenToForm(e.target); }, true);

    var originalFetch = window.fetch;
    if (originalFetch) {
        window.fetch = function (resource, init) {
            init = init || {};
            var method = (init.method || 'GET').toUpperCase();
            var url = typeof resource === 'string' ? resource : (resource && resource.url) || '';
            var sameOrigin = new URL(url, window.location.href).origin === window.location.origin;
            if (sameOrigin && ['POST', 'PUT', 'PATCH', 'DELETE'].indexOf(method) !== -1) {
                var headers = new Headers(init.headers || {});
                headers.set('X-CSRFToken', token);
                init.headers = headers;
            }
            return originalFetch.call(this, resource, init);
        };
    }
})();

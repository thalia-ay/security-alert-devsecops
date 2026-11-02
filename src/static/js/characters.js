/**
 * Security Alert - Personagens estilo Pixie Haus
 * SVGs cartoon com estilo vibrante e expressivo
 */

const Characters = {
    /**
     * Chefe Carlos - Mentor bigodudo, estilo cartoon
     * Usa oculos, terno azul marinho, expressao amigavel
     */
    boss: `
    <svg viewBox="0 0 160 200" width="140" height="175" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <radialGradient id="skin" cx="50%" cy="40%" r="50%">
                <stop offset="0%" stop-color="#f5c6a0"/>
                <stop offset="100%" stop-color="#d4956b"/>
            </radialGradient>
            <radialGradient id="hair" cx="50%" cy="30%" r="60%">
                <stop offset="0%" stop-color="#5a5a5a"/>
                <stop offset="100%" stop-color="#2c2c2c"/>
            </radialGradient>
        </defs>
        <!-- Cabelo -->
        <ellipse cx="80" cy="55" rx="42" ry="38" fill="url(#hair)"/>
        <rect x="42" y="40" width="10" height="20" rx="5" fill="url(#hair)"/>
        <rect x="108" y="40" width="10" height="20" rx="5" fill="url(#hair)"/>
        <!-- Rosto -->
        <ellipse cx="80" cy="72" rx="35" ry="32" fill="url(#skin)"/>
        <!-- Bigode -->
        <path d="M55 82 Q80 98 105 82" stroke="#4a3728" stroke-width="5" fill="none" stroke-linecap="round"/>
        <!-- Oculos -->
        <circle cx="65" cy="68" r="12" fill="white" stroke="#333" stroke-width="2.5"/>
        <circle cx="95" cy="68" r="12" fill="white" stroke="#333" stroke-width="2.5"/>
        <line x1="77" y1="68" x2="83" y2="68" stroke="#333" stroke-width="2.5"/>
        <!-- Olhos -->
        <circle cx="65" cy="68" r="5" fill="#2c1810"/>
        <circle cx="63" cy="66" r="1.8" fill="white"/>
        <circle cx="95" cy="68" r="5" fill="#2c1810"/>
        <circle cx="93" cy="66" r="1.8" fill="white"/>
        <!-- Sobrancelhas grossas -->
        <line x1="53" y1="58" x2="75" y2="56" stroke="#333" stroke-width="3" stroke-linecap="round"/>
        <line x1="85" y1="56" x2="107" y2="58" stroke="#333" stroke-width="3" stroke-linecap="round"/>
        <!-- Corpo - terno -->
        <rect x="45" y="105" width="70" height="55" rx="12" fill="#1a3a5c"/>
        <rect x="60" y="105" width="40" height="55" fill="#1e4570"/>
        <!-- Gravata -->
        <polygon points="75,110 85,110 83,135 80,140 77,135" fill="#e74c3c"/>
        <!-- Bracos -->
        <rect x="30" y="115" width="18" height="40" rx="9" fill="#1a3a5c"/>
        <rect x="112" y="115" width="18" height="40" rx="9" fill="#1a3a5c"/>
        <!-- Maos -->
        <circle cx="39" cy="158" r="10" fill="url(#skin)"/>
        <circle cx="121" cy="158" r="10" fill="url(#skin)"/>
        <!-- Pranchinha "CHEFE" -->
        <rect x="50" y="165" width="60" height="22" rx="6" fill="white" stroke="#ccc" stroke-width="1"/>
        <text x="80" y="180" text-anchor="middle" font-size="10" font-weight="bold" fill="#1a3a5c" font-family="sans-serif">CHEFE</text>
    </svg>`,

    /**
     * Novato(a) - Jogador, personagem jovem e animado
     */
    player: `
    <svg viewBox="0 0 140 180" width="120" height="155" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <radialGradient id="skin2" cx="50%" cy="40%" r="50%">
                <stop offset="0%" stop-color="#fddcb5"/>
                <stop offset="100%" stop-color="#e8b88a"/>
            </radialGradient>
        </defs>
        <!-- Cabelo -->
        <ellipse cx="70" cy="48" rx="38" ry="35" fill="#3a1f0a"/>
        <path d="M35 50 Q25 35 30 25 Q40 18 55 20 Q70 22 85 20 Q100 18 110 25 Q115 35 105 50" fill="#3a1f0a"/>
        <!-- Franja -->
        <path d="M42 45 Q55 30 70 28 Q85 30 98 45 Q85 35 70 33 Q55 35 42 45" fill="#4a2810"/>
        <!-- Rosto -->
        <ellipse cx="70" cy="65" rx="32" ry="30" fill="url(#skin2)"/>
        <!-- Olhos grandes (estilo cartoon) -->
        <ellipse cx="58" cy="63" rx="9" ry="11" fill="white" stroke="#333" stroke-width="2"/>
        <ellipse cx="82" cy="63" rx="9" ry="11" fill="white" stroke="#333" stroke-width="2"/>
        <circle cx="58" cy="64" r="5.5" fill="#4a2810"/>
        <circle cx="56" cy="61" r="2" fill="white"/>
        <circle cx="82" cy="64" r="5.5" fill="#4a2810"/>
        <circle cx="80" cy="61" r="2" fill="white"/>
        <!-- Bochechas rosadas -->
        <ellipse cx="50" cy="72" rx="7" ry="4" fill="rgba(255,150,150,.3)"/>
        <ellipse cx="90" cy="72" rx="7" ry="4" fill="rgba(255,150,150,.3)"/>
        <!-- Sorriso -->
        <path d="M62 76 Q70 84 78 76" stroke="#d47a6a" stroke-width="2" fill="none" stroke-linecap="round"/>
        <!-- Corpo - Uniforme Leroy Merlin -->
        <rect x="42" y="96" width="56" height="48" rx="10" fill="#27ae60"/>
        <rect x="42" y="96" width="56" height="15" rx="10" fill="#2ecc71"/>
        <!-- Cracha -->
        <rect x="56" y="105" width="28" height="18" rx="3" fill="white"/>
        <text x="70" y="117" text-anchor="middle" font-size="7" font-weight="bold" fill="#27ae60" font-family="sans-serif">NOVATO</text>
        <!-- Bracos -->
        <rect x="28" y="105" width="16" height="35" rx="8" fill="#27ae60"/>
        <rect x="96" y="105" width="16" height="35" rx="8" fill="#27ae60"/>
        <circle cx="36" cy="143" r="9" fill="url(#skin2)"/>
        <circle cx="104" cy="143" r="9" fill="url(#skin2)"/>
        <!-- Pernas -->
        <rect x="48" y="144" width="20" height="30" rx="8" fill="#2c3e50"/>
        <rect x="72" y="144" width="20" height="30" rx="8" fill="#2c3e50"/>
    </svg>`,

    /**
     * Hacker - Vilao que aparece quando erra
     */
    hacker: `
    <svg viewBox="0 0 140 180" width="120" height="155" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <radialGradient id="hackerglow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stop-color="rgba(255,0,0,.4)"/>
                <stop offset="100%" stop-color="rgba(255,0,0,0)"/>
            </radialGradient>
        </defs>
        <!-- Glow vermelho -->
        <circle cx="70" cy="80" r="70" fill="url(#hackerglow)"/>
        <!-- Capuz -->
        <path d="M30 70 Q30 20 70 15 Q110 20 110 70 L100 70 Q100 35 70 30 Q40 35 40 70 Z" fill="#1a1a1a"/>
        <path d="M110 70 Q120 85 115 110" stroke="#1a1a1a" stroke-width="12" fill="none"/>
        <!-- Rosto sombrio -->
        <ellipse cx="70" cy="75" rx="28" ry="25" fill="#2a2a2a"/>
        <!-- Olhos vermelhos brilhantes -->
        <ellipse cx="58" cy="72" rx="8" ry="5" fill="#ff0000"/>
        <ellipse cx="82" cy="72" rx="8" ry="5" fill="#ff0000"/>
        <circle cx="58" cy="72" r="3" fill="#ff4444"/>
        <circle cx="82" cy="72" r="3" fill="#ff4444"/>
        <circle cx="56" cy="70" r="1" fill="white"/>
        <circle cx="80" cy="70" r="1" fill="white"/>
        <!-- Sorriso maligno -->
        <path d="M58 85 Q70 96 82 85" stroke="#444" stroke-width="2" fill="none"/>
        <line x1="62" y1="85" x2="62" y2="90" stroke="#444" stroke-width="1.5"/>
        <line x1="78" y1="85" x2="78" y2="90" stroke="#444" stroke-width="1.5"/>
        <!-- Corpo escuro -->
        <rect x="42" y="105" width="56" height="45" rx="10" fill="#1a1a1a"/>
        <!-- Simbolo de caveira -->
        <text x="70" y="120" text-anchor="middle" font-size="18">☠️</text>
        <!-- Maos com "luvas" -->
        <circle cx="35" cy="130" r="10" fill="#333"/>
        <circle cx="105" cy="130" r="10" fill="#333"/>
        <!-- Linhas de codigo caindo -->
        <text x="20" y="100" font-size="7" fill="rgba(0,255,0,.3)" font-family="monospace">01</text>
        <text x="110" y="95" font-size="7" fill="rgba(0,255,0,.3)" font-family="monospace">10</text>
    </svg>`
};

// Funcao pra injetar personagem
function showCharacter(type, containerId) {
    const container = document.getElementById(containerId);
    if (container && Characters[type]) {
        container.innerHTML = Characters[type];
    }
}

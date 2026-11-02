"""
Security Alert - Plataforma de Treinamento em Ciberseguranca
Challenge Leroy Merlin 2026 - FIAP Defesa Cibernetica
Grupo: Ana Luiza, Maria Eduarda (Duda), Pedro Henrique, Thalia
"""

import os
import re
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, g, jsonify, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

# ─── Configuracao ────────────────────────────────────────────
app = Flask(__name__)


def _env_bool(name, default=False):
    """Le uma variavel de ambiente booleana ("1", "true", "yes", "on")."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


# SECRET_KEY DEVE ser definida (fixa) em producao via variavel de ambiente.
# Sem ela, uma chave aleatoria e gerada a cada inicializacao: as sessoes sao
# invalidadas a cada restart e nao sao compartilhadas entre workers do gunicorn.
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Flags do cookie de sessao. SESSION_COOKIE_SECURE=false somente para
# execucao local via HTTP (sem TLS).
app.config['SESSION_COOKIE_SECURE'] = _env_bool('SESSION_COOKIE_SECURE', True)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Limite de tamanho das requisicoes (uploads de avatar): 2 MB
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

app.config['AVATAR_UPLOAD_DIR'] = os.path.join(app.root_path, 'static', 'img', 'avatars')

DATABASE = os.environ.get('DATABASE_PATH') or os.path.join(app.instance_path, 'security_alert.db')

# Assinaturas (magic bytes) aceitas para o upload de avatar
IMAGE_SIGNATURES = {
    'png': [b'\x89PNG\r\n\x1a\n'],
    'jpg': [b'\xff\xd8\xff'],
    'jpeg': [b'\xff\xd8\xff'],
    'gif': [b'GIF87a', b'GIF89a'],
    'webp': [b'RIFF'],  # complementado pela checagem de "WEBP" no offset 8
}


def image_matches_extension(header, ext):
    """Confere se os primeiros bytes do arquivo correspondem a extensao informada."""
    signatures = IMAGE_SIGNATURES.get(ext)
    if not signatures:
        return False
    if not any(header.startswith(sig) for sig in signatures):
        return False
    if ext == 'webp' and header[8:12] != b'WEBP':
        return False
    return True


def is_safe_redirect(target):
    """Permite apenas caminhos relativos locais (evita open redirect)."""
    if not target or not target.startswith('/'):
        return False
    if target.startswith('//') or target.startswith('/\\'):
        return False
    return True

# ─── Badges disponiveis (emoji depois troca por imagem) ───────
# Nova grade alinhada as fases do treinamento.
BADGES = [
    {
        "id": "escudo",
        "icon": "img/badges/escudo.png",
        "name": "Escudo de Conclusão",
        "description": "Complete todo o treinamento de segurança.",
        "requirement": "Termine uma sessão de jogo completa.",
        "rarity": "comum"
    },
    {
        "id": "chave",
        "icon": "img/badges/chave.png",
        "name": "Mestre das Senhas",
        "description": "Complete a primeira fase sobre senhas seguras.",
        "requirement": "Termine a fase Senhas Seguras.",
        "rarity": "comum"
    },
    {
        "id": "cadeado",
        "icon": "img/badges/cadeado.png",
        "name": "Guardiao da Atencao",
        "description": "Complete a fase de Negligência e Atenção.",
        "requirement": "Termine a fase Negligência e Atenção.",
        "rarity": "comum"
    },
    {
        "id": "phishing",
        "icon": "img/badges/phishing.png",
        "name": "Phishing Invicto",
        "description": "Complete a fase de Phishing.",
        "requirement": "Termine a fase Phishing.",
        "rarity": "raro"
    },
    {
        "id": "engrenagem",
        "icon": "img/badges/engrenagem.png",
        "name": "Anti Engenharia Social",
        "description": "Complete a fase de Engenharia Social.",
        "requirement": "Termine a fase ligação - Engenharia Social (telefone).",
        "rarity": "raro"
    },
    {
        "id": "celular",
        "icon": "img/badges/celular.png",
        "name": "Uso Consciente de Dispositivos",
        "description": "Complete a fase de Uso de dispositivos pessoais.",
        "requirement": "Termine a fase Uso de dispositivos pessoais.",
        "rarity": "raro"
    },
    {
        "id": "robo",
        "icon": "img/badges/robo.png",
        "name": "Mestre da IA",
        "description": "Complete a fase de Inteligencia Artificial.",
        "requirement": "Termine a fase Uso de IA.",
        "rarity": "epico"
    },
    {
        "id": "cem_porcento",
        "icon": "img/badges/cem.png",
        "name": "Score Perfeito",
        "description": "Atinja a pontuação máxima em uma sessão.",
        "requirement": "Pontuação total máxima em um jogo.",
        "rarity": "epico"
    }
]

# ─── Filtros Jinja ───────────────────────────────────────────
@app.template_filter('br_date')
def br_date(value):
    """Converte 'YYYY-MM-DD' ou 'YYYY-MM-DD HH:MM:SS' (TIMESTAMP do SQLite)
    para 'DD/MM/AAAA'. Devolve o valor original se nao der pra parsear."""
    if not value:
        return value
    s = str(value)
    # Pega so a parte da data (antes do espaco, se houver)
    date_part = s.split(' ')[0] if ' ' in s else s[:10]
    parts = date_part.split('-')
    if len(parts) == 3 and len(parts[0]) == 4 and len(parts[1]) == 2 and len(parts[2]) == 2:
        return f'{parts[2]}/{parts[1]}/{parts[0]}'
    return s

# ─── Banco de Dados ──────────────────────────────────────────
def get_db():
    if 'db' not in g:
        os.makedirs(app.instance_path, exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            show_in_ranking BOOLEAN DEFAULT 1,
            character TEXT DEFAULT 'ana',
            profile_image TEXT,
            loja TEXT,
            reset_token TEXT,
            reset_token_expires TIMESTAMP,
            is_admin BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS game_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            score INTEGER DEFAULT 0,
            max_score INTEGER DEFAULT 0,
            current_phase INTEGER DEFAULT 1,
            current_subphase INTEGER DEFAULT 1,
            completed BOOLEAN DEFAULT 0,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS phase_answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            phase INTEGER NOT NULL,
            subphase INTEGER NOT NULL,
            correct BOOLEAN NOT NULL,
            timed_out BOOLEAN DEFAULT 0,
            answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (session_id) REFERENCES game_sessions(id)
        );

        CREATE TABLE IF NOT EXISTS user_badges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            badge_id TEXT NOT NULL,
            unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, badge_id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    # Migra banco existente (caso ja exista sem as colunas)
    cols = [r["name"] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    if "show_in_ranking" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN show_in_ranking BOOLEAN DEFAULT 1")
    if "character" not in cols:
        # DDL nao aceita parametros (?) no DEFAULT; usa literal fixo (= DEFAULT_CHARACTER)
        db.execute("ALTER TABLE users ADD COLUMN character TEXT DEFAULT 'ana'")
    if "profile_image" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN profile_image TEXT")
    if "loja" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN loja TEXT")
    if "is_admin" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0")
    answer_cols = [r["name"] for r in db.execute("PRAGMA table_info(phase_answers)").fetchall()]
    if "timed_out" not in answer_cols:
        db.execute("ALTER TABLE phase_answers ADD COLUMN timed_out BOOLEAN DEFAULT 0")
    db.commit()
    bootstrap_admin(db)


def bootstrap_admin(db):
    """Cria um administrador inicial a partir de variaveis de ambiente (opcional).

    Usado porque o banco nao e versionado: em um ambiente novo nao existe
    nenhum admin. Definir ADMIN_USERNAME, ADMIN_EMAIL e ADMIN_PASSWORD
    (via secrets) para habilitar.
    """
    username = os.environ.get('ADMIN_USERNAME', '').strip().lower()
    email = os.environ.get('ADMIN_EMAIL', '').strip().lower()
    password = os.environ.get('ADMIN_PASSWORD', '')
    if not (username and email and len(password) >= 12):
        return
    exists = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if exists:
        return
    db.execute(
        "INSERT INTO users (username, email, password_hash, is_admin, show_in_ranking) VALUES (?, ?, ?, 1, 0)",
        (username, email, generate_password_hash(password))
    )
    db.commit()

# ─── Protecao CSRF (token sincronizador, sem dependencias) ─────
CSRF_PROTECTED_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}


def generate_csrf_token():
    """Gera (uma vez por sessao) e devolve o token CSRF."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token


@app.before_request
def csrf_protect():
    """Valida o token CSRF em toda requisicao que altera estado."""
    if not app.config.get('CSRF_ENABLED', True):
        return None
    if request.method not in CSRF_PROTECTED_METHODS:
        return None
    expected = session.get('csrf_token')
    received = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    if not expected or not received or not secrets.compare_digest(expected, received):
        abort(400, description='Token CSRF ausente ou invalido.')
    return None


# ─── Cabecalhos de seguranca ─────────────────────────────────
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    # Os templates usam scripts/estilos inline: 'unsafe-inline' e um risco
    # aceito e documentado em docs/observacoes.md.
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = CONTENT_SECURITY_POLICY
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    if app.config.get('SESSION_COOKIE_SECURE'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Paginas dinamicas nao devem ser armazenadas em cache (dados de sessao)
    if not request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'no-store'
    # Oculta a versao do servidor
    response.headers.pop('Server', None)
    return response


# ─── Decorator de Autenticacao ────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Voce precisa fazer login para acessar essa pagina.', 'warning')
            return redirect(url_for('login', next=request.full_path.rstrip('?')))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Voce precisa fazer login para acessar essa pagina.', 'warning')
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            flash('Acesso restrito a administradores.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# ─── Dados do Jogo ───────────────────────────────────────────
CHARACTERS = {
    "ana":                          {"name": "Ana",       "sprite": "img/personagens/ana.png"},
    "donoleroy":                    {"name": "Patrão",    "sprite": "img/personagens/donoleroy.png"},
    "fabi":                         {"name": "Fabi",      "sprite": "img/personagens/fabi.png"},
    "homembrancocadeirantepaulo":   {"name": "Paulo",     "sprite": "img/personagens/homembrancocadeirantepaulo.png"},
    "homembrancocarlos":            {"name": "Carlos",    "sprite": "img/personagens/homembrancocarlos.png"},
    "homemnegrocadeiranteheitor":   {"name": "Heitor",    "sprite": "img/personagens/homemnegrocadeiranteheitor.png"},
    "homemnegromanuel":             {"name": "Manuel",    "sprite": "img/personagens/homemnegromanuel.png"},
    "mulherbrancacadeirantefernanda":{"name": "Fernanda",  "sprite": "img/personagens/mulherbrancacadeirantefernanda.png"},
    "mulhernegrapamela":            {"name": "Pamela",    "sprite": "img/personagens/mulhernegrapamela.png"},
    "mulherpretacadeiranterose":    {"name": "Rose",      "sprite": "img/personagens/mulherpretacadeiranterose.png"},
    "pedro":                        {"name": "Pedro",     "sprite": "img/personagens/pedro.png"},
    "silvio":                       {"name": "Silvio",    "sprite": "img/personagens/silvio.png"},
}
DEFAULT_CHARACTER = "ana"

# Ordem de giro (volta completa) para a animacao na tela de selecao
SPIN_ORDER = ["south", "south-west", "west", "north-west",
              "north", "north-east", "east", "south-east"]

def get_spin_frames(char_key):
    """Lista de URLs dos sprites de rotacao existentes para o personagem girar."""
    frames = []
    for direction in SPIN_ORDER:
        rel = f"img/personagens/spin/{char_key}/{direction}.png"
        if os.path.exists(os.path.join(app.static_folder, *rel.split('/'))):
            frames.append(f"{app.static_url_path}/{rel}")
    return frames

GAME_PHASES = {
    1: {
        "title": "Fase 1: Senhas Seguras",
        "icon": "🔑",
        "color": "#f8bce4",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Bem-vindo(a) ao seu primeiro dia de treinamento! "
            "Sou seu chefe, Carlos, e vou te ensinar sobre a importância de senhas fortes no seu dia a dia! "
            "Sabia que senhas fracas são a principal porta de entrada para hackers? "
            "Vamos aprender a criar senhas que são verdadeiras fortalezas digitais! "
            "A primeira tarefa é: construir senhas fortes! Você sabia que usar seus dados públicos como senha podem ser usados como diferentes combinações para atacantes? "
            "Veja como seus dados viram senhas fracas para atacantes utilizarem! "
        ),
        "subphases": [
            {
                "id": 1,
                "title": "Construtor de senha com dados",
                "mode": "password_builder",
                "scorable": False,  # subfase educativa: nao conta pontos nem no max_score
                "question": (
                    "Digite dados fictícios e veja que senhas fracas um "
                    "atacante poderia montar com eles."
                )
            },
            {
                "id": 2,
                "title": "Criar senha forte",
                "question": "Crie uma senha forte usando o teclado virtual abaixo.",
                "options": []
            },
            {
                "id": 3,
                "title": "Classificar senhas",
                "mode": "password_dnd",
                "question": (
                    "Arraste cada cartão para a coluna correta: Senha Fácil (fraca, "
                    "fácil de adivinhar) ou Senha Difícil (forte, bem protegida)."
                )
            }
        ]
    },
    2: {
        "title": "Fase 2: Negligência e Atenção",
        "icon": "⚠️",
        "color": "#a8d89e",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Muito bem até aqui! Agora vou testar sua atenção com uma tarefa diferente. "
            "Na empresa lidamos com todo tipo de arquivo, e cada um tem um nível de acesso. "
            "Você vai receber 5 documentos e deve classificá-los como Público, Interno ou Confidencial. "
            "Um documento no lugar errado pode vazar informações sigilosas. Vamos lá!"
        ),
        "classify": True,
        "classification_labels": {
            "Público": "Pode ser compartilhado livremente.",
            "Interno": "Uso apenas dentro da empresa.",
            "Confidencial": "Acesso restrito a pessoas autorizadas."
        },
        "subphases": [
            {
                "id": 1,
                "title": "folha_de_pagamento_marco.xlsx",
                "question": (
                    "FOLHA DE PAGAMENTO — COMPETÊNCIA MARÇO/2026\n\n"
                    "Matrícula | Nome | CPF | Cargo | Salário\n"
                    "001234 | Maria Oliveira Santos | 123.456.789-00 | Gerente de Loja | R$ 12.500,00\n"
                    "001567 | João Pereira Lima | 987.654.321-00 | Coordenador | R$ 8.900,00\n"
                    "002345 | Ana Souza Costa | 456.789.123-00 | Caixa | R$ 2.450,00\n"
                    "002890 | Carlos Mendes Rocha | 789.123.456-00 | Repositor | R$ 2.150,00\n\n"
                    "TOTAL BRUTO: R$ 1.230.456,78 · Gerado pelo RH em 02/04/2026."
                ),
                "options": ["Público", "Interno", "Confidencial"],
                "correct": 2,
                "explanation_correct": (
                    "A folha de pagamento reúne dados pessoais e informações financeiras "
                    "dos funcionários. Por isso, o acesso deve ser restrito a pessoas autorizadas."
                ),
                "explanation_wrong": (
                    "Você errou. A classificação correta é Confidencial. "
                    "Salários, CPF e informações financeiras são dados pessoais e informações "
                    "de caráter privado que devem ter acesso restrito."
                )
            },
            {
                "id": 2,
                "title": "encarte_ofertas_semana14.pdf",
                "question": (
                    "ENCARTE DE OFERTAS — SEMANA DO CONSUMIDOR\n"
                    "Válido de 12/03/2026 a 18/03/2026 nas lojas Leroy Merlin e no site.\n\n"
                    "OFERTAS DA SEMANA\n"
                    "• Tinta Esmalte Sintético 3,6L — de R$ 129,90 por R$ 89,90\n"
                    "• Furadeira de Impacto 600W + maleta 13 peças — de R$ 259,00 por R$ 189,90\n"
                    "• Kit Banheiro Completo (9 peças) — de R$ 349,00 por R$ 279,00\n"
                    "• Luminária LED 10W bivolt — de R$ 29,90 por R$ 19,90\n"
                    "• Mesa de Jantar + 4 cadeiras — de R$ 1.299,00 por R$ 999,00\n\n"
                    "Sujeito a disponibilidade de estoque. Não acumulativo com outras promoções."
                ),
                "options": ["Público", "Interno", "Confidencial"],
                "correct": 0,
                "explanation_correct": (
                    "Exato! O encarte é material de divulgação criado justamente para ser lido "
                    "por todos os clientes. Informações públicas não têm restrição e podem circular livremente."
                ),
                "explanation_wrong": (
                    "Você errou. A classificação correta é Público. "
                    "O encarte é distribuído nas lojas, no site e nas redes sociais para qualquer pessoa — "
                    "não contém informação interna nem dado sensível."
                )
            },
            {
                "id": 3,
                "title": "backup_banco_dados_clientes.bak",
                "question": (
                    "BACKUP — BANCO DE DADOS CLIENTES LEROY MERLIN (17/04/2026)\n\n"
                    "CLIENTES: 2.400.000 registros — nome, CPF, data de nascimento, "
                    "telefone, e-mail, endereço, histórico de compras\n\n"
                    "PEDIDOS: 8.150.000 registros — id_cliente, data, valor, "
                    "forma de pagamento (cartão tokenizado)\n\n"
                    "ENTREGAS: 5.300.000 registros — id_pedido, endereço de entrega, data prevista\n\n"
                    "Backup completo para recuperação de desastres (DRP)."
                ),
                "options": ["Público", "Interno", "Confidencial"],
                "correct": 2,
                "explanation_correct": (
                    "O backup reúne grande quantidade de dados pessoais de clientes, "
                    "incluindo CPF, endereço e histórico de compras. "
                    "Por isso, seu acesso deve ser restrito a pessoas autorizadas."
                ),
                "explanation_wrong": (
                    "Você errou. A classificação correta é Confidencial. "
                    "O backup reúne uma grande quantidade de dados pessoais de clientes protegidos pela LGPD."
                )
            },
            {
                "id": 4,
                "title": "manual_operacional_lojas_v3.pdf",
                "question": (
                    "MANUAL OPERACIONAL — LOJAS LEROY MERLIN (v3.0)\n\n"
                    "1. Abertura de loja: acionar o sistema de controle da loja, conferir o cofre e ativar o alarme "
                    "da recepção de mercadorias.\n"
                    "2. Reposição de estoque: registrar saídas no sistema interno e atualizar o "
                    "inventário ao fim de cada turno.\n"
                    "3. Fechamento de loja: executar a rotina de recolhimento de valores e registrar "
                    "o fechamento do caixa.\n"
                    "4. Adesão de ofertas: etiquetas promocionais autorizadas pelo gerente antes da impressão.\n\n"
                    "Dúvidas: coordenador de operações."
                ),
                "options": ["Público", "Interno", "Confidencial"],
                "correct": 1,
                "explanation_correct": (
                    "Mandou bem! Esse manual descreve os procedimentos internos de abertura, "
                    "reposição e fechamento das lojas. Ele é usado apenas pelos colaboradores, dentro da empresa."
                ),
                "explanation_wrong": (
                    "Você errou. A classificação correta é Interno. "
                    "O manual mostra como a empresa opera por dentro — rotinas de caixa, cofre e sistemas internos. "
                    "Ele circula só entre colaboradores, mas não contém dados sensíveis a ponto de ser confidencial."
                )
            },
            {
                "id": 5,
                "title": "ficha_tecnica_produto.pdf",
                "question": (
                    "FICHA TÉCNICA — TINTA ESMALTE SINTÉTICO 3,6L\n\n"
                    "• Tipo: esmalte sintético à base de solvente\n"
                    "• Rendimento: até 60 m² por demão\n"
                    "• Secagem: ao toque 4h / entre demãos 6h / final 24h\n"
                    "• Acabamento: brilhante e semibrilhante\n"
                    "• Cores: Branco Giz, Preto Carbono, Vermelho Loja e +40 opções\n"
                    "• Cuidados: aplicar sobre superfície limpa, seca e lixada\n"
                    "• Validade: 24 meses · Garantia: 6 meses · Ref.: 7456123\n\n"
                    "Disponível no site leroymerlin.com.br e nas lojas físicas."
                ),
                "options": ["Público", "Interno", "Confidencial"],
                "correct": 0,
                "explanation_correct": (
                    "Perfeito! A ficha técnica fica exposta no e-commerce para qualquer cliente "
                    "consultar antes de comprar. É um documento público por natureza, sem restrição de acesso."
                ),
                "explanation_wrong": (
                    "Você errou. A classificação correta é Público. "
                    "A ficha técnica está no site para todos os clientes — ela descreve o produto, "
                    "não revela nenhum controle interno da empresa."
                )
            }
        ]
    },
    3: {
        "title": "Fase 3: Phishing",
        "icon": "🎣",
        "color": "#5a8581",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Voce está indo muito bem! Agora chegamos ao ataque mais comum no mundo corporativo: "
            "o Phishing. Ele pode vir por e-mail, telefone, SMS ou até WhatsApp. "
            "Seu objetivo é aprender a identificar essas tentativas antes de cair nelas!"
        ),
        "subphases": [
            {
                "id": 1,
                "title": "E-mail suspeito",
                "mode": "email_compare",
                "question": (
                    "Você recebeu DOIS e-mails no seu correio corporativo. Um deles é falso e está "
                    "tentando enganar você. Compare os dois e REPORTE ao TI o e-mail que você "
                    "acredita ser o FALSO."
                ),
                "emails": [
                    {
                        "label": "E-mail 1",
                        "from_name": "Recursos Humanos",
                        "from_email": "rh@leroymerlin.com.br",
                        "time": "09:14",
                        "subject": "🎓 Treinamento Security Alert - Certificado disponível",
                        "body": [
                            "Prezado(a) colaborador(a),",
                            "Parabéns por concluir o treinamento de cibersegurança Security Alert! Seu certificado já está disponível no Portal do Colaborador. Acesse https://portal.leroymerlin.com.br e procure por 'Meus Treinamentos'.",
                            "Em caso de dúvidas, fale com a equipe de RH",
                            "Atenciosamente, Equipe de RH."
                        ],
                        "is_fake": False
                    },
                    {
                        "label": "E-mail 2",
                        "from_name": "Departamento de TI",
                        "from_email": "ti@ler0y-merlin.com.br",
                        "time": "09:30",
                        "subject": "⚠️ AÇÃO NECESSÁRIA: atualize sua senha hoje!!",
                        "body": [
                            "Prezado(a) colaborador(a),",
                            "Detectamos atividade suspeita na sua conta. Para manter seus dados seguros, atualize sua senha imediatamente clicando no link abaixo.",
                            "https://portall.ler0ymerIin.com.br/atualizar-senha",
                            "Caso não faça isso em até 24 horas, seu acesso será suspenso.",
                            "Departamento de Segurança da Informação."
                        ],
                        "is_fake": True
                    }
                ],
                "correct": 1,
                "explanation_correct": (
                    "🎉 Parabéns! Você identificou e reportou o e-mail FALSO corretamente! "
                    "O e-mail 2 vinha de 'ti@ler0y-merlin.com.br', repare no HÍFEN e no número 0 do domínio. "
                    "O domínio oficial da Leroy Merlin é @leroymerlin.com.br (sem hífen). "
                    "Além disso, ele usava um link suspeito ('portall...') e tom de urgência, "
                    "sinais clássicos de phishing. Reportar ao TI foi a atitude correta!"
                ),
                "explanation_wrong": (
                    "😔 Que Pena! Você reportou o e-mail VERDADEIRO! Comparando os dois: o e-mail 2 era o falso. "
                    "Ele vinha de 'ti@ler0y-merlin.com.br' — repare que ele possui um número 0 e um HÍFEN do domínio. "
                    "O domínio oficial é @leroymerlin.com.br (sem hífen). O e-mail falso também tinha "
                    "um link suspeito ('portall.leroymerIin.com.br') e pressionava com urgência "
                    "('seu acesso será suspenso'). Esses são os sinais de phishing que você deve observar!"
                )
            },
            {
                "id": 2,
                "title": "SMS falso",
                "mode": "sms_sim",
                "question": (
                    "Você recebeu este SMS no seu celular corporativo. "
                    "Por que essa mensagem NÃO é legítima?"
                ),
                "options": [
                    "Porque a Leroy Merlin nunca envia SMS aos colaboradores - Sinal de phishing",
                    "Porque usa tom de urgência, link encurtado (bit.ly) e tem erros ortográficos - sinais clássicos de phishing",
                    "Porque erros de ortografia não acontecem em mensagens de golpe",
                    "Porque vazamento de dados não é um tema real de segurança"
                ],
                "correct": 1,
                "explanation_correct": (
                    "Excelente! 🎉 Você identificou os sinais de phishing: tom de urgência, "
                    "link encurtado (bit.ly) e vários erros ortográficos ('forão', 'pessuais', 'SEGURANSA'). "
                    "Mensagens oficiais da Leroy Merlin são revisadas e nunca pedem ação urgente por SMS. "
                    "Exclua a mensagem e reporte ao TI!"
                ),
                "explanation_wrong": (
                    "Quase lá! Os sinais de golpe eram: tom de urgência ('URGENTE', 'será bloqueado'), "
                    "link encurtado (bit.ly) e vários erros ortográficos ('forão', 'pessuais', 'SEGURANSA'). "
                    "Mensagens legítimas da empresa não usam links encurtados nem pedem ação imediata por SMS."
                )
            },
            {
                "id": 3,
                "title": "Site clonado",
                "mode": "site_sim",
                "question": (
                    "Você clicou em um link e caiu neste site, que se parece com o portal da "
                    "Leroy Merlin. Por que este site é FALSO?"
                ),
                "options": [
                    "Porque a URL tem hífen (leroymerlin-seguranca.com) e não é o domínio oficial leroymerlin.com.br",
                    "Porque a página é muito bonita para ser um site falso",
                    "Porque promoções com 90% de desconto sempre são reais",
                    "Porque pedir login é algo que nenhum site legítimo faz"
                ],
                "correct": 0,
                "explanation_correct": (
                    "Excelente! 🎉 O domínio oficial da Leroy Merlin é leroymerlin.com.br. "
                    "Este site usava 'leroymerlin-seguranca.com' (com hífen), um domínio falso criado "
                    "para enganar. Além disso, o alerta de 'site não seguro' e a promoção absurda "
                    "de 90% de desconto são fortes sinais de golpe. Feche a página e reporte ao TI!"
                ),
                "explanation_wrong": (
                    "Cuidado! 🚨 O site era falso porque a URL tinha um hífen: "
                    "'leroymerlin-seguranca.com' em vez do domínio oficial 'leroymerlin.com.br'. "
                    "Promoções exageradas, alertas de 'site não seguro' e pedidos de login fora do "
                    "site oficial são sinais clássicos de phishing. NUNCA digite suas credenciais em "
                    "sites com URLs suspeitas."
                )
            }
        ]
    },
    4: {
        "title": "Fase 4: Engenharia Social",
        "icon": "📞",
        "color": "#f2d38b",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Você chegou à última fase do treinamento! Agora vamos falar sobre engenharia social: "
            "golpistas que usam a confiança e o medo para enganar. Vou simular uma ligação de um "
            "farsante e você precisa decidir como agir com segurança."
        ),
        "subphases": [
            {
                "id": 1,
                "title": "Ligação do farsante",
                "mode": "call_sim",
                "question": (
                    "Você recebeu esta ligação de alguém se passando pelo setor de segurança da "
                    "Leroy Merlin e pedindo seus dados. Como você deve proceder?"
                ),
                "options": [
                    "Passo meu CPF completo, parece ser legítimo",
                    "Desligo a ligação e confirmo com o TI pelos canais oficiais da empresa",
                    "Informo meus dados, mas peço para a pessoa confirmar o nome dela primeiro",
                    "Dou só a data de admissão, não é tão grave"
                ],
                "correct": 1,
                "explanation_correct": (
                    "Perfeito! 🎉 Você concluiu o treinamento com maestria! Desligar e confirmar "
                    "pelos canais oficiais é a atitude certa. Empresas legítimas NUNCA pedem dados "
                    "sensíveis por telefone. O golpista usava engenharia social, e você não caiu!"
                ),
                "explanation_wrong": (
                    "Cuidado! 🚨 Isso é engenharia social: o golpista se passa por alguém de "
                    "confiança para roubar seus dados. Nunca informe CPF, senha ou dados pessoais "
                    "por telefone. Desligue e confirme com o TI pelos canais oficiais da empresa."
                )
            }
        ]
    },
    5: {
        "title": "Fase 5: Uso de dispositivos pessoais",
        "icon": "📱",
        "color": "#b8a8d8",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Mandou muito bem até aqui! Agora vamos falar sobre os dispositivos pessoais: celular, pen drive, "
            "computador de casa... Eles facilitam o seu trabalho, mas também podem abrir portas para os hackers. "
            "Quando você usa tecnologia própria para acessar o sistema da empresa, a segurança depende das SUAS escolhas. "
            "E atenção: na última questão o tempo é seu inimigo. Um ataque não espera você pensar!"
        ),
        "subphases": [
            {
                "id": 2,
                "title": "Pen drive de banca de rua",
                "question": (
                    "Você comprou um pen drive baratinho em uma banca de rua. Precisa levar arquivos do trabalho para casa. "
                    "O que você deve fazer?"
                ),
                "options": [
                    "Formatar o pen drive antes de usar, pois isso elimina qualquer ameaça.",
                    "Não usar esse pen drive para arquivos da empresa. Utilize apenas dispositivos fornecidos ou aprovados pela TI.",
                    "Passar o antivírus no pen drive uma vez e depois usar sem preocupação.",
                    "Usar o pen drive normalmente, já que ele é novo e custou pouco."
                ],
                "correct": 1,
                "explanation_correct": (
                    "Exato! ✅ Pen drives de origem duvidosa podem vir com programas escondidos que infectam o computador ao serem "
                    "conectados. Para arquivos da empresa, use apenas dispositivos confiáveis."
                ),
                "explanation_wrong": (
                    "❌ 'Novo e barato' não significa seguro. O dispositivo pode ter sido preparado para parecer normal, mas conter "
                    "ameaças invisíveis (D). O antivírus (C) não detecta tudo, especialmente ameaças escondidas no firmware do pen drive; "
                    "quando você conecta para escanear, o ataque pode já ter acontecido. E formatar (A) limpa os arquivos, mas não remove "
                    "ameaças que estão no firmware do dispositivo."
                )
            },
            {
                "id": 3,
                "title": "Celular pessoal no trabalho",
                "question": "Você usa seu celular pessoal para acessar o e-mail da empresa. Qual atitude é a mais segura?",
                "options": [
                    "Instalar o e-mail da empresa e os apps pessoais (jogos, redes sociais) no mesmo espaço, sem separação.",
                    "Usar a mesma senha do e-mail pessoal no e-mail corporativo para não esquecer.",
                    "Manter o celular atualizado, com bloqueio de tela por biometria ou PIN forte, e usar o perfil de trabalho para separar dados pessoais dos corporativos.",
                    "Deixar o celular sem bloqueio de tela para responder e-mails mais rápido."
                ],
                "correct": 2,
                "explanation_correct": (
                    "Perfeito! ✅ Celular atualizado fecha brechas conhecidas, bloqueio de tela protege contra acesso de estranhos e a "
                    "separação de perfis impede que um app pessoal infectado alcance os dados da empresa."
                ),
                "explanation_wrong": (
                    "❌ Sem bloqueio de tela (D), qualquer pessoa que pegue seu celular terá acesso livre aos e-mails e documentos da empresa — "
                    "é como deixar a porta de casa aberta. Se sua conta pessoal for invadida (B), o atacante terá automaticamente a senha da "
                    "empresa também: cada conta deve ter senha diferente. E misturar tudo no mesmo espaço (A) faz com que um app pessoal com "
                    "problema possa acessar dados corporativos. A separação é essencial para isolar os riscos."
                )
            },
            {
                "id": 7,
                "title": "Jogo de site não oficial",
                "question": (
                    "Você baixou um jogo de um site não oficial no mesmo computador que usa para acessar o sistema da empresa. Qual é o problema?"
                ),
                "options": [
                    "O problema é só que o jogo pode deixar o computador lento.",
                    "Jogos de sites não oficiais podem vir com vírus escondidos que infectam o computador e podem roubar senhas e dados da empresa acessados no mesmo aparelho.",
                    "Nenhum, desde que o jogo seja gratuito.",
                    "O único problema é que a empresa pode multar você por usar o computador para coisas pessoais."
                ],
                "correct": 1,
                "explanation_correct": (
                    "Correto! ✅ Programas de sites não oficiais costumam trazer vírus escondidos que podem capturar senhas, roubar arquivos e usar "
                    "o computador como ponte para atacar a empresa."
                ),
                "explanation_wrong": (
                    "❌ Ser gratuito (C) não significa seguro. Muitos vírus são distribuídos justamente em programas 'gratuitos' para atrair "
                    "usuários desavisados. O problema vai muito além de punição administrativa (D): há um risco técnico real de vazamento de dados "
                    "e comprometimento dos sistemas da empresa. E lentidão (A) é o menor dos problemas, o perigo é invisível e silencioso: o vírus "
                    "pode agir por meses sem que você perceba nada de errado."
                )
            },
            {
                "id": 8,
                "title": "Protegendo a empresa",
                "question": "Qual destas atitudes ajuda a proteger a empresa quando você usa seu equipamento pessoal para trabalhar?",
                "options": [
                    "Desativar o firewall do computador quando o sistema da empresa estiver lento.",
                    "Usar a mesma senha para tudo, desde que seja uma senha muito forte.",
                    "Ativar a autenticação em duas etapas (MFA) nos sistemas da empresa e manter o computador com antivírus e sistema operacional atualizados.",
                    "Deixar o antivírus desligado para o computador ficar mais rápido."
                ],
                "correct": 2,
                "explanation_correct": (
                    "Perfeito! ✅ A autenticação em duas etapas exige um segundo passo para entrar (como um código no celular). Mesmo que alguém "
                    "descubra sua senha, não consegue acessar sem o segundo fator. Antivírus e atualizações fecham brechas conhecidas."
                ),
                "explanation_wrong": (
                    "❌ Antivírus desligado (D) deixa o computador desprotegido. A perda de performance é mínima perto do risco de comprometer "
                    "dados da empresa. Mesmo a senha mais forte, se reutilizada em vários lugares (B), vira ponto único de falha: se uma conta for "
                    "invadida, todas as outras com a mesma senha também estarão comprometidas. E o firewall (A) bloqueia conexões perigosas de fora "
                    "para dentro — desligá-lo deixa o computador exposto a invasões e a vírus se comunicando com criminosos pela internet."
                )
            },
            {
                "id": 9,
                "title": "Pen drive infectado - ataque em andamento!",
                "question": (
                    "🚨 AMEAÇA ATIVA! Você conectou um pen drive infectado ao computador da empresa e percebeu que ele pode estar comprometido. "
                    "O ataque já começou - decida rápido, antes que o hacker complete a invasão!"
                ),
                "options": [
                    "Continuar usando o computador normalmente e avisar a TI apenas se aparecer algum problema.",
                    "Formatar o pen drive e conectá-lo novamente para verificar se o problema foi resolvido.",
                    "Desconectar o pen drive, não abrir nem executar arquivos dele e comunicar imediatamente a TI ou o responsável pela segurança da empresa.",
                    "Passar o antivírus no pen drive e, se não encontrar nada, continuar usando normalmente."
                ],
                "correct": 2,
                "timer_seconds": 30,
                "hacked_title": "Você foi hackeado(a)",
                "hacked_text": (
                    "💀 O tempo acabou e o malware se espalhou pelo computador antes de você reagir. Todos os pontos desta fase foram perdidos. "
                    "No mundo real, a atitude correta era: desconectar o pen drive, não abrir nem executar arquivos dele e comunicar IMEDIATAMENTE "
                    "a TI ou o responsável pela segurança, isso permite analisar a máquina e evita que a infecção se espalhe."
                ),
                "saved_title": "Você salvou a empresa.",
                "explanation_correct": (
                    "🌱 Você salvou a empresa! Ao desconectar o pen drive, não abrir nenhum arquivo dele e comunicar imediatamente a TI ou o "
                    "responsável pela segurança, você interrompeu o ataque na hora certa. Isso permite que o computador seja analisado e evita que "
                    "uma possível infecção se espalhe pela rede."
                ),
                "explanation_wrong": (
                    "❌ A atitude correta era desconectar o pen drive, não abrir nem executar arquivos dele e comunicar imediatamente a TI ou o "
                    "responsável pela segurança (C). Continuar usando o computador (A) permite que o malware se espalhe ou roube informações antes "
                    "que alguém perceba. Formatar e reconectar o pen drive (B) não garante que a ameaça foi eliminada — e ainda coloca o computador "
                    "em risco outra vez. E o antivírus (D) pode não detectar todas as ameaças: a análise deve ficar com a equipe responsável pela segurança."
                )
            }
        ]
    },
    6: {
        "title": "Fase 6: Uso de IA — Compartilhamento indevido de informações",
        "icon": "🤖",
        "color": "#8ecae6",
        "boss_name": "Chefe Carlos",
        "explanation": (
            "Ferramentas de IA são ótimas aliadas, mas exigem cuidado. Um prompt com dados pessoais ou "
            "informações internas pode vazar dados sensíveis e violar a LGPD. Vou mostrar quatro prompts. "
            "Decida se cada um pode ou não pode ser enviado para a IA."
        ),
        "subphases": [
            {
                "id": 1,
                "title": "Prompt com dados pessoais",
                "question": "Chat, resuma o atendimento do cliente João. CPF: 123.456.789-00 e telefone: (11) 99999-9999. O endereço dele é AV. X, número X e CEP 00000-000.",
                "options": ["Pode enviar", "Não pode enviar"],
                "correct": 1,
                "explanation_correct": (
                    "Correto! Esse prompt não pode ser enviado, pois contém o nome, o CPF e o telefone de um cliente. "
                    "Esses dados pessoais não devem ser compartilhados com uma ferramenta de IA sem autorização."
                ),
                "explanation_wrong": (
                    "Incorreto! O prompt contém o nome, o CPF e o telefone do cliente. Compartilhar esses dados com "
                    "uma ferramenta de IA pode expor informações pessoais e violar a LGPD."
                )
            },
            {
                "id": 2,
                "title": "Mensagem genérica de agradecimento",
                "question": "Chat, crie uma mensagem agradecendo ao cliente pela compra sendo gentil.",
                "options": ["Pode enviar", "Não pode enviar"],
                "correct": 0,
                "explanation_correct": (
                    "Correto! Esse prompt pode ser enviado, pois solicita apenas uma mensagem genérica de agradecimento "
                    "e não contém dados pessoais ou informações internas."
                ),
                "explanation_wrong": (
                    "Incorreto! Esse prompt pode ser enviado, pois não apresenta dados pessoais, informações confidenciais "
                    "ou informações internas da empresa."
                )
            },
            {
                "id": 3,
                "title": "Relatório interno de metas",
                "question": "Chat, resuma este relatório interno com as metas de vendas da loja para o próximo mês.",
                "options": ["Pode enviar", "Não pode enviar"],
                "correct": 1,
                "explanation_correct": (
                    "Correto! Esse prompt não pode ser enviado, pois o relatório apresenta metas de vendas que são "
                    "informações internas da empresa."
                ),
                "explanation_wrong": (
                    "Incorreto! As metas de vendas são informações internas da empresa e não devem ser compartilhadas "
                    "com uma ferramenta de IA sem autorização."
                )
            },
            {
                "id": 4,
                "title": "Mensagem sobre prazo de entrega",
                "question": "Chat, crie uma mensagem educada informando que o prazo de entrega pode variar de acordo com a região.",
                "options": ["Pode enviar", "Não pode enviar"],
                "correct": 0,
                "explanation_correct": (
                    "Correto! Esse prompt pode ser enviado, pois solicita uma mensagem genérica sobre o prazo de entrega "
                    "e não contém informações sensíveis."
                ),
                "explanation_wrong": (
                    "Incorreto! Esse prompt pode ser enviado, pois não contém dados de clientes nem informações internas "
                    "ou confidenciais da empresa."
                )
            }
        ]
    }
}

# ─── Rotas de Autenticacao ───────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    # Busca ranking por loja: soma do melhor score dos usuarios de cada loja
    db = get_db()
    max_score_possible = sum(
        sum(1 for s in p['subphases'] if s.get('scorable', True))
        for p in GAME_PHASES.values()
    ) * 100
    ranking = db.execute("""
        SELECT u.loja,
               SUM(COALESCE(best.best_score, 0)) as total_score,
               COUNT(DISTINCT u.id) as total_players
        FROM users u
        LEFT JOIN (
            SELECT user_id, MAX(score) as best_score
            FROM game_sessions
            WHERE completed = 1
            GROUP BY user_id
        ) best ON best.user_id = u.id
        WHERE u.show_in_ranking = 1 AND u.loja IS NOT NULL AND u.loja != ''
        GROUP BY u.loja
        ORDER BY total_score DESC
        LIMIT 10
    """).fetchall()
    return render_template('index.html', ranking=ranking, max_score_possible=max_score_possible)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        email = request.form.get('email', '').strip().lower()
        loja = request.form.get('loja', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        errors = []
        if len(username) < 3:
            errors.append('Nome de usuario deve ter pelo menos 3 caracteres.')
        if len(email) < 5 or '@' not in email:
            errors.append('Email invalido.')
        if loja not in ['Loja A', 'Loja B']:
            errors.append('Selecione uma loja valida.')
        if len(password) < 6:
            errors.append('Senha deve ter pelo menos 6 caracteres.')
        if password != confirm:
            errors.append('As senhas nao conferem.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html')

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        ).fetchone()

        if existing:
            flash('Usuario ou email ja cadastrado.', 'warning')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        show_in_ranking = 1 if request.form.get('show_in_ranking') else 0
        db.execute(
            "INSERT INTO users (username, email, password_hash, show_in_ranking, loja) VALUES (?, ?, ?, ?, ?)",
            (username, email, password_hash, show_in_ranking, loja)
        )
        db.commit()

        flash('Conta criada com sucesso! Faca login para comecar.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_field = request.form.get('login', '').strip().lower()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (login_field, login_field)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            # Renova a sessao no login (mitiga session fixation)
            session.clear()
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['profile_image'] = user['profile_image'] or ''
            session['is_admin'] = bool(user['is_admin'])
            flash(f'Bem-vindo(a) de volta, {user["username"]}!', 'success')
            next_url = request.args.get('next') or request.form.get('next')
            if is_safe_redirect(next_url):
                return redirect(next_url)
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario/email ou senha incorretos.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    db = get_db()
    user_id = session['user_id']

    if request.method == 'POST':
        file = request.files.get('profile_image')
        if file and file.filename:
            ext = file.filename.rsplit('.', 1)[-1].lower()
            if ext not in {'png', 'jpg', 'jpeg', 'gif', 'webp'}:
                flash('Formato invalido. Use PNG, JPG, GIF ou WEBP.', 'danger')
                return redirect(url_for('perfil'))

            # Valida o conteudo real do arquivo (magic bytes), nao so a extensao
            header = file.stream.read(16)
            file.stream.seek(0)
            if not image_matches_extension(header, ext):
                flash('Arquivo invalido: o conteudo nao corresponde a uma imagem valida.', 'danger')
                return redirect(url_for('perfil'))

            filename = f"user_{user_id}.{ext}"
            upload_dir = app.config['AVATAR_UPLOAD_DIR']
            os.makedirs(upload_dir, exist_ok=True)

            # remove imagem antiga se existir
            old = db.execute("SELECT profile_image FROM users WHERE id = ?", (user_id,)).fetchone()
            if old and old['profile_image']:
                old_path = os.path.join(upload_dir, old['profile_image'])
                try:
                    os.remove(old_path)
                except FileNotFoundError:
                    pass

            file.save(os.path.join(upload_dir, filename))
            db.execute("UPDATE users SET profile_image = ? WHERE id = ?", (filename, user_id))
            db.commit()
            session['profile_image'] = filename
            flash('Foto de perfil atualizada!', 'success')

        return redirect(url_for('perfil'))

    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    user_badges = get_user_badges(user_id)
    return render_template('perfil.html', user=user, badges=user_badges)

def get_user_badges(user_id):
    """Retorna a lista de badges conquistadas pelo usuario (com dados completos)."""
    db = get_db()
    unlocked = {
        row['badge_id']: row['unlocked_at']
        for row in db.execute("SELECT badge_id, unlocked_at FROM user_badges WHERE user_id = ?", (user_id,)).fetchall()
    }
    result = []
    for badge in BADGES:
        b = dict(badge)
        b['unlocked_at'] = unlocked.get(badge['id'])
        b['unlocked'] = badge['id'] in unlocked
        result.append(b)
    return result


def check_and_award_badges(user_id):
    """Verifica condicoes e desbloqueia badges automaticamente."""
    db = get_db()

    unlocked = {
        row['badge_id'] for row in
        db.execute("SELECT badge_id FROM user_badges WHERE user_id = ?", (user_id,)).fetchall()
    }

    # Estatisticas do usuario
    completed_sessions = db.execute(
        "SELECT id, score, max_score FROM game_sessions WHERE user_id = ? AND completed = 1",
        (user_id,)
    ).fetchall()

    answers = db.execute(
        "SELECT phase, subphase, correct FROM phase_answers WHERE session_id IN ("
        "SELECT id FROM game_sessions WHERE user_id = ? AND completed = 1"
        ")",
        (user_id,)
    ).fetchall()

    new_badges = []

    # Conta quantas fases distintas foram respondidas em sessoes completadas
    fases_respondidas = set()
    for a in answers:
        fases_respondidas.add(a['phase'])

    # 1. Escudo de Conclusao: completou ao menos 1 sessao
    if 'escudo' not in unlocked and completed_sessions:
        new_badges.append('escudo')

    # 2. Chave: terminou fase 1 (senhas)
    if 'chave' not in unlocked and 1 in fases_respondidas:
        new_badges.append('chave')

    # 3. Cadeado: terminou fase 2 (negligencia e atencao)
    if 'cadeado' not in unlocked and 2 in fases_respondidas:
        new_badges.append('cadeado')

    # 4. Phishing: terminou fase 3 (phishing)
    if 'phishing' not in unlocked and 3 in fases_respondidas:
        new_badges.append('phishing')

    # 5. Engrenagem: terminou fase 4 (engenharia social - telefone)
    if 'engrenagem' not in unlocked and 4 in fases_respondidas:
        new_badges.append('engrenagem')

    # 6. Celular: terminou fase 5 (uso de dispositivos pessoais)
    if 'celular' not in unlocked and 5 in fases_respondidas:
        new_badges.append('celular')

    # 7. Robo: terminou fase 6 (IA)
    if 'robo' not in unlocked and 6 in fases_respondidas:
        new_badges.append('robo')

    # 8. Score Perfeito: score == max_score em alguma sessao
    if 'cem_porcento' not in unlocked:
        for s in completed_sessions:
            if s['score'] >= s['max_score'] and s['max_score'] > 0:
                new_badges.append('cem_porcento')
                break

    for badge_id in new_badges:
        db.execute(
            "INSERT OR IGNORE INTO user_badges (user_id, badge_id) VALUES (?, ?)",
            (user_id, badge_id)
        )

    if new_badges:
        db.commit()

    return new_badges


@app.route('/badges')
@login_required
def badges():
    user_badges = get_user_badges(session['user_id'])
    return render_template('badges.html', badges=BADGES, user_badges=user_badges)

@app.route('/desafios')
@app.route('/cursos')
@login_required
def cursos():
    modulos = [
        {
            'titulo': 'Módulo 1 - Engenharia Social e Phishing',
            'atividades': [
                {'titulo': 'Fazer download do curso', 'url': url_for('static', filename='pdfs/modulo1_engenharia_social_e_phishing.pdf'), 'download': True}
            ]
        },
        {
            'titulo': 'Módulo 2 - Senhas e Segurança dos Dispositivos',
            'atividades': [
                {'titulo': 'Fazer download do curso', 'url': url_for('static', filename='pdfs/modulo2_senhas_e_seguranca_dos_dispositivos.pdf'), 'download': True}
            ]
        },
        {
            'titulo': 'Módulo 3 - Negligência e Uso Seguro da IA',
            'atividades': [
                {'titulo': 'Fazer download do curso', 'url': url_for('static', filename='pdfs/modulo3_negligencia_e_uso_seguro_da_ia.pdf'), 'download': True}
            ]
        },
    ]
    return render_template('cursos.html', modulos=modulos)


@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute("""
        SELECT u.*,
               COUNT(DISTINCT gs.id) as total_games,
               COUNT(DISTINCT CASE WHEN gs.completed = 1 THEN gs.id END) as completed_games,
               COALESCE(MAX(CASE WHEN gs.completed = 1 THEN gs.score END), 0) as best_score
        FROM users u
        LEFT JOIN game_sessions gs ON gs.user_id = u.id
        GROUP BY u.id
        ORDER BY u.id
    """).fetchall()
    return render_template('admin.html', users=users)


@app.route('/admin/user/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('Usuario nao encontrado.', 'danger')
        return redirect(url_for('admin_panel'))

    if user['id'] == session['user_id']:
        flash('Use a troca de senha normal para sua propria conta.', 'warning')
        return redirect(url_for('admin_panel'))

    new_password = request.form.get('new_password', '').strip()
    if len(new_password) < 6:
        flash('Senha deve ter pelo menos 6 caracteres.', 'danger')
        return redirect(url_for('admin_panel'))

    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id)
    )
    db.commit()
    flash(f"Senha de {user['username']} redefinida com sucesso.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/reset-progress', methods=['POST'])
@admin_required
def admin_reset_progress(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('Usuario nao encontrado.', 'danger')
        return redirect(url_for('admin_panel'))

    # apaga sessoes e respostas
    db.execute("DELETE FROM phase_answers WHERE session_id IN (SELECT id FROM game_sessions WHERE user_id = ?)", (user_id,))
    db.execute("DELETE FROM game_sessions WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM user_badges WHERE user_id = ?", (user_id,))
    db.commit()
    flash(f"Progresso de {user['username']} resetado com sucesso.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def admin_toggle_admin(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('Usuario nao encontrado.', 'danger')
        return redirect(url_for('admin_panel'))

    if user['id'] == session['user_id']:
        flash('Voce nao pode alterar seu proprio nivel de admin.', 'warning')
        return redirect(url_for('admin_panel'))

    new_value = 0 if user['is_admin'] else 1
    db.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_value, user_id))
    db.commit()
    status = 'administrador' if new_value else 'usuario comum'
    flash(f"{user['username']} agora e {status}.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash('Usuario nao encontrado.', 'danger')
        return redirect(url_for('admin_panel'))

    if user['id'] == session['user_id']:
        flash('Voce nao pode excluir sua propria conta.', 'warning')
        return redirect(url_for('admin_panel'))

    # apaga dados do usuario
    db.execute("DELETE FROM phase_answers WHERE session_id IN (SELECT id FROM game_sessions WHERE user_id = ?)", (user_id,))
    db.execute("DELETE FROM game_sessions WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM user_badges WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    flash(f"Usuario {user['username']} excluido com sucesso.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        new_password = request.form.get('new_password', '')
        confirm = request.form.get('confirm', '')

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user:
            flash('Email nao encontrado.', 'danger')
            return render_template('reset_password.html')

        if len(new_password) < 6:
            flash('Senha deve ter pelo menos 6 caracteres.', 'danger')
            return render_template('reset_password.html')

        if new_password != confirm:
            flash('As senhas nao conferem.', 'danger')
            return render_template('reset_password.html')

        password_hash = generate_password_hash(new_password)
        db.execute(
            "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?",
            (password_hash, user['id'])
        )
        db.commit()

        flash('Senha redefinida com sucesso! Faca login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# ─── Rotas do Jogo ───────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    sessions = db.execute(
        "SELECT * FROM game_sessions WHERE user_id = ? ORDER BY started_at DESC",
        (session['user_id'],)
    ).fetchall()

    # Calcular estatisticas
    total_games = len(sessions)
    completed_games = [s for s in sessions if s['completed']]

    # max_max_score_global = max pontuavel POSSIVEL hoje (recalculado das GAME_PHASES,
    # nao do banco). Isso garante que mesmo sessoes antigas com max_score=2100
    # (gravadas antes da migracao pra base 1600) mostrem o teto atualizado.
    max_score_possible = sum(
        sum(1 for s in p['subphases'] if s.get('scorable', True))
        for p in GAME_PHASES.values()
    ) * 100

    # best_score/max = o melhor jogo completed do usuario
    if completed_games:
        best_session = max(completed_games, key=lambda s: s['score'])
        # Cap em 100%: se a sessao antiga tem pontos de subfases que foram removidas
        # (score > teto novo), capamos o score no teto pra nao mostrar >100%.
        # Tambem cap o max no teto novo (sessoes antigas gravadas com max=2100/1700).
        best_score = min(best_session['score'], max_score_possible)
        best_max = min(best_session['max_score'], max_score_possible)
    else:
        best_score = 0
        best_max = max_score_possible

    # Busca status de show_in_ranking e loja do usuario
    user_data = db.execute(
        "SELECT show_in_ranking, loja FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    show_in_ranking = bool(user_data['show_in_ranking']) if user_data else True

    # Ranking por loja: soma do melhor score dos usuarios de cada loja
    ranking = db.execute("""
        SELECT u.loja,
               SUM(COALESCE(best.best_score, 0)) as total_score,
               COUNT(DISTINCT u.id) as total_players
        FROM users u
        LEFT JOIN (
            SELECT user_id, MAX(score) as best_score
            FROM game_sessions
            WHERE completed = 1
            GROUP BY user_id
        ) best ON best.user_id = u.id
        WHERE u.show_in_ranking = 1 AND u.loja IS NOT NULL AND u.loja != ''
        GROUP BY u.loja
        ORDER BY total_score DESC
        LIMIT 10
    """).fetchall()

    return render_template('dashboard.html',
                         sessions=sessions,
                         total_games=total_games,
                         completed_count=len(completed_games),
                         best_score=best_score,
                         best_max=best_max,
                         max_score_possible=max_score_possible,
                         show_in_ranking=show_in_ranking,
                         ranking=ranking,
                         user_loja=user_data['loja'] if user_data else None)

@app.route('/toggle-ranking', methods=['POST'])
@login_required
def toggle_ranking():
    db = get_db()
    current = db.execute(
        "SELECT show_in_ranking FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    new_value = 0 if current['show_in_ranking'] else 1
    db.execute(
        "UPDATE users SET show_in_ranking = ? WHERE id = ?",
        (new_value, session['user_id'])
    )
    db.commit()
    return redirect(url_for('dashboard'))

# ─── Selecao de Personagem ───────────────────────────────────
def get_user_character():
    """Retorna os dados do personagem escolhido pelo usuario logado."""
    db = get_db()
    row = db.execute(
        "SELECT character FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    key = row['character'] if row and row['character'] in CHARACTERS else DEFAULT_CHARACTER
    return key, CHARACTERS[key]

@app.route('/personagem', methods=['GET', 'POST'])
@login_required
def personagem():
    db = get_db()
    if request.method == 'POST':
        chosen = request.form.get('character', '')
        if chosen not in CHARACTERS:
            flash('Personagem invalido.', 'danger')
            return redirect(url_for('personagem'))
        db.execute(
            "UPDATE users SET character = ? WHERE id = ?",
            (chosen, session['user_id'])
        )
        db.commit()
        flash(f'{CHARACTERS[chosen]["name"]} agora e o seu personagem! 🎮', 'success')
        return redirect(url_for('personagem'))
    current, _ = get_user_character()
    return render_template('personagem.html',
                         characters=CHARACTERS,
                         current=current,
                         spin_frames={k: get_spin_frames(k) for k in CHARACTERS})

@app.route('/game/start')
@login_required
def game_start():
    db = get_db()
    # Pontuacao maxima: 100 pts por subfase pontuavel.
    # Subfases com "scorable": False (ex: builder educativo da Fase 1) nao contam.
    # 17 subfases totais - 1 builder nao-pontuavel = 16 pontuaveis * 100 = 1600 max.
    total_scorable = sum(
        sum(1 for s in p['subphases'] if s.get('scorable', True))
        for p in GAME_PHASES.values()
    )
    cursor = db.execute(
        "INSERT INTO game_sessions (user_id, max_score) VALUES (?, ?)",
        (session['user_id'], total_scorable * 100)
    )
    db.commit()
    game_id = cursor.lastrowid

    return redirect(url_for('game_play', game_id=game_id, phase=1, sub=1))

@app.route('/game/<int:game_id>/phase/<int:phase>/sub/<int:sub>')
@login_required
def game_play(game_id, phase, sub):
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ?",
        (game_id, session['user_id'])
    ).fetchone()

    if not game:
        flash('Sessao de jogo nao encontrada.', 'danger')
        return redirect(url_for('dashboard'))

    if game['completed']:
        return redirect(url_for('game_feedback', game_id=game_id))

    if phase not in GAME_PHASES:
        return redirect(url_for('game_feedback', game_id=game_id))

    # A Fase 1 tem layout customizado (teclado virtual in-page),
    # mas é renderizado dentro do proprio game.html quando phase == 1.

    phase_data = GAME_PHASES[phase]
    if sub > len(phase_data['subphases']):
        # Proxima fase
        next_phase = phase + 1
        if next_phase in GAME_PHASES:
            return redirect(url_for('game_play', game_id=game_id, phase=next_phase, sub=1))
        else:
            # Jogo concluido!
                db.execute(
                    "UPDATE game_sessions SET completed = 1, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (game_id,)
                )
                db.commit()
                check_and_award_badges(session['user_id'])
                return redirect(url_for('game_feedback', game_id=game_id))

    subphase_data = phase_data['subphases'][sub - 1]

    # Verificar se ja respondeu
    already_answered = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = ? AND subphase = ?",
        (game_id, phase, sub)
    ).fetchone()

    # Lista de subphases da fase atual que ja foram respondidas (usada pelas bolinhas)
    answered_subphases = db.execute(
        "SELECT subphase FROM phase_answers WHERE session_id = ? AND phase = ?",
        (game_id, phase)
    ).fetchall()
    answered_subs = {row['subphase'] for row in answered_subphases}

    # Email cadastrado pelo usuario (usado como destinatario na simulacao de e-mail)
    user_email = db.execute(
        "SELECT email FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()['email']

    # Personagem escolhido pelo jogador (exibido no canto da fase)
    char_key, char_data = get_user_character()

    return render_template('game.html',
                         game=game,
                         phase=phase,
                         sub=sub,
                         phase_data=phase_data,
                         subphase_data=subphase_data,
                         already_answered=already_answered,
                         answered_subs=answered_subs,
                         user_email=user_email,
                         player_char=char_data,
                         total_phases=len(GAME_PHASES),
                         total_subs_in_phase=len(phase_data['subphases']))

# ═══════════════════════════════════════════════════════════════════════════
# 🎮 FASE 1 — CRIADOR DE SENHA (point-and-click)
# Rotas dedicadas: /game/<id>/phase/1/play e /game/<id>/phase/1/submit
# ═══════════════════════════════════════════════════════════════════════════

COMMON_PATTERNS = [
    r'123', r'234', r'345', r'456', r'567', r'678', r'789', r'890',
    r'abc', r'bcd', r'cde', r'def', r'qwerty', r'asdf', r'zxcv',
    r'111', r'222', r'333', r'444', r'555', r'666', r'777', r'888', r'999', r'000',
    r'password', r'senha', r'admin', r'login', r'user',
]

def check_password_strength(password):
    """Avalia a força de uma senha.

    max_score = 19 (maximo absoluto se todos os 9 criterios forem atingidos):
      tam>=8: +2, tam>=12: +3, tam>=16: +2 (max +7)
      lower/upper/num: +2 cada (+6)
      simbolo: +3
      sem padrao comum: +2
      sem repeticao: +1
    """
    if not password:
        return {"score": 0, "max_score": 19, "strength": "vazia", "label": "Digite uma senha...", "color": "#888", "percent": 0, "time": "—", "feedback": [], "bonuses": [], "missing": [], "length": 0}

    score = 0
    feedback = []
    bonuses = []
    missing = []   # criterios NAO atingidos, pra exibir "o que faltou"
    length = len(password)

    # Tamanho — acumula TODOS os bonus atingidos (>=8, >=12, >=16) pra fechar max_score = 19
    if length >= 8:
        score += 2; feedback.append("✅ Pelo menos 8 caracteres")
    elif length >= 6:
        score += 1; feedback.append("⚠️ Senha curta — tente pelo menos 8 caracteres")
        missing.append({"pts": 1, "reason": "atingir 8 caracteres (+1 pt)"})
    else:
        feedback.append("❌ Senha muito curta (mínimo 6 caracteres)")
        missing.append({"pts": 2, "reason": "atingir 8 caracteres (+2 pts)"})

    if length >= 12:
        score += 3; bonuses.append("🌟 12+ caracteres (+3)")
    else:
        missing.append({"pts": 3, "reason": "atingir 12 caracteres (+3 pts)"})

    if length >= 16:
        score += 2; bonuses.append("🏆 16+ caracteres (+2)")
    else:
        missing.append({"pts": 2, "reason": "atingir 16 caracteres (+2 pts)"})

    # Variedade de caracteres
    if re.search(r'[a-z]', password): score += 2; feedback.append("✅ Tem letras minúsculas")
    else:
        feedback.append("❌ Falta letra minúscula")
        missing.append({"pts": 2, "reason": "letra minúscula (+2 pts)"})
    if re.search(r'[A-Z]', password): score += 2; feedback.append("✅ Tem letras maiúsculas")
    else:
        feedback.append("❌ Falta letra maiúscula")
        missing.append({"pts": 2, "reason": "letra maiúscula (+2 pts)"})
    if re.search(r'[0-9]', password): score += 2; feedback.append("✅ Tem números")
    else:
        feedback.append("❌ Falta número")
        missing.append({"pts": 2, "reason": "número (+2 pts)"})
    if re.search(r'[^a-zA-Z0-9]', password): score += 3; feedback.append("✅ Tem caracteres especiais")
    else:
        feedback.append("❌ Falta caractere especial (!@#$%)")
        missing.append({"pts": 3, "reason": "caractere especial (+3 pts)"})

    # Padrao comum
    pwd_lower = password.lower()
    has_pattern = any(re.search(pat, pwd_lower) for pat in COMMON_PATTERNS)
    if has_pattern:
        feedback.append("⚠️ Contém padrão comum (123, abc, qwerty...)")
        missing.append({"pts": 2, "reason": "sem padrão comum como 123, abc, qwerty (+2 pts)"})
    else:
        score += 2; feedback.append("✅ Sem padrões óbvios")

    # Repeticao em sequencia
    if re.search(r'(.)\1\1', password):
        score -= 2; feedback.append("⚠️ Caracteres repetidos em sequência (aaa, 111)")
        missing.append({"pts": 1, "reason": "sem repetições em sequência como aaa, 111 (+1 pt)"})
    else:
        score += 1; feedback.append("✅ Sem repetições em sequência")

    score = max(0, score)
    percent = int((score / 19) * 100)  # max real e 19, nao 18

    if score <= 6: strength, label, color = "fraca", "❌ Fraca", "#FF6B6B"
    elif score <= 10: strength, label, color = "media", "⚠️ Média", "#FFC98A"
    elif score <= 14: strength, label, color = "forte", "✅ Forte", "#A8D5BA"
    else: strength, label, color = "epica", "⭐ Épica", "#F29DBF"

    if length < 6: time_str = "instantâneo"
    elif length < 8 and not has_pattern: time_str = "algumas horas"
    elif length < 10: time_str = "dias"
    elif length < 12: time_str = "anos"
    elif length < 16: time_str = "séculos"
    else: time_str = "mais que a idade do universo 🌌"

    return {"score": score, "max_score": 19, "strength": strength, "label": label, "color": color, "percent": percent, "time": time_str, "feedback": feedback, "bonuses": bonuses, "missing": missing, "length": length}


@app.route('/game/<int:game_id>/phase/1/sub/0/submit', methods=['POST'])
@login_required
def phase1_sub0_submit(game_id):
    """Mini drag-and-drop de aquecimento (sub 0 da Fase 1). 4 cards:
    2 faceis + 2 dificeis. Avanca para a sub 1 (teclado virtual).

    Pontuacao por acerto: 25 pts por cartao certo (4 acertos = 100 pts = fase cheia).
    Mesma logica do DnD de 8 cartoes da sub 3, so que em escala 4."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        data = {}

    score = int(data.get('score', 0))
    correct = int(data.get('correct', 0))
    wrong = int(data.get('wrong', 0))

    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 0",
        (game_id,)
    ).fetchone()
    if existing:
        return jsonify({"error": "Voce ja completou essa fase"}), 400

    # Pontuacao: 25 pts por acerto (4 acertos = 100 = fase cheia)
    points = correct * 25
    is_strong = correct >= 3

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, 1, 0, ?)",
        (game_id, is_strong)
    )
    if points > 0:
        db.execute(
            "UPDATE game_sessions SET score = score + ? WHERE id = ?",
            (points, game_id)
        )
    db.commit()

    next_url = url_for('game_play', game_id=game_id, phase=1, sub=1)

    return jsonify({
        "success": True,
        "score": score,
        "points_earned": points,
        "is_strong": is_strong,
        "correct": correct,
        "wrong": wrong,
        "next_url": next_url
    })


@app.route('/game/<int:game_id>/phase/1/submit', methods=['POST'])
@login_required
def phase1_submit(game_id):
    """Teclado virtual (sub 2). Avanca para a sub 3 (drag and drop).

    O usuario pode refazer quantas vezes quiser: cada re-submit deleta a
    resposta anterior, reverte os pontos que tinham sido somados e
    recalcula tudo com base na nova senha. Isso incentiva o usuario a
    sempre tentar uma senha mais forte (se ele re-submeter uma fraca,
    perde os 10 pts anteriores)."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    password = request.form.get('password', '')
    result = check_password_strength(password)

    # Resubmit permitido: se ja existe resposta, deleta e reverte os pontos antigos
    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 2",
        (game_id,)
    ).fetchone()
    if existing:
        # Reverte os pontos que tinham sido creditados (100 pts se passou no submit)
        if existing['correct']:
            db.execute(
                "UPDATE game_sessions SET score = MAX(0, score - 100) WHERE id = ?",
                (game_id,)
            )
        db.execute(
            "DELETE FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 2",
            (game_id,)
        )

    is_strong = all([
        len(password) >= 10,
        re.search(r'[a-z]', password),
        re.search(r'[A-Z]', password),
        re.search(r'[0-9]', password),
        re.search(r'[^a-zA-Z0-9]', password),
    ])
    points = 100 if is_strong else 0

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, 1, 2, ?)",
        (game_id, is_strong)
    )
    if points > 0:
        db.execute(
            "UPDATE game_sessions SET score = score + ? WHERE id = ?",
            (points, game_id)
        )
    db.commit()

    next_url = url_for('game_play', game_id=game_id, phase=1, sub=3)

    return jsonify({
        "success": True,
        "score": result['score'], "max_score": result['max_score'],
        "is_strong": is_strong, "points_earned": points,
        "strength": result['strength'], "label": result['label'],
        "color": result['color'], "percent": result['percent'],
        "time": result['time'], "feedback": result['feedback'],
        "bonuses": result['bonuses'], "missing": result['missing'],
        "next_url": next_url
    })


@app.route('/game/<int:game_id>/phase/1/sub/2/submit', methods=['POST'])
@login_required
def phase1_sub2_submit(game_id):
    """Valida o resultado do jogo de classificar senhas (drag and drop).
    Mora dentro da Fase 1 (subfase 3) e empurra o jogador para a Fase 2.
    """
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    # Pega dados do JSON (frontend envia JSON)
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        data = {}

    score = int(data.get('score', 0))
    correct = int(data.get('correct', 0))
    wrong = int(data.get('wrong', 0))

    # Verifica se ja respondeu essa fase
    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 3",
        (game_id,)
    ).fetchone()
    if existing:
        return jsonify({"error": "Voce ja completou essa fase"}), 400

    # Pontuacao: 100 pts por fase, dividido pelos 8 cartoes (12.5 pts por acerto).
    # 8 acertos = 100 (gabarito); 4 acertos = 50 (metade); 1 acerto = 12.
    # Mantem a escala continua pra nao punir quem errou 1-2 cartoes.
    points = round(correct * 100 / 8)
    is_strong = correct >= 6

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, 1, 3, ?)",
        (game_id, is_strong)
    )
    db.execute(
        "UPDATE game_sessions SET score = score + ? WHERE id = ?",
        (points, game_id)
    )
    db.commit()

    next_url = url_for('game_play', game_id=game_id, phase=2, sub=1)

    return jsonify({
        "success": True,
        "score": score,
        "points_earned": points,
        "is_strong": is_strong,
        "correct": correct,
        "wrong": wrong,
        "next_url": next_url
    })


@app.route('/game/<int:game_id>/phase/1/sub/3/save-data', methods=['POST'])
@login_required
def phase1_sub3_save_data(game_id):
    """Salva os 5 dados ficticios do Construtor de Senha com Dados na sessao.
    O frontend usa isso pra construir o passo 2 (mostra senhas fracas).
    Os dados nao sao persistidos no banco — sao temporarios e vivem
    apenas na sessao do Flask."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception:
        return jsonify({"error": "JSON invalido."}), 400

    # Validacao: todos os 5 campos sao obrigatorios
    raw = {
        'pet':    data.get('pet', ''),
        'dob':    data.get('dob', ''),
        'team':   data.get('team', ''),
        'city':   data.get('city', ''),
        'mother': data.get('mother', ''),
    }
    missing = [k for k, v in raw.items() if not str(v).strip()]
    if missing:
        return jsonify({
            "error": "Preencha todos os campos antes de continuar.",
            "missing": missing
        }), 400

    # Validacao de formato: pet/team/city/mother = letras (com acento) e espacos;
    # dob = apenas digitos. Defesa em profundidade alem do filtro JS do frontend.
    ALPHA_PATTERN = re.compile(r'^[A-Za-zÀ-ÿ\s]+$')
    DIGIT_PATTERN = re.compile(r'^[0-9]+$')
    invalid_format = []
    if not ALPHA_PATTERN.match(str(raw['pet'])):
        invalid_format.append('pet')
    if not DIGIT_PATTERN.match(str(raw['dob'])):
        invalid_format.append('dob')
    if not ALPHA_PATTERN.match(str(raw['team'])):
        invalid_format.append('team')
    if not ALPHA_PATTERN.match(str(raw['city'])):
        invalid_format.append('city')
    if not ALPHA_PATTERN.match(str(raw['mother'])):
        invalid_format.append('mother')
    if invalid_format:
        return jsonify({
            "error": "Verifique o formato dos campos: nome/texto aceita apenas letras, data aceita apenas numeros.",
            "invalid_format": invalid_format
        }), 400

    # Salva os 5 campos na sessao (so pra esse usuario + esse game)
    session[f'p1s3_personal_{game_id}'] = {
        'pet':    str(raw['pet']).strip()[:40],
        'dob':    str(raw['dob']).strip()[:10],
        'team':   str(raw['team']).strip()[:40],
        'city':   str(raw['city']).strip()[:40],
        'mother': str(raw['mother']).strip()[:40],
    }

    # Pre-calcula as 5 senhas fracas com base nos dados, pra o frontend
    # renderizar no passo 2. (Todos os campos ja vieram preenchidos —
    # a validacao acima garante isso.)
    d = session[f'p1s3_personal_{game_id}']
    pet = d['pet'] or 'pet'
    dob = d['dob'] or '15051998'
    team = d['team'] or 'time'
    city = d['city'] or 'cidade'
    mother = d['mother'] or 'mae'

    # Extrai o ano (4 ultimos digitos) e o dia+mes (do meio) da data.
    # Ex: "29122006" -> day_month="2912", year="2006"
    digits_only = ''.join(c for c in dob if c.isdigit())
    year = digits_only[-4:] if len(digits_only) >= 4 and digits_only[-4:].isdigit() else '1990'
    day_month = digits_only[:4] if len(digits_only) >= 4 else '0101'
    # Pega a primeira letra do pet e do time (variação "inicial + algo")
    pet_initial = pet[0].lower() if pet else 'p'
    team_initial = team[0].lower() if team else 't'
    # Time sem espacos e em minusculo pra combinacoes tipo "santos2912"
    team_compact = team.lower().replace(' ', '') if team else 'time'
    # Mae sem espacos e em minusculo pra combinacoes tipo "jane29122006"
    mother_compact = mother.lower().replace(' ', '') if mother else 'mae'

    weak_passwords = [
        # 1) inicial do pet + ano de nascimento
        (f'{pet_initial}{year}',         f'inicial do pet + ano (ex: nome do pet comecando com a letra e ano de nascimento)'),
        # 2) inicial do time + ano de nascimento
        (f'{team_initial}{year}',        f'inicial do time + ano (ex: time do coracao comecando pela letra e ano de nascimento)'),
        # 3) nome da mae + data completa
        (f'{mother_compact}{digits_only}', f'nome da mae + data completa (mae e data inteira sao uma combinacao classica)'),
        # 4) cidade + ano
        (f'{city}{year}',                f'cidade + ano (ex: local de nascimento seguido do ano)'),
        # 5) pet + ano (classica)
        (f'{pet}{year}',                 f'pet + ano (a combinacao mais obvia: nome do animal + ano de nascimento)'),
        # 6) time + dia/mes
        (f'{team_compact}{day_month}',   f'time + dia/mes de nascimento (time do coracao + aniversario no formato DDMM)'),
    ]

    return jsonify({
        "success": True,
        "weak_passwords": weak_passwords
    })


@app.route('/game/<int:game_id>/phase/1/sub/3/submit', methods=['POST'])
@login_required
def phase1_sub3_submit(game_id):
    """Fecha a subfase 1 (Construtor de Senha) e avanca para o teclado virtual.
    Nao soma pontos: a subfase 1 e educativa, nao pontuavel."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = 1 AND subphase = 1",
        (game_id,)
    ).fetchone()
    if existing:
        return jsonify({"error": "Voce ja completou essa fase"}), 400

    # Trava de seguranca: o usuario precisa ter passado pelo save-data com
    # todos os 5 campos preenchidos. Sem isso, nao fechamos a subfase.
    personal = session.get(f'p1s3_personal_{game_id}')
    required = ('pet', 'dob', 'team', 'city', 'mother')
    if not personal or not all(str(personal.get(k, '')).strip() for k in required):
        return jsonify({
            "error": "Preencha todos os campos do Construtor de Senha antes de continuar."
        }), 400

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, 1, 1, ?)",
        (game_id, True)
    )
    db.commit()

    next_url = url_for('game_play', game_id=game_id, phase=1, sub=2)

    return jsonify({
        "success": True,
        "next_url": next_url
    })


@app.route('/game/<int:game_id>/answer', methods=['POST'])
@login_required
def game_answer(game_id):
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()

    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    phase = int(request.form.get('phase', 1))
    sub = int(request.form.get('sub', 1))
    answer = int(request.form.get('answer', -1))

    if phase not in GAME_PHASES:
        return jsonify({"error": "Fase invalida"}), 400

    phase_data = GAME_PHASES[phase]
    if sub > len(phase_data['subphases']):
        return jsonify({"error": "Sub-fase invalida"}), 400

    subphase_data = phase_data['subphases'][sub - 1]

    # Verificar se ja respondeu
    existing = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? AND phase = ? AND subphase = ?",
        (game_id, phase, sub)
    ).fetchone()

    if existing:
        return jsonify({"error": "Voce ja respondeu essa pergunta"}), 400

    correct = (answer == subphase_data['correct'])
    points = 100 if correct else 0

    db.execute(
        "INSERT INTO phase_answers (session_id, phase, subphase, correct) VALUES (?, ?, ?, ?)",
        (game_id, phase, sub, correct)
    )

    if correct:
        db.execute(
            "UPDATE game_sessions SET score = score + ? WHERE id = ?",
            (points, game_id)
        )

    db.commit()

    # Determinar proximo destino
    next_sub = sub + 1
    next_phase = phase
    if next_sub > len(phase_data['subphases']):
        next_phase = phase + 1
        next_sub = 1

    is_final = (next_phase not in GAME_PHASES)

    if is_final:
        db.execute(
            "UPDATE game_sessions SET completed = 1, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            (game_id,)
        )
        db.commit()
        check_and_award_badges(session['user_id'])

    if phase_data.get('classify'):
        explanation_title = "Classificação correta! +100 pontos" if correct else "Classificação incorreta... 0 pontos"
    else:
        explanation_title = "Acertou! +100 pontos" if correct else "Que pena... 0 pontos"

    return jsonify({
        "correct": correct,
        "explanation": subphase_data['explanation_correct'] if correct else subphase_data['explanation_wrong'],
        "points_earned": points,
        "explanation_title": explanation_title,
        "next_phase": next_phase,
        "next_sub": next_sub,
        "is_final": is_final,
        "next_url": url_for('game_feedback', game_id=game_id) if is_final
                   else url_for('game_play', game_id=game_id, phase=next_phase, sub=next_sub)
    })

@app.route('/game/<int:game_id>/hacked', methods=['POST'])
@login_required
def game_hacked(game_id):
    """Tempo esgotado em questao com timer: o jogador foi hackeado.
    Os pontos da fase inteira sao descartados (zerados)."""
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 0",
        (game_id, session['user_id'])
    ).fetchone()

    if not game:
        return jsonify({"error": "Sessao invalida"}), 400

    phase = int(request.form.get('phase', 0))
    sub = int(request.form.get('sub', 0))

    if phase not in GAME_PHASES:
        return jsonify({"error": "Fase invalida"}), 400

    phase_data = GAME_PHASES[phase]
    if sub > len(phase_data['subphases']):
        return jsonify({"error": "Sub-fase invalida"}), 400

    # Zera as respostas corretas dessa fase e desconta os pontos ganhos nela
    lost = 0
    row = db.execute(
        "SELECT COUNT(*) AS n FROM phase_answers WHERE session_id = ? AND phase = ? AND correct = 1",
        (game_id, phase)
    ).fetchone()
    lost = row['n'] * 10
    if lost:
        db.execute(
            "UPDATE phase_answers SET correct = 0 WHERE session_id = ? AND phase = ? AND correct = 1",
            (game_id, phase)
        )
        db.execute(
            "UPDATE game_sessions SET score = MAX(0, score - ?) WHERE id = ?",
            (lost, game_id)
        )

    # Registra a questao atual como nao respondida a tempo (timeout)
    existing = db.execute(
        "SELECT id FROM phase_answers WHERE session_id = ? AND phase = ? AND subphase = ?",
        (game_id, phase, sub)
    ).fetchone()
    if not existing:
        db.execute(
            "INSERT INTO phase_answers (session_id, phase, subphase, correct, timed_out) VALUES (?, ?, ?, 0, 1)",
            (game_id, phase, sub)
        )

    # Se era a ultima questao do jogo, finaliza a sessao
    next_sub = sub + 1
    next_phase = phase
    if next_sub > len(phase_data['subphases']):
        next_phase = phase + 1
        next_sub = 1

    is_final = (next_phase not in GAME_PHASES)
    if is_final:
        db.execute(
            "UPDATE game_sessions SET completed = 1, finished_at = CURRENT_TIMESTAMP WHERE id = ?",
            (game_id,)
        )
        check_and_award_badges(session['user_id'])
    db.commit()

    return jsonify({
        "ok": True,
        "hacked": True,
        "points_lost": lost,
        "is_final": is_final,
        "next_url": url_for('game_feedback', game_id=game_id) if is_final
                   else url_for('game_play', game_id=game_id, phase=next_phase, sub=next_sub)
    })


@app.route('/game/<int:game_id>/feedback')
@login_required
def game_feedback(game_id):
    db = get_db()
    game = db.execute(
        "SELECT * FROM game_sessions WHERE id = ? AND user_id = ?",
        (game_id, session['user_id'])
    ).fetchone()

    if not game:
        flash('Sessao nao encontrada.', 'danger')
        return redirect(url_for('dashboard'))

    answers = db.execute(
        "SELECT * FROM phase_answers WHERE session_id = ? ORDER BY phase, subphase",
        (game_id,)
    ).fetchall()

    score = game['score']
    # Cap em 100%: se a sessao antiga tem pontos de subfases que foram removidas
    # (score > teto novo), capamos o score no teto pra nao mostrar >100%.
    # Tambem cap o max no teto novo (sessoes antigas gravadas com max=2100/1700).
    max_score_possible = sum(
        sum(1 for s in p['subphases'] if s.get('scorable', True))
        for p in GAME_PHASES.values()
    ) * 100
    score = min(game['score'], max_score_possible)
    max_score = min(game['max_score'], max_score_possible)
    percentage = (score / max_score * 100) if max_score > 0 else 0

    # Gerar feedback personalizado
    if percentage >= 90:
        feedback_level = "excelente"
        feedback_image = "img/badges/trofeu.png"
        feedback_msg = (
            "Voce e um verdadeiro guardiao digital! Seu conhecimento em ciberseguranca "
            "e impressionante. Continue assim e ajude seus colegas a se protegerem tambem!"
        )
    elif percentage >= 60:
        feedback_level = "bom"
        feedback_image = "img/badges/ok.png"
        feedback_msg = (
            "Bom trabalho! Voce tem uma base solida, mas ainda pode melhorar. "
            "Revise os topicos onde errou e tente novamente para alcancar a pontuacao maxima!"
        )
    elif percentage >= 30:
        feedback_level = "regular"
        feedback_image = "img/badges/justica.png"
        feedback_msg = (
            "Voce esta no caminho certo, mas precisa de mais atencao. "
            "A ciberseguranca e essencial no dia a dia. Que tal jogar novamente "
            "para reforcar o aprendizado?"
        )
    else:
        feedback_level = "iniciante"
        feedback_image = "img/badges/inciante.png"
        feedback_msg = (
            "Todo expert ja foi iniciante! Nao desanime. "
            "A ciberseguranca e uma habilidade que se desenvolve com pratica. "
            "Jogue novamente e preste atencao nas explicacoes!"
        )

    # Mapeamento fase -> icone PNG da badge
    PHASE_BADGE_ICON = {
        1: 'img/badges/chave.png',
        2: 'img/badges/cadeado.png',
        3: 'img/badges/phishing.png',
        4: 'img/badges/engrenagem.png',
        5: 'img/badges/celular.png',
        6: 'img/badges/robo.png',
    }

    # Detalhamento por fase
    phase_details = []
    for p_num, p_data in GAME_PHASES.items():
        phase_answers = [a for a in answers if a['phase'] == p_num]
        correct_count = sum(1 for a in phase_answers if a['correct'])
        total_count = len(p_data['subphases'])
        phase_details.append({
            "num": p_num,
            "title": p_data['title'],
            "icon": p_data['icon'],
            "badge_icon": PHASE_BADGE_ICON.get(p_num, ''),
            "correct": correct_count,
            "total": total_count,
            "percentage": (correct_count / total_count * 100) if total_count > 0 else 0
        })

    return render_template('feedback.html',
                         game=game,
                         score=score,
                         max_score=max_score,
                         percentage=percentage,
                         feedback_level=feedback_level,
                         feedback_image=feedback_image,
                         feedback_msg=feedback_msg,
                         phase_details=phase_details,
                         answers=answers,
                         game_id=game_id)


# ─── Reset próprio progresso ────────────────────────────────
@app.route('/reset-my-progress', methods=['POST'])
@login_required
def reset_my_progress():
    user_id = session['user_id']
    db = get_db()
    db.execute("DELETE FROM phase_answers WHERE session_id IN (SELECT id FROM game_sessions WHERE user_id = ?)", (user_id,))
    db.execute("DELETE FROM game_sessions WHERE user_id = ?", (user_id,))
    db.execute("DELETE FROM user_badges WHERE user_id = ?", (user_id,))
    db.commit()
    flash('Seu progresso foi resetado com sucesso.', 'success')
    return redirect(url_for('dashboard'))


# ─── Certificado ─────────────────────────────────────────────
@app.route('/certificado/<int:game_id>')
@login_required
def certificado(game_id):
    db = get_db()
    game = db.execute(
        "SELECT id FROM game_sessions WHERE id = ? AND user_id = ? AND completed = 1",
        (game_id, session['user_id'])
    ).fetchone()
    if not game:
        flash('Certificado disponivel apenas para jogos concluidos.', 'warning')
        return redirect(url_for('dashboard'))

    cert_path = os.path.join(app.root_path, 'static', 'assets', 'certificado.png')
    return send_file(cert_path, mimetype='image/png',
                     download_name='certificado_security_alert.png', as_attachment=True)


# ─── Inicializacao ───────────────────────────────────────────
@app.before_request
def before_request():
    init_db()

if __name__ == '__main__':
    print("=" * 55)
    print("🛡️  SECURITY ALERT - Plataforma de Treinamento")
    print("   Challenge Leroy Merlin 2026 - FIAP")
    print("=" * 55)
    print()
    print("🌐 Acesse: http://localhost:5000")
    print("📋 Para parar: pressione Ctrl+C")
    print()
    # Somente para desenvolvimento local. Em producao a aplicacao roda via
    # gunicorn (ver Dockerfile), responsavel pelo bind de host/porta.
    app.run(debug=_env_bool('DEBUG', False), port=int(os.environ.get('PORT', '5000')))

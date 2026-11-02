"""Testes automatizados da aplicacao Security Alert (etapa 3 da esteira)."""
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import app as app_module  # noqa: E402

PNG_BYTES = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64
# Credencial FICTICIA usada apenas nos testes automatizados (banco temporario).
# Falso positivo do Gitleaks (generic-api-key) suprimido inline e justificado em docs/observacoes.md.
VALID_USER = {
    'username': 'tester',
    'email': 'tester@example.com',
    'loja': 'Loja A',
    'password': 'SenhaForte123',  # gitleaks:allow
    'confirm': 'SenhaForte123',  # gitleaks:allow
}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Cliente de teste com banco SQLite temporario e isolado por teste."""
    monkeypatch.setattr(app_module, 'DATABASE', str(tmp_path / 'test.db'))
    monkeypatch.setitem(app_module.app.config, 'AVATAR_UPLOAD_DIR', str(tmp_path / 'avatars'))
    monkeypatch.setitem(app_module.app.config, 'SESSION_COOKIE_SECURE', False)
    monkeypatch.setitem(app_module.app.config, 'TESTING', True)
    with app_module.app.test_client() as c:
        yield c


def csrf(client):
    """Obtem um token CSRF valido renderizando uma pagina."""
    client.get('/login')
    with client.session_transaction() as sess:
        return sess['csrf_token']


def query_user(username):
    with app_module.app.app_context():
        app_module.init_db()
        db = app_module.get_db()
        return db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


def register_and_login(client):
    token = csrf(client)
    client.post('/register', data={**VALID_USER, 'csrf_token': token})
    token = csrf(client)
    return client.post('/login', data={'login': VALID_USER['username'],
                                       'password': VALID_USER['password'],
                                       'csrf_token': token})


def test_index_responde(client):
    resp = client.get('/')
    assert resp.status_code in (200, 302)


def test_login_page_responde_200(client):
    resp = client.get('/login')
    assert resp.status_code == 200
    assert b'csrf-token' in resp.data


def test_cabecalhos_de_seguranca(client):
    resp = client.get('/login')
    assert resp.headers['X-Content-Type-Options'] == 'nosniff'
    assert resp.headers['X-Frame-Options'] == 'DENY'
    assert resp.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
    assert "frame-ancestors 'none'" in resp.headers['Content-Security-Policy']


def test_configuracao_segura_padrao():
    # Valores padrao definidos no modulo (antes de qualquer override de teste)
    assert app_module.app.config['SESSION_COOKIE_HTTPONLY'] is True
    assert app_module.app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
    assert app_module.app.config['MAX_CONTENT_LENGTH'] == 2 * 1024 * 1024
    assert app_module.app.debug is False


def test_post_sem_csrf_e_rejeitado(client):
    resp = client.post('/register', data=VALID_USER)
    assert resp.status_code == 400
    assert query_user('tester') is None


def test_register_senha_fraca_retorna_erro(client):
    token = csrf(client)
    data = {**VALID_USER, 'password': '123', 'confirm': '123', 'csrf_token': token}
    resp = client.post('/register', data=data)
    assert resp.status_code == 200
    assert 'Senha deve ter pelo menos 6 caracteres'.encode() in resp.data
    assert query_user('tester') is None


def test_register_valido_cria_usuario_com_hash(client):
    token = csrf(client)
    resp = client.post('/register', data={**VALID_USER, 'csrf_token': token})
    assert resp.status_code == 302
    user = query_user('tester')
    assert user is not None
    assert user['password_hash'] != VALID_USER['password']


def test_login_bloqueia_open_redirect(client):
    token = csrf(client)
    client.post('/register', data={**VALID_USER, 'csrf_token': token})
    token = csrf(client)
    resp = client.post('/login?next=https://evil.example.com/',
                       data={'login': 'tester', 'password': VALID_USER['password'],
                             'csrf_token': token})
    assert resp.status_code == 302
    assert 'evil.example.com' not in resp.headers['Location']


def test_login_aceita_next_local(client):
    token = csrf(client)
    client.post('/register', data={**VALID_USER, 'csrf_token': token})
    token = csrf(client)
    resp = client.post('/login?next=/badges',
                       data={'login': 'tester', 'password': VALID_USER['password'],
                             'csrf_token': token})
    assert resp.status_code == 302
    assert resp.headers['Location'].endswith('/badges')


@pytest.mark.parametrize('filename,content', [
    ('malware.php', PNG_BYTES),                  # extensao invalida
    ('fake.png', b'<?php system($_GET[1]); ?>'),  # magic byte invalido
], ids=['extensao_invalida', 'magic_byte_invalido'])
def test_upload_avatar_invalido_e_rejeitado(client, filename, content):
    register_and_login(client)
    token = csrf(client)
    resp = client.post('/perfil', data={'profile_image': (io.BytesIO(content), filename),
                                        'csrf_token': token},
                       content_type='multipart/form-data')
    assert resp.status_code == 302
    assert query_user('tester')['profile_image'] is None


def test_upload_avatar_png_valido_e_aceito(client):
    register_and_login(client)
    token = csrf(client)
    resp = client.post('/perfil', data={'profile_image': (io.BytesIO(PNG_BYTES), 'foto.png'),
                                        'csrf_token': token},
                       content_type='multipart/form-data')
    assert resp.status_code == 302
    assert query_user('tester')['profile_image'] == 'user_1.png'


def test_upload_acima_do_limite_e_rejeitado(client):
    register_and_login(client)
    token = csrf(client)
    big = PNG_BYTES + b'\x00' * (3 * 1024 * 1024)
    resp = client.post('/perfil', data={'profile_image': (io.BytesIO(big), 'grande.png'),
                                        'csrf_token': token},
                       content_type='multipart/form-data')
    assert resp.status_code == 413


def test_is_safe_redirect():
    assert app_module.is_safe_redirect('/dashboard')
    assert not app_module.is_safe_redirect('//evil.com')
    assert not app_module.is_safe_redirect('https://evil.com')
    assert not app_module.is_safe_redirect('/\\evil.com')
    assert not app_module.is_safe_redirect(None)


def test_fetch_com_header_csrf_e_aceito(client):
    """Chamadas fetch() do jogo enviam o token no cabecalho X-CSRFToken."""
    register_and_login(client)
    token = csrf(client)
    assert client.post('/toggle-ranking').status_code == 400
    resp = client.post('/toggle-ranking', headers={'X-CSRFToken': token})
    assert resp.status_code in (200, 302)

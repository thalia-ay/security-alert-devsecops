# Principais observações – análise dos achados

> **Como ler este documento:**
> - **Seção 1:** achados da revisão manual do código original, com as correções aplicadas.
> - **Seção 2:** achados das ferramentas executadas **localmente**, antes do primeiro push: Semgrep 1.183.0, Gitleaks 8.30.1 e Trivy 0.76.1.
> - **Seção 3:** espaço para os resultados das execuções **no GitHub Actions**. Ela só deve ser preenchida com dados reais dos artifacts.

---

## 1. Revisão manual do código original (antes da esteira)

| Achado (severidade) | Onde | Classificação | Ação tomada | Resultado esperado |
|---|---|---|---|---|
| Flask em modo debug (`debug=True`, `host='0.0.0.0'`). O debugger do Werkzeug permite execução remota de código. **Crítico** | `src/app.py`, `app.run(...)` | Vulnerabilidade real | O debug agora vem de `DEBUG`, desligado por padrão. O bind passou para o gunicorn (Dockerfile). | Semgrep sem `debug-enabled`; produção roda via gunicorn |
| `SECRET_KEY` aleatória a cada start, sem configuração. Sessões inválidas e workers inconsistentes. **Médio** | `src/app.py` | Vulnerabilidade real (disponibilidade e integridade de sessão) | Lida de `SECRET_KEY` no ambiente, com fallback aleatório só para desenvolvimento | Sessões estáveis em produção com o secret configurado |
| Ausência de proteção CSRF em todos os formulários POST (admin: excluir usuário, promover admin, resetar senha). **Alto** | `src/app.py` e `templates/*.html` | Vulnerabilidade real | Token sincronizador por sessão, validado em `before_request` para POST, PUT, PATCH e DELETE. Campo oculto nos formulários e cabeçalho `X-CSRFToken` nos `fetch()`. | POST sem token → HTTP 400 (testes `test_post_sem_csrf_e_rejeitado` e `test_fetch_com_header_csrf_e_aceito`) |
| Cookie de sessão sem `Secure` e `SameSite`. **Médio** | `src/app.py` | Vulnerabilidade real | `SESSION_COOKIE_SECURE=True` (configurável), `HTTPONLY` e `SAMESITE=Lax` | O ZAP não deve reportar *Cookie without Secure/SameSite* |
| Ausência de cabeçalhos de segurança (CSP, X-Frame-Options, nosniff, HSTS etc.). **Médio** | Respostas HTTP | Vulnerabilidade real | `after_request` com CSP, XFO, nosniff, Referrer-Policy, Permissions-Policy, COOP, CORP, HSTS e `Cache-Control: no-store` | Redução dos alertas do ZAP Baseline (teste `test_cabecalhos_de_seguranca`) |
| Upload de avatar validado apenas pela extensão. **Médio** | `src/app.py`, rota `/perfil` | Vulnerabilidade real | Validação de *magic bytes* (PNG, JPEG, GIF, WEBP) e `MAX_CONTENT_LENGTH` de 2 MB | Arquivo disfarçado é rejeitado e upload grande retorna 413 (testes de upload) |
| Sem renovação da sessão no login (session fixation) e sem tratamento seguro de `next`. **Baixo** | `src/app.py`, `/login` | Hardening | `session.clear()` no login; `next` aceito só como caminho local (`is_safe_redirect`) | Teste `test_login_bloqueia_open_redirect` |
| Banco SQLite com 24 usuários e hashes de senha, além de avatares de usuários, no pacote original. **Alto** | `instance/security_alert.db`, `static/img/avatars/user_*.png` | Exposição de dados | **Não versionados.** Ficam em `.gitignore` e `.dockerignore`, e o banco é criado do zero. | Nenhum dado pessoal no repositório nem na imagem |
| Dependências sem versão fixa (`flask>=3.0`). **Médio** | `requirements.txt` | Má prática (build não reprodutível) | Lock com versões exatas e hashes (`pip-compile --generate-hashes`), instalado com `--require-hashes` | Build determinístico e SCA preciso |

## 2. Pré-validação local das ferramentas (executado antes do primeiro push)

| Ferramenta | Achado (severidade) | Onde | Classificação | Ação tomada | Resultado da reexecução local |
|---|---|---|---|---|---|
| Semgrep | `python.lang.security.audit.formatted-sql-query` (WARNING) e `python.sqlalchemy.security.sqlalchemy-execute-raw-query` (ERROR) | `src/app.py`, `init_db()`: `ALTER TABLE ... DEFAULT '{DEFAULT_CHARACTER}'` com f-string | Vulnerabilidade real em potencial. O valor era uma constante interna, mas o padrão é inseguro. | O f-string foi trocado por um literal fixo. DDL não aceita parâmetros `?` no `DEFAULT`. | Achado eliminado |
| Semgrep | `python.django.security.django-no-csrf-token` (WARNING), 8 ocorrências | Formulários POST em `templates/*.html` | Inicialmente, **vulnerabilidade real**: não havia CSRF | CSRF implementado (seção 1) | Restaram 4 ocorrências mesmo com o campo `csrf_token` presente. Ver a linha abaixo. |
| Semgrep | `django-no-csrf-token` (persistente) | `login.html`, `perfil.html`, `personagem.html`, `reset_password.html` | **Falso positivo.** A regra procura a tag `{% csrf_token %}`, exclusiva do Django. A aplicação é Flask e usa o campo `csrf_token`, validado no servidor e coberto por testes. | Regra excluída **individualmente** com `--exclude-rule` no workflow, com comentário | `semgrep --error` com exit code 0 em todo o repositório |
| Gitleaks | `generic-api-key` | `tests/test_app.py`, senha fictícia `SenhaForte123` usada nos testes | **Falso positivo.** A credencial é fictícia e só existe em banco temporário de teste. | Supressão inline `# gitleaks:allow`, com comentário no próprio arquivo | `no leaks found` |
| Trivy fs | HIGH/CRITICAL em `requirements.txt` e no `Dockerfile` | Repositório | Nenhum achado | Nenhuma | `0` vulnerabilidades e `0` misconfigurations |

> O build Docker, o Trivy image e o ZAP **não foram executados localmente** porque o ambiente de preparação não permite executar containers. A primeira validação dessas etapas acontece no GitHub Actions.

## 3. Resultados da esteira no GitHub Actions

> [a preencher após primeira execução do pipeline]. Usar os artifacts `relatorio-0N-*` de cada execução.

### 3.1 Gitleaks
| Achado | Onde | Classificação | Ação tomada (link do commit) | Resultado (link da execução) |
|---|---|---|---|---|
| [a preencher após primeira execução do pipeline] | | | | |

### 3.2 Semgrep
| Achado | Onde | Classificação | Ação tomada (link do commit) | Resultado (link da execução) |
|---|---|---|---|---|
| [a preencher após primeira execução do pipeline] | | | | |

### 3.3 Build / pip-audit
| Achado | Onde | Classificação | Ação tomada (link do commit) | Resultado (link da execução) |
|---|---|---|---|---|
| [a preencher após primeira execução do pipeline] | | | | |

### 3.4 Trivy fs (SCA)
| Achado | Onde | Classificação | Ação tomada (link do commit) | Resultado (link da execução) |
|---|---|---|---|---|
| [a preencher após primeira execução do pipeline] | | | | |

### 3.5 Trivy image
| Achado | Onde | Classificação | Ação tomada (link do commit) | Resultado (link da execução) |
|---|---|---|---|---|
| [a preencher após primeira execução do pipeline] | | | | |

### 3.6 OWASP ZAP
| Achado | Onde | Classificação | Ação tomada (link do commit) | Resultado (link da execução) |
|---|---|---|---|---|
| [a preencher após primeira execução do pipeline] | | | | |

### 3.7 Execução bloqueada por quality gate (demonstração)
> [a preencher]. Sugestão:
> 1. Criar a branch `teste/quality-gate` com um segredo **fictício**, por exemplo uma chave AWS de exemplo da documentação, ou com uma dependência vulnerável fixada de propósito (ex.: `jinja2==2.10`).
> 2. Fazer o push e registrar aqui o link da execução que falhou na etapa 1 ou 4.
> 3. Registrar a correção e a execução seguinte, já verde.
> 4. **Nunca** fazer merge dessa branch na `main`.

---

## Supressões e riscos aceitos

| Item | Tipo | Justificativa |
|---|---|---|
| `--exclude-rule python.django.security.django-no-csrf-token...` | Supressão Semgrep (1 regra) | A regra é específica do Django. A aplicação é Flask com CSRF próprio, validado no servidor e testado. |
| `# gitleaks:allow` em `tests/test_app.py` | Supressão Gitleaks (2 linhas) | Credencial fictícia de teste |
| CSP com `'unsafe-inline'` em `script-src` e `style-src` | Risco aceito | Os templates do jogo têm muitos scripts e estilos inline. Migrar para arquivos estáticos com nonce é a melhoria planejada. Os demais controles da CSP continuam valendo (`frame-ancestors`, `object-src`, `base-uri`, `form-action`). |
| Cabeçalho `Server: gunicorn` | Risco aceito (baixo) | Não expõe a versão. Pode ser removido com um proxy reverso em produção. |

## Adaptações para Python

O enunciado usa Node.js como referência. A aplicação é Flask (Python), então os comandos foram adaptados:

| Referência (Node) | Adaptação (Python) | Motivo |
|---|---|---|
| `npm ci` + `package-lock.json` | `pip install --require-hashes -r src/requirements.txt` | O `requirements.txt` é um lock gerado por `pip-compile --generate-hashes`, a partir de `requirements.in`, com versões exatas e hashes |
| `npm audit --json` → `npm-audit.json` | `pip-audit --format json` → `pip-audit.json` | Auditoria nativa do ecossistema PyPI (informativa) |
| `npm ls` (árvore) | `pipdeptree` → `arvore-dependencias.txt` | Inventário das dependências transitivas |
| `npm test` | `pytest` + `pytest-cov` | 15 testes cobrindo as correções de segurança |
| `npm run build` | `tar.gz` de `src/` nomeado com o SHA | Python não tem compilação; o artefato é o pacote do código |
| `node server.js` | `gunicorn app:app` | Servidor WSGI de produção |

## Limitações conhecidas

1. **Deploy de produção depende de configuração externa.** O job está implementado para o Render (Deploy Hook com a imagem pelo digest). Sem o secret `RENDER_DEPLOY_HOOK_URL` no environment `producao`, ele **não faz deploy** e informa isso no relatório.
2. **SQLite em container é efêmero.** Sem um volume persistente no provedor, os dados se perdem a cada redeploy. Para produção real, recomenda-se volume persistente ou banco gerenciado.
3. **`SECRET_KEY` precisa ser configurada.** Sem ela, a app gera uma chave aleatória por processo. Com 2 workers do gunicorn, isso causa sessões inconsistentes.
4. **`SESSION_COOKIE_SECURE=True` por padrão.** Para rodar localmente via HTTP, defina `SESSION_COOKIE_SECURE=false`.
5. **Primeiro administrador.** Como o banco não é versionado, o admin inicial é criado pelas variáveis `ADMIN_USERNAME`, `ADMIN_EMAIL` e `ADMIN_PASSWORD` (mínimo de 12 caracteres), configuradas como secrets do provedor.
6. **Redefinição de senha sem verificação de posse do e-mail** (`/reset-password`). Esse comportamento é herdado da aplicação original. Fica registrado como risco a tratar: envio de token por e-mail.
7. **Não há rate limiting no login.** Melhoria futura: Flask-Limiter ou proxy reverso.

## Lições aprendidas

> As lições 1 a 5 vêm da preparação da esteira. Completar com as observações das execuções reais: tempo total da esteira, ferramenta com mais falsos positivos etc.

1. **Dados sensíveis chegam ao repositório pelo "pacote do projeto", não só pelo código.** O ZIP original trazia o banco com usuários e hashes de senha. `.gitignore` e `.dockerignore` são controles de segurança, não detalhe de organização.
2. **Regras de SAST são específicas de framework.** A regra de CSRF do Django gerou falsos positivos em Flask. Excluir **uma** regra com justificativa é diferente de silenciar o scanner em massa.
3. **O Semgrep encontrou um padrão inseguro (SQL com f-string) em código que "funcionava".** O valor era constante, mas o padrão se repete facilmente com entrada do usuário. Corrigir o padrão é melhor que justificar a exceção.
4. **Fixar versões não basta: hashes tornam o build verificável.** `--require-hashes` impede que um pacote adulterado com a mesma versão seja instalado. Fixar as actions pelo SHA aplica a mesma ideia ao próprio pipeline.
5. **Segurança em tempo de execução precisa de testes.** Cabeçalhos, CSRF e validação de upload só ficam garantidos com testes automatizados que quebram o build se alguém removê-los.
6. [a preencher após primeira execução do pipeline: tempo médio da esteira]
7. [a preencher após primeira execução do pipeline: comparação Trivy fs × Trivy image]

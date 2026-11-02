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

**Execução #1:** [https://github.com/thalia-ay/security-alert-devsecops/actions/runs/41516785203](https://github.com/thalia-ay/security-alert-devsecops/actions/runs/41516785203)
- Commit `943cfdf`, branch `main`.
- Status **Success**, duração total **5m 9s**, **12 artifacts**.
- Os números abaixo foram extraídos dos artifacts `relatorio-0N-*` dessa execução.
- Prints em [`evidencias/`](evidencias/).

### 3.1 Gitleaks
| Achado | Onde | Classificação | Ação tomada | Resultado |
|---|---|---|---|---|
| Nenhum segredo (`no leaks found`; 2 commits, ~535 KB analisados) | Histórico completo | — | Nenhuma necessária. A supressão inline em `tests/test_app.py` está justificada na seção 2. | `gitleaks.json` vazio ([print](evidencias/03-gitleaks.png)) |

### 3.2 Semgrep
| Achado | Onde | Classificação | Ação tomada | Resultado |
|---|---|---|---|---|
| `Findings: 0 (0 blocking)`: 44 arquivos e 534 regras (`p/default`, `p/owasp-top-ten`, `p/python`) | Repositório | — | Os achados reais foram corrigidos antes do push (seção 2). Única exclusão: `django-no-csrf-token` (falso positivo). | `semgrep.json` com 0 resultados ([print](evidencias/04-semgrep.png)) |

### 3.3 Build / pip-audit / testes
| Achado | Onde | Classificação | Ação tomada | Resultado |
|---|---|---|---|---|
| pip-audit: 0 vulnerabilidades | `src/requirements.txt` (lock com hashes) | — | Nenhuma | `pip-audit.json` |
| 15 testes `PASSED` em 1,46 s. Cobertura de `src/app.py`: 34% (836 statements, 548 não cobertos). | `tests/test_app.py` | Observação de qualidade | Os testes cobrem os controles de segurança (CSRF, cabeçalhos, upload, redirect). As rotas do jogo não têm testes. | [print 1](evidencias/05-testes-parte1.png), [print 2](evidencias/05-testes-parte2.png) |

### 3.4 Trivy fs (SCA)
| Achado | Onde | Classificação | Ação tomada | Resultado |
|---|---|---|---|---|
| 0 vulnerabilidades em `src/requirements.txt`; 0 misconfigurations no `Dockerfile` | Repositório | — | Nenhuma | `trivy-fs.txt` ([print](evidencias/06-trivy-fs.png)) |

### 3.5 Docker build + GHCR e Trivy image
Imagem publicada: `ghcr.io/thalia-ay/security-alert-devsecops:943cfdf32e33ed6a5f2298b2dabdce819623e173`, digest `sha256:d4f872f49981b890ba61c11225a74950ddaac711ba73966cc9aaa46c532a9a0d`. A assinatura com Cosign terminou com `success` ([print do pacote](evidencias/07-ghcr.png)).

| Achado | Onde | Classificação | Ação tomada | Resultado |
|---|---|---|---|---|
| 185 CVEs no SO base (UNKNOWN 8, LOW 61, MEDIUM 71, **HIGH 45**, CRITICAL 0) | Pacotes Debian 13.7 da imagem `python:3.12-slim` | **Risco aceito.** Nenhuma das HIGH tem correção publicada pelo Debian (status *affected* / *will_not_fix*). O Dockerfile já aplica `apt-get upgrade`. | Gate com `--ignore-unfixed`. As CVEs voltam a bloquear automaticamente quando surgir uma correção. Melhoria futura: avaliar uma base distroless. | `trivy-image.json` (filtrado): 0 HIGH/CRITICAL com correção ([print](evidencias/08-trivy-image.png)) |
| 0 CVEs nas bibliotecas Python da imagem | `site-packages` (flask, werkzeug, gunicorn…) | — | Nenhuma | `trivy-image.txt` |

### 3.6 OWASP ZAP (Baseline, informativo)
Resultado: `FAIL-NEW: 0  WARN-NEW: 9  PASS: 62`. São 0 alertas High e 3 Medium, conforme `report_json.json` ([print 1](evidencias/09-zap-parte1.png), [print 2](evidencias/09-zap-parte2.png)).

| Achado (risco ZAP) | Onde | Classificação | Ação tomada / justificativa | Resultado |
|---|---|---|---|---|
| 10055 CSP: `script-src 'unsafe-inline'` (**Medium**) | 5 URLs (`/`, `/login`, `/register`, `/about`) | **Risco aceito** (já previsto na seção de supressões) | Os templates do jogo usam muitos scripts inline. Correção planejada: mover para arquivos `.js` e usar nonce. | Permanece |
| 10055 CSP: `style-src 'unsafe-inline'` (**Medium**) | 5 URLs | **Risco aceito** | Estilos inline nos templates. Mesma correção planejada. | Permanece |
| 90003 Sub Resource Integrity Attribute Missing (**Medium**) | `<link>` para o Google Fonts | **Risco aceito** | O CSS do Google Fonts é gerado dinamicamente por navegador, então um hash SRI fixo quebraria o carregamento. Alternativa futura: hospedar a fonte localmente. | Permanece |
| 90004 Cross-Origin-Embedder-Policy ausente (Low) | 5 URLs | Hardening opcional | Não aplicado: COEP `require-corp` bloquearia as fontes de terceiros | Permanece |
| 90005 Sec-Fetch-* ausentes (Informational) | Requisições do próprio scanner | **Falso positivo** | São cabeçalhos que o *navegador* envia; o ZAP não os envia | — |
| 10094, 10027, 10049, 10111, 10112 (Informational) | Várias | Informativo | Identificação de login e sessão, comentários e cache. Sem impacto. | — |

O ZAP **não** reportou problemas de cookie (Secure/HttpOnly), anti-clickjacking, X-Content-Type-Options nem divulgação de versão. Isso confirma as correções da seção 1.

### 3.6.1 Etapa 8 – Aprovação + Produção (execução #1)
| Situação | Evidência | Pendência |
|---|---|---|
| O job terminou com sucesso, mas **não houve aprovação humana**. Na execução #1, o environment `producao` não tinha *Required reviewers* (a API de aprovações dessa execução retornou lista vazia), então o job rodou direto. | [print](evidencias/10-deploy-prod.png) | Configurar *Required reviewers* em `producao` e executar de novo |
| **Deploy real não executado** (`Deploy executado: false`, URL não configurada). O secret `RENDER_DEPLOY_HOOK_URL` não existe. | `relatorio-08-producao/deploy-producao.md` | Configurar o provedor de nuvem e o secret |

### 3.6.2 Etapa 8 – Pendências resolvidas (execuções #5 e #9)
| Item | Resultado | Evidência |
|---|---|---|
| Aprovação humana | Configurado *Required reviewers* = `analu-a` no environment `producao`. Na [#5](https://github.com/thalia-ay/security-alert-devsecops/actions/runs/41526012116) e na [#9](https://github.com/thalia-ay/security-alert-devsecops/actions/runs/41528928961), a API de aprovações retorna `analu-a – approved – producao`. Na #9, a etapa 7 terminou às 21:34:30 UTC e a etapa 8 só começou às 21:42:49 UTC, depois da aprovação. | API `GET /actions/runs/{id}/approvals`; tela *Review deployments* |
| Deploy real | Render (plano Free), serviço a partir da imagem do GHCR. O secret `RENDER_DEPLOY_HOOK_URL` e a variável `PRODUCTION_URL` estão no environment `producao`. Relatório da #9: `Deploy executado: true`, digest `sha256:7707654e…c393`, commit `d1ebd7c`. | `relatorio-08-producao/deploy-producao.md` (#9) |
| Aplicação em produção | O health check da esteira retornou "Produção respondendo". Em uma checagem independente, `GET /` e `GET /login` em https://security-alert-devsecops.onrender.com/ retornaram **200**, com título "Login - Security Alert" e os cabeçalhos CSP, HSTS, `X-Frame-Options: DENY`, `nosniff` e o cookie `Secure; HttpOnly`, servidos por gunicorn. | Saída do `curl` |

### 3.7 Execução bloqueada por quality gate (demonstração)
| Item | Valor |
|---|---|
| Branch de teste | `teste-quality-gate` (nunca mesclada na `main`) |
| Commit | `ee26e3e`: adiciona `src/config_teste.py` com a linha `PAYMENT_API_KEY = "..."`, um valor **fictício** de alta entropia que não pertence a nenhum serviço |
| Execução | [#8](https://github.com/thalia-ay/security-alert-devsecops/actions/runs/41527602124): **failure** |
| Etapa que bloqueou | 1 – Secrets (Gitleaks): `leaks found: 1`, exit code 1 |
| Achado (`gitleaks.json`) | `RuleID: generic-api-key`, `File: src/config_teste.py`, `StartLine: 3`, `Entropy: 5.09`, segredo exibido como `REDACTED` |
| Etapas 2 a 8 | `skipped`: nenhuma imagem foi publicada e nada foi para homologação ou produção |
| Resumo da Esteira | executou (`if: always()`) e registrou a falha |

**Efeito colateral observado (lição aprendida):** a execução #6 da `main` (commit `16db8eb`, que só alterava os RMs no README) também falhou na etapa 1, com o mesmo achado. O motivo foi este: com `fetch-depth: 0`, o checkout traz todas as branches, e `gitleaks git .` varre o histórico de **todas** as refs. Por isso a branch de teste, que existia naquele momento, contaminou a varredura da `main`. Esse comportamento é conservador: um segredo commitado em qualquer branch do repositório público já está exposto. A correção foi apagar a branch de teste depois de registrar a evidência. Em um segredo real, o procedimento seria revogar a credencial **antes** de qualquer limpeza.

**Correção:** a branch `teste-quality-gate` foi apagada, e a execução seguinte da `main`, a [#9](https://github.com/thalia-ay/security-alert-devsecops/actions/runs/41528928961) (commit `d1ebd7c`), passou na etapa 1 e em todas as demais.

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
6. **A esteira completa leva cerca de 5 minutos** (5m 9s na execução #1). As etapas mais lentas são o ZAP (~1m 22s) e o build da imagem. É um custo aceitável para rodar a cada push.
7. **Trivy fs × Trivy image mostram riscos diferentes.** O fs encontrou 0 vulnerabilidades nas dependências declaradas. A imagem trouxe 185 CVEs (45 HIGH), todas no sistema operacional base e nenhuma nas bibliotecas Python. Sem a etapa 6, esse risco ficaria invisível. Como nenhuma HIGH tem correção, o `--ignore-unfixed` evita um gate que não teria como ser atendido.
8. **O ZAP gerou os achados mais "discutíveis".** Dos 9 avisos, os Medium vêm de decisões de front-end (scripts inline, Google Fonts) e os Sec-Fetch-* são falso positivo por natureza. A ferramenta com mais falsos positivos nesta aplicação foi o ZAP, seguido pelo Semgrep (regra de CSRF do Django).
9. **Um job "verde" não prova que o controle funcionou.** A etapa 8 passou sem aprovação porque o environment não tinha revisores. Os controles de governança precisam ser conferidos na configuração, não só no status da execução.

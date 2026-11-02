# Esteira DevSecOps – detalhamento das etapas

Arquivo: [`.github/workflows/devsecops.yml`](../.github/workflows/devsecops.yml)

## Visão geral

- **Gatilhos:** `push` em qualquer branch, `pull_request` para `main` e `workflow_dispatch` (manual).
- **Sequencial:** cada job declara `needs` do anterior; se uma etapa falha, as seguintes não rodam.
- **Escopo por evento:**
  - `pull_request`: etapas 1 a 4 e o Resumo (não publica imagem a partir de PR).
  - `push` em branches que não são a `main`: etapas 1 a 7 e o Resumo. É o caminho usado para demonstrar uma execução bloqueada por quality gate.
  - `push` na `main`: etapas 1 a 8 e o Resumo.
- **Permissões mínimas:** `contents: read` no topo. Permissões extras só onde são necessárias:
  - `security-events: write` na etapa 2, para enviar o SARIF.
  - `packages: write` e `id-token: write` na etapa 5, para o push e a assinatura.
  - `packages: read` nas etapas 6 e 7.
- **Cadeia de suprimentos:**
  - Todas as actions estão fixadas pelo **SHA do commit**, com a tag em comentário.
  - As ferramentas usam versões fixas: Gitleaks 8.30.1 (com verificação de checksum), Semgrep 1.183.0 e Trivy v0.76.1.
- **Relatórios:** todo upload usa `actions/upload-artifact` com `if: always()`. Assim o relatório existe mesmo quando a etapa falha.

```
push → [1 Gitleaks] → [2 Semgrep] → [3 Build/Testes/Artefato] → [4 Trivy fs]
     → [5 Docker → GHCR] → [6 Trivy image] → [7 Homologação + ZAP]
     → ⏸ aprovação (environment producao) → [8 Deploy produção] → [★ Resumo]
```

---

## Etapa 1 – Verificação de secrets (Gitleaks)

| Item | Valor |
|------|-------|
| Job | `secrets-scan` |
| Ferramenta | Gitleaks 8.30.1. O binário oficial é baixado e conferido com `sha256sum -c`. |
| O que verifica | Tokens, chaves de API, senhas e chaves privadas em **todo o histórico Git**. O checkout usa `fetch-depth: 0`. |
| Comando | `gitleaks git . --redact --exit-code 1 --report-format json --report-path gitleaks.json` |
| Quality gate | **Bloqueia.** O `--exit-code 1` falha a etapa se qualquer segredo for encontrado. |
| Artifact | `relatorio-01-gitleaks` → `gitleaks.json`. Com `--redact`, o segredo não é reexposto no relatório. |

Supressões ficam só em `.gitleaksignore` ou no comentário inline `gitleaks:allow`. Cada uma tem justificativa em `observacoes.md`.

## Etapa 2 – SAST (Semgrep)

| Item | Valor |
|------|-------|
| Job | `sast` |
| Ferramenta | Semgrep 1.183.0, instalado via pip com versão fixa |
| Rulesets | `p/default`, `p/owasp-top-ten` e `p/python` (ruleset da linguagem) |
| O que verifica | Injeção (SQL/comando), XSS, uso inseguro de funções, criptografia fraca, configurações inseguras de Flask, Dockerfile e GitHub Actions |
| Quality gate | **Bloqueia** (`--error`) quando há achados |
| Artifact | `relatorio-02-semgrep` → `semgrep.json` e `semgrep.sarif` |
| Bônus | O SARIF é enviado para **Security → Code scanning** (`github/codeql-action/upload-sarif`) |

A única regra excluída é `python.django.security.django-no-csrf-token`, que é específica do Django. A justificativa está em `observacoes.md`.

## Etapa 3 – Build, dependências e artefato

| Item | Valor |
|------|-------|
| Job | `build` |
| Ferramentas | `pip` (com `--require-hashes`), `pipdeptree`, `pip-audit` e `pytest` com `pytest-cov` |
| Instalação determinística | `pip install --require-hashes -r src/requirements.txt`. O `requirements.txt` é um lock gerado por `pip-compile --generate-hashes`, com versões exatas e hash SHA-256. É o equivalente ao `npm ci` com `package-lock.json`. |
| Inventário | `arvore-dependencias.txt`, gerado pelo `pipdeptree` |
| Auditoria nativa | `pip-audit.json`, o equivalente ao `npm audit --json`. É **informativa**. |
| Testes | `pytest tests/` com cobertura. Gera `coverage.xml` e `pytest-junit.xml`. |
| Quality gate | **Bloqueia** se a instalação ou os testes falharem |
| Artifacts | `relatorio-03-build` (árvore, pip-audit, JUnit e cobertura) e `artefato-aplicacao-<SHA>` (`security-alert-<SHA>.tar.gz`) |

## Etapa 4 – SCA (Trivy fs)

| Item | Valor |
|------|-------|
| Job | `sca` |
| Ferramenta | `aquasecurity/trivy-action` com Trivy v0.76.1 |
| O que verifica | CVEs nas dependências (`src/requirements.txt`), misconfig (`Dockerfile`) e segredos (`scanners: vuln,misconfig,secret`) |
| Relatórios | `trivy-fs.txt`: tabela completa com todas as severidades. `trivy-fs.json`: JSON filtrado em HIGH e CRITICAL. |
| Quality gate | **Bloqueia** (`exit-code: 1`) se houver HIGH ou CRITICAL |
| Artifact | `relatorio-04-trivy-sca` |

O Trivy depende de arquivos de lock. Aqui o lock é o próprio `requirements.txt`, com versões exatas e hashes.

## Etapa 5 – Docker build e push (GHCR)

| Item | Valor |
|------|-------|
| Job | `docker-build` (não roda em `pull_request`) |
| Ferramentas | Docker Buildx, `docker/login-action` com `GITHUB_TOKEN`, `docker/build-push-action` |
| Imagem | `ghcr.io/<owner>/<repo>:<SHA do commit>`. O nome é convertido para minúsculas e a tag `latest` **não** é publicada. |
| Dockerfile | Detalhes abaixo da tabela |
| Quality gate | **Bloqueia** se o build ou o push falharem |
| Artifact | `relatorio-05-docker-build`: `docker-build.md` com imagem, digest, referência imutável e manifesto, mais `sbom.spdx.json` |
| Bônus | Assinatura keyless com **Cosign** e **SBOM** SPDX (anchore/sbom-action). Ambos usam `continue-on-error`, então não fazem parte do gate obrigatório. |

O Dockerfile segue estas práticas:
- Imagem base `python:3.12-slim`.
- Build multi-stage.
- `apt-get upgrade` para aplicar as correções do sistema base.
- `pip`, `setuptools` e `wheel` removidos da imagem final.
- Usuário não-root `appuser` (UID 10001).
- Código pertencente ao root, somente leitura para o app.
- `HEALTHCHECK` configurado.
- Nenhum segredo em `ENV` ou `ARG`.

## Etapa 6 – Scan da imagem (Trivy image)

| Item | Valor |
|------|-------|
| Job | `image-scan` |
| Alvo | A imagem publicada na etapa 5, pelo **digest** (`image@sha256:...`) |
| Credenciais | `TRIVY_USERNAME` e `TRIVY_PASSWORD`, passados como variáveis de ambiente, nunca na linha de comando |
| Relatórios | `trivy-image.txt`: tabela completa. `trivy-image.json`: HIGH e CRITICAL com correção disponível (`ignore-unfixed`). |
| Quality gate | **Bloqueia** (`exit-code: 1`) se houver HIGH ou CRITICAL que já tenham correção |
| Artifact | `relatorio-06-trivy-image` |

**Diferença em relação à etapa 4:**
- A etapa 4 olha as **dependências da aplicação** (pacotes Python declarados) e a configuração do repositório.
- A etapa 6 olha a **imagem final**: pacotes do sistema operacional Debian da imagem base (libc, openssl etc.), o interpretador Python e as bibliotecas instaladas.
- Uma imagem pode estar limpa na etapa 4 e ainda assim falhar na 6 por causa da imagem base.

## Etapa 7 – Homologação e DAST (OWASP ZAP)

| Item | Valor |
|------|-------|
| Job | `dast-staging`, no environment `homologacao` |
| Deploy de homologação | O container da **mesma imagem (digest)** sobe no próprio runner (`localhost:5000`). Um health check aguarda a resposta de `/login`. |
| Ferramenta | `zaproxy/action-baseline` v0.15.0 com `-a` (inclui regras alfa passivas) |
| O que verifica | Cabeçalhos de segurança, flags de cookie, exposição de informações, CSP e outros problemas visíveis só em tempo de execução |
| Quality gate | **Informativo** (`fail_action: false`). A decisão é da pessoa aprovadora na etapa 8. |
| Artifact | `relatorio-07-homologacao-zap` → `report_html.html`, `report_json.json` e `report_md.md`. Também `homologacao-logs`, com os logs do container. |

O ZAP só é executado contra o ambiente do próprio grupo, um container efêmero no runner.

## Etapa 8 – Aprovação humana e produção

| Item | Valor |
|------|-------|
| Job | `deploy-prod`, no environment `producao`. Roda só em `push` na `main`. |
| Aprovação | O environment `producao` precisa ter **Required reviewers**. O job fica em espera até a aprovação, e a rejeição interrompe o deploy. |
| Deploy | Dispara o **Deploy Hook do Render** com `imgURL=<imagem@digest>`, ou seja, a imagem pelo SHA. Depois faz um smoke test em `PRODUCTION_URL/login`. |
| Credenciais | O secret `RENDER_DEPLOY_HOOK_URL` fica nos **Environment secrets** de `producao`. A variável `PRODUCTION_URL` fica nas Environment variables. |
| Sem configuração | Se o secret não existir, o job registra um aviso e o relatório informa **"Deploy executado: false"**. Nada é simulado. |
| Artifact | `relatorio-08-producao` → `deploy-producao.md`, com imagem, responsável, data, commit, URL e link da execução |

## Resumo da Esteira

| Item | Valor |
|------|-------|
| Job | `pipeline-summary`. Depende de todas as etapas e roda com `if: always()`. |
| Como funciona | Baixa os artifacts `relatorio-*`, extrai as contagens com **jq** e publica uma tabela em `$GITHUB_STEP_SUMMARY` |
| Artifact | `resumo-da-esteira` → `resumo-esteira.md` |

Como o Resumo depende da etapa 8, na `main` ele só é gerado depois da aprovação ou rejeição do deploy. A equipe optou por não criar um resumo parcial: os relatórios de cada etapa já ficam disponíveis como artifacts para o revisor antes da aprovação.

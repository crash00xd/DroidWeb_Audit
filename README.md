# DroidWeb Audit

Ferramenta de **análise estática de APKs Android**, desenvolvida em Python, com foco em indicadores de segurança relacionados ao uso de `WebView`.

O DroidWeb Audit analisa o manifesto e referências presentes no bytecode DEX. Ele **não instala nem executa o aplicativo**, não realiza exploração e não confirma vulnerabilidades. Os resultados são indicadores para triagem e devem ser validados manualmente.

> **Uso autorizado:** utilize somente APKs que você tenha autorização para analisar. APKs são arquivos não confiáveis; execute o scanner em ambiente isolado quando trabalhar com amostras desconhecidas.

## Recursos

- Leitura de metadados do APK e SHA-256.
- Coleta de informações do manifesto:
  - pacote, nome e versão;
  - SDK mínimo e alvo;
  - permissões;
  - atividades, serviços, receivers e providers;
  - componentes e atributo `exported`;
  - `debuggable`, `allowBackup`, `usesCleartextTraffic` e `networkSecurityConfig`.
- Busca de referências a APIs relevantes de WebView e captura de XREFs (classe, método, descritor e offset, quando disponíveis).
- Busca de strings relacionadas a `WebView`, `file://` e `javascript:`, com referências quando disponíveis.
- Achados com identificador de regra, severidade heurística, confiança, justificativa e orientação de validação manual.
- Relatório em texto ou JSON versionado.
- Limite configurável de tamanho do APK.
- Códigos de saída documentados e erros operacionais enviados para `stderr`.

## Requisitos

- Python 3.10 ou superior.
- Androguard 4.1.x.

A implementação foi direcionada à API 4.x do Androguard. A API 3.x possui diferenças relevantes e não faz parte da faixa suportada/testada.

## Instalação

```bash
git clone https://github.com/SEU-USUARIO/droidweb-audit.git
cd droidweb-audit

python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Uso

### Relatório no terminal

```bash
python droidweb_audit.py ./aplicativo.apk
```

### Relatório JSON

```bash
python droidweb_audit.py ./aplicativo.apk --json
```

### Salvar relatório em arquivo

```bash
python droidweb_audit.py ./aplicativo.apk --out ./reports/analise.txt
python droidweb_audit.py ./aplicativo.apk --json --out ./reports/analise.json
```

Quando `--out` é informado, o relatório também é impresso no terminal. Arquivos existentes no caminho de saída são sobrescritos.

### Limitar tamanho máximo do APK

O limite padrão é 512 MiB:

```bash
python droidweb_audit.py ./aplicativo.apk --max-apk-size-mb 256
```

### Diagnóstico

```bash
python droidweb_audit.py ./aplicativo.apk --verbose
```

## Regras atuais

### Referências a métodos

| Regra | Indicador | Nível heurístico |
|---|---|---|
| `WV-API-001` | `WebView.addJavascriptInterface` | HIGH |
| `WV-API-002` | `WebView.setWebContentsDebuggingEnabled` | MEDIUM |
| `WV-API-003` | `WebView.evaluateJavascript` | MEDIUM |
| `WV-API-004` | `WebView.loadUrl` | INFO |
| `WV-API-005` | `WebViewClient.shouldOverrideUrlLoading` | INFO |
| `WV-API-006` | `WebSettings.setJavaScriptEnabled` | MEDIUM |
| `WV-API-007` | `WebSettings.setAllowFileAccess` | MEDIUM |
| `WV-API-008` | `WebSettings.setAllowFileAccessFromFileURLs` | HIGH |
| `WV-API-009` | `WebSettings.setAllowUniversalAccessFromFileURLs` | HIGH |
| `WV-API-010` | `WebSettings.setMixedContentMode` | MEDIUM |

Os níveis acima são **prioridades heurísticas de revisão**, não severidades CVSS. A presença de uma chamada não revela necessariamente o argumento passado nem o estado efetivo da configuração.

### Busca por strings

| Regra | Padrão procurado | Nível heurístico |
|---|---|---|
| `WV-STR-001` | `javascript:` | MEDIUM |
| `WV-STR-002` | `file://` | MEDIUM |
| `WV-STR-003` | `setAllowUniversalAccessFromFileURLs` | HIGH |
| `WV-STR-004` | `setAllowFileAccessFromFileURLs` | HIGH |
| `WV-STR-005` | `setAllowFileAccess` | MEDIUM |
| `WV-STR-006` | `android.webkit` | INFO |

Strings podem estar presentes sem serem utilizadas em um fluxo executável. Strings e referências ausentes também não demonstram que o comportamento esteja ausente.

## Formato JSON

O objeto raiz possui:

- `metadata`: ferramenta, versão, timestamp UTC, arquivo, tamanho, SHA-256 e versão do Androguard;
- `manifest`: dados extraídos do manifesto;
- `findings`: lista de indicadores;
- `risk_summary`: contagem por nível e maior nível encontrado;
- `errors`: erros parciais de coleta/análise.

Cada item de `findings` inclui `finding_id`, `rule_id`, `title`, `category`, `severity`, `confidence`, `evidence_type`, `evidence`, `rationale`, `manual_validation` e `status`.

`schema_version` identifica a versão do contrato JSON. Mudanças incompatíveis no formato devem incrementar essa versão.

## Códigos de saída

| Código | Significado |
|---|---|
| `0` | Análise concluída, com ou sem indicadores |
| `2` | Falha de análise ou dependência indisponível |
| `2` | Entrada inválida (o `argparse` encerra com erro) |
| `3` | Falha ao gravar o relatório |

A presença de achados não altera o código de saída: o scanner é uma ferramenta de triagem, não um verificador binário de segurança.

## Testes

Os testes unitários das regras auxiliares podem ser executados com:

```bash
python -m unittest discover -s tests -v
```

A validação de integração deve ser feita com APKs de laboratório construídos especificamente para conter casos positivos, negativos e ambíguos. Não use aplicativos de terceiros como fixtures sem autorização.

## Limitações técnicas

- Análise estática: nenhum código do APK é executado.
- Não realiza análise de fluxo de dados (*taint analysis*) nem determina se entradas controladas pelo usuário chegam a um sink.
- Não avalia o valor efetivo de argumentos de chamadas, salvo quando isso puder ser inferido por análise manual adicional.
- Pode não identificar chamadas indiretas, wrappers, reflexão, JNI, código baixado em tempo de execução, DEX carregado dinamicamente ou código fortemente ofuscado.
- XREFs do Androguard podem ser incompletas ou conter imprecisões; offsets são relativos ao método chamador.
- A coleta de atributos do manifesto depende da decodificação realizada pelo Androguard.
- `exported` pode estar ausente no manifesto; nesse caso o scanner retorna `null`, sem inferir o comportamento efetivo a partir de regras específicas de versão do Android.
- A ausência de indicadores não significa que o APK seja seguro.

## Segurança operacional

O scanner processa arquivos APK não confiáveis. Para amostras suspeitas:

1. Execute em VM ou container descartável e atualizado.
2. Não execute o aplicativo analisado no mesmo ambiente do scanner.
3. Limite CPU, memória, tempo de execução e tamanho dos arquivos no ambiente de execução.
4. Evite executar como administrador/root.
5. Mantenha Androguard e dependências atualizados.
6. Não publique relatórios sem revisar caminhos locais, nomes de pacotes e strings que possam conter dados sensíveis.

O limite de tamanho da CLI reduz entradas excessivamente grandes, mas **não é uma sandbox nem protege sozinho contra arquivos maliciosos ou consumo excessivo de recursos**.

## Estrutura do projeto

```text
droidweb-audit/
├── droidweb_audit.py
├── requirements.txt
├── README.md
└── tests/
    └── test_rules.py
```

## Roadmap sugerido

- Análise de `network_security_config` referenciado pelo manifesto.
- Detecção de configurações de WebView com inferência de argumentos constantes.
- Inspeção de `usesCleartextTraffic`, `debuggable` e `allowBackup` com regras dedicadas.
- Exportação SARIF e HTML.
- Análise de fluxo de dados para fontes e sinks selecionados.
- Fixtures APK de laboratório e testes de integração automatizados.
- Perfis de regras configuráveis e allowlist por projeto.

## Referências

- [Androguard - documentação](https://androguard.github.io/androguard/)
- [Androguard - PyPI](https://pypi.org/project/androguard/)
- [Android Developers - WebView](https://developer.android.com/develop/ui/views/layout/webapps/webview)
- [Android Developers - WebView security](https://developer.android.com/privacy-and-security/risks/webview-unsafe-file-inclusion)

## Licença

Defina a licença do repositório antes de publicar. Se optar por MIT, adicione o arquivo `LICENSE` com o texto oficial da licença e os dados corretos do titular.

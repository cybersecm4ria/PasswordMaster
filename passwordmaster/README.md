# PasswordGuard

Checador de senhas para quem não tem conhecimento de segurança — verifica se uma senha já vazou publicamente e avalia sua força real, com explicações em linguagem simples.

## Como funciona

### 1. Checagem de vazamento
Usa a API pública **[Have I Been Pwned – Pwned Passwords](https://haveibeenpwned.com/Passwords)**, que aplica a técnica de **k-anonymity**: apenas os 5 primeiros caracteres do hash SHA-1 da senha são enviados à API. A senha completa **nunca sai da sua máquina**, nem em texto puro nem em hash completo.

Se não houver conexão com a internet (ou a API estiver fora do ar), a ferramenta cai automaticamente para uma checagem **offline**, comparando contra uma lista local de senhas comuns/vazadas conhecidas (`senhas_comuns.txt`).

### 2. Checagem de força
Baseada nas diretrizes do **NIST 800-63B** (guia atual de referência sobre senhas), que prioriza:
- Tamanho da senha acima de complexidade forçada
- Ausência de sequências previsíveis (`1234`, `qwerty`, `abcd`)
- Ausência de repetição excessiva de caracteres
- Variedade real de tipos de caractere
- Estimativa de entropia (imprevisibilidade estatística)

## Instalação

```bash
git clone <link-do-seu-repositorio>
cd passwordguard
pip install -r requirements.txt
```

## Uso

```bash
# vai pedir a senha de forma oculta (não aparece na tela)
python passwordguard.py

# passar a senha direto (menos seguro, fica no histórico do terminal)
python passwordguard.py --senha "MinhaSenha123"

# forçar modo 100% offline, sem consultar a internet
python passwordguard.py --offline
```

## Privacidade

- A senha nunca é salva em arquivo, log ou enviada para qualquer lugar além da consulta de hash parcial à API HIBP (que é padrão de mercado, usada por navegadores como Firefox e serviços como 1Password).
- O modo `--offline` garante que nenhum dado sai da sua máquina.

## Limitações conhecidas

- A lista local (`senhas_comuns.txt`) é uma amostra curada de senhas extremamente comuns, não substitui a cobertura completa da API online.
- A estimativa de entropia é simplificada (baseada no espaço de caracteres), não é uma análise criptográfica completa.
- A detecção de "palavra de dicionário" não está implementada nesta versão — fica no roadmap.

## Roadmap

- [ ] Detecção de palavras de dicionário (PT-BR e EN)
- [ ] Modo web (formulário simples em HTML) para pessoas não técnicas
- [ ] Gerador de senhas fortes integrado
- [ ] Exportar relatório em HTML

#!/usr/bin/env python3
"""
Password Master - Checador de senhas para quem não tem conhecimento
de segurança, com output traduzido em linguagem simples.

Verifica:
  1. Se a senha já vazou em bancos de dados públicos conhecidos
     (online via API Have I Been Pwned, com fallback offline)
  2. A força real da senha, baseado nas diretrizes NIST 800-63B

IMPORTANTE SOBRE PRIVACIDADE:
A senha completa NUNCA sai da sua máquina. A checagem online usa
k-anonymity: só os 5 primeiros caracteres do hash SHA-1 da senha
são enviados à API. A senha em si nunca trafega pela rede.

Uso:
    python passwordguard.py
    python passwordguard.py --senha "MinhaSenha123"
    python passwordguard.py --offline
"""

import argparse
import getpass
import hashlib
import os
import re
import sys
import requests
import pyfiglet

CAMINHO_LISTA_LOCAL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "senhas_comuns.txt"
)


# ---------- Cores no terminal ----------
class Cor:
    ALTO = '\033[91m'
    MEDIO = '\033[93m'
    BAIXO = '\033[94m'
    OK = '\033[92m'
    RESET = '\033[0m'
    NEGRITO = '\033[1m'


# ---------- Checagem de vazamento ----------
def checar_vazamento_online(senha, timeout=5):
    """
    Consulta a API Have I Been Pwned usando k-anonymity.
    Retorna (vazada: bool, quantidade: int) ou (None, None) se falhar.
    """
    sha1 = hashlib.sha1(senha.encode("utf-8")).hexdigest().upper()
    prefixo, sufixo = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefixo}",
            timeout=timeout,
            headers={"Add-Padding": "true"},
        )
        resp.raise_for_status()
    except requests.RequestException:
        return None, None

    for linha in resp.text.splitlines():
        suf, contagem = linha.split(":")
        if suf == sufixo:
            return True, int(contagem)

    return False, 0


def checar_vazamento_offline(senha):
    """Confere a senha contra a lista local de senhas comuns/vazadas."""
    if not os.path.exists(CAMINHO_LISTA_LOCAL):
        return None

    senha_lower = senha.lower()
    with open(CAMINHO_LISTA_LOCAL, "r", encoding="utf-8") as f:
        for linha in f:
            if linha.strip().lower() == senha_lower:
                return True
    return False


# ---------- Checagem de força (baseado em NIST 800-63B) ----------
SEQUENCIAS_TECLADO = [
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx",
    "123456", "654321", "abcdef",
]


def _tem_sequencia_numerica_ou_alfabetica(senha, tamanho_min=4):
    """Detecta sequências como '1234', 'abcd', '4321', 'dcba'."""
    s = senha.lower()
    for i in range(len(s) - tamanho_min + 1):
        trecho = s[i:i + tamanho_min]
        if trecho.isdigit() or trecho.isalpha():
            codigos = [ord(c) for c in trecho]
            crescente = all(codigos[j + 1] - codigos[j] == 1 for j in range(len(codigos) - 1))
            decrescente = all(codigos[j] - codigos[j + 1] == 1 for j in range(len(codigos) - 1))
            if crescente or decrescente:
                return True
    return False


def _tem_repeticao_excessiva(senha, limite=3):
    """Detecta caracteres repetidos em sequência, tipo 'aaaa' ou '1111'."""
    contagem = 1
    for i in range(1, len(senha)):
        if senha[i] == senha[i - 1]:
            contagem += 1
            if contagem >= limite:
                return True
        else:
            contagem = 1
    return False


def _substituicoes_obvias_removidas(senha):
    """Reverte substituições comuns (leet speak) pra detectar palavra base."""
    mapa = {
        "0": "o", "1": "i", "3": "e", "4": "a",
        "5": "s", "7": "t", "@": "a", "$": "s",
    }
    resultado = senha.lower()
    for k, v in mapa.items():
        resultado = resultado.replace(k, v)
    return resultado


def calcular_entropia_bits(senha):
    """Estimativa simples de entropia baseada no espaço de caracteres usado."""
    espacos = 0
    if re.search(r"[a-z]", senha):
        espacos += 26
    if re.search(r"[A-Z]", senha):
        espacos += 26
    if re.search(r"[0-9]", senha):
        espacos += 10
    if re.search(r"[^a-zA-Z0-9]", senha):
        espacos += 32

    if espacos == 0:
        return 0

    import math
    return len(senha) * math.log2(espacos)


def checar_forca(senha):
    """
    Analisa a força da senha e retorna uma lista de problemas encontrados,
    cada um com explicação e recomendação, mais uma nota final.
    """
    problemas = []

    # Comprimento (NIST prioriza tamanho sobre complexidade forçada)
    if len(senha) < 8:
        problemas.append({
            "titulo": "Senha muito curta",
            "explicacao": f"Sua senha tem {len(senha)} caracteres. Segundo as diretrizes "
                           "atuais de segurança (NIST 800-63B), o tamanho é o fator mais "
                           "importante para dificultar tentativas automatizadas de adivinhação.",
            "risco": "ALTO",
            "recomendacao": "Use pelo menos 12 caracteres. Uma frase longa e fácil de "
                             "lembrar é mais segura que uma senha curta e complexa."
        })
    elif len(senha) < 12:
        problemas.append({
            "titulo": "Senha com tamanho abaixo do recomendado",
            "explicacao": f"Sua senha tem {len(senha)} caracteres. O recomendado atualmente "
                           "é 12 ou mais.",
            "risco": "MEDIO",
            "recomendacao": "Aumente para 12+ caracteres. Considere usar uma frase "
                             "(ex: 'CachorroAzulComeuOQueijo42')."
        })

    # Sequência de teclado ou alfabética/numérica
    senha_lower = senha.lower()
    if any(seq in senha_lower for seq in SEQUENCIAS_TECLADO) or \
       _tem_sequencia_numerica_ou_alfabetica(senha):
        problemas.append({
            "titulo": "Contém sequência previsível",
            "explicacao": "Sua senha tem uma sequência de teclado ou de caracteres "
                           "(tipo '1234', 'abcd', 'qwerty'). Esse é um dos primeiros "
                           "padrões que ferramentas de quebra de senha tentam.",
            "risco": "ALTO",
            "recomendacao": "Evite sequências óbvias. Prefira combinações sem padrão "
                             "lógico visível."
        })

    # Repetição excessiva
    if _tem_repeticao_excessiva(senha):
        problemas.append({
            "titulo": "Contém caracteres repetidos em excesso",
            "explicacao": "Sua senha tem o mesmo caractere repetido várias vezes seguidas "
                           "(tipo 'aaaa' ou '1111'), o que reduz bastante a imprevisibilidade.",
            "risco": "MEDIO",
            "recomendacao": "Evite repetir o mesmo caractere mais de duas vezes seguidas."
        })

    # Diversidade de tipos de caractere
    tem_minuscula = bool(re.search(r"[a-z]", senha))
    tem_maiuscula = bool(re.search(r"[A-Z]", senha))
    tem_numero = bool(re.search(r"[0-9]", senha))
    tem_simbolo = bool(re.search(r"[^a-zA-Z0-9]", senha))
    variedade = sum([tem_minuscula, tem_maiuscula, tem_numero, tem_simbolo])

    if variedade <= 1:
        problemas.append({
            "titulo": "Usa só um tipo de caractere",
            "explicacao": "Sua senha usa apenas um tipo de caractere (só letras minúsculas, "
                           "por exemplo). Misturar tipos aumenta bastante o espaço de "
                           "possibilidades que um atacante precisa tentar.",
            "risco": "ALTO",
            "recomendacao": "Combine letras maiúsculas, minúsculas, números e símbolos."
        })
    elif variedade == 2:
        problemas.append({
            "titulo": "Pouca variedade de caracteres",
            "explicacao": "Sua senha usa só 2 tipos de caractere diferentes.",
            "risco": "BAIXO",
            "recomendacao": "Se possível, inclua mais um tipo (símbolo ou número, por exemplo)."
        })

    # Entropia estimada
    entropia = calcular_entropia_bits(senha)
    if entropia < 40:
        problemas.append({
            "titulo": "Baixa imprevisibilidade estatística (entropia)",
            "explicacao": f"A estimativa de entropia da sua senha é de aproximadamente "
                           f"{entropia:.0f} bits. Como referência, especialistas consideram "
                           "confortável a partir de 60 bits para uso geral.",
            "risco": "MEDIO",
            "recomendacao": "Aumente o tamanho e a variedade de caracteres para elevar "
                             "a entropia."
        })

    return problemas, entropia


def imprimir_banner():
    """Exibe o banner ASCII de abertura, no estilo de ferramentas como Nmap/SQLMap."""
    arte = pyfiglet.figlet_format("PASSWORD MASTER", font="slant")
    print(f"{Cor.BAIXO}{arte}{Cor.RESET}", end="")
    print(f"{Cor.NEGRITO}  v1.0  |  Checador de senhas para todo mundo{Cor.RESET}")
    print(f"  Sua senha nunca sai da sua máquina em texto puro.\n")


# ---------- Relatório ----------
def imprimir_relatorio(vazamento_status, quantidade_vazamentos, fonte_vazamento,
                        problemas_forca, entropia):
    print()
    print(f"{Cor.NEGRITO}{'=' * 60}{Cor.RESET}")
    print(f"{Cor.NEGRITO}  RELATÓRIO DA SENHA{Cor.RESET}")
    print(f"{Cor.NEGRITO}{'=' * 60}{Cor.RESET}\n")

    # Vazamento
    if vazamento_status is None:
        print(f"{Cor.MEDIO}[AVISO] Não foi possível checar vazamento ({fonte_vazamento}).{Cor.RESET}\n")
    elif vazamento_status:
        if quantidade_vazamentos:
            print(f"{Cor.ALTO}{Cor.NEGRITO}[ALTO] Essa senha JÁ APARECEU em vazamentos públicos "
                  f"({fonte_vazamento}).{Cor.RESET}")
            print(f"  Foi vista {quantidade_vazamentos:,} vez(es) em bancos de dados de vazamentos conhecidos.")
        else:
            print(f"{Cor.ALTO}{Cor.NEGRITO}[ALTO] Essa senha está numa lista de senhas comuns/vazadas "
                  f"({fonte_vazamento}).{Cor.RESET}")
        print("  Isso significa que essa senha é uma das primeiras que um atacante tenta,")
        print("  independente de quão 'complexa' ela pareça visualmente.")
        print(f"  {Cor.NEGRITO}Recomendação: troque essa senha imediatamente, em todos os lugares onde ela é usada.{Cor.RESET}\n")
    else:
        print(f"{Cor.OK}[OK] Essa senha não foi encontrada em vazamentos conhecidos "
              f"({fonte_vazamento}).{Cor.RESET}\n")

    # Força
    if not problemas_forca:
        print(f"{Cor.OK}[OK] Nenhum problema estrutural encontrado na força da senha.{Cor.RESET}")
    else:
        cores_risco = {"ALTO": Cor.ALTO, "MEDIO": Cor.MEDIO, "BAIXO": Cor.BAIXO}
        ordem_risco = {"ALTO": 0, "MEDIO": 1, "BAIXO": 2}
        for problema in sorted(problemas_forca, key=lambda p: ordem_risco[p["risco"]]):
            cor = cores_risco[problema["risco"]]
            print(f"{cor}{Cor.NEGRITO}[{problema['risco']}] {problema['titulo']}{Cor.RESET}")
            print(f"  O que é: {problema['explicacao']}")
            print(f"  Recomendação: {problema['recomendacao']}\n")

    print(f"{Cor.NEGRITO}{'-' * 60}{Cor.RESET}")
    print(f"Entropia estimada: {entropia:.0f} bits")

    total_alto = sum(1 for p in problemas_forca if p["risco"] == "ALTO")
    if vazamento_status:
        total_alto += 1

    if total_alto > 0:
        classificacao = f"{Cor.ALTO}FRACA{Cor.RESET}"
    elif len(problemas_forca) > 0:
        classificacao = f"{Cor.MEDIO}RAZOÁVEL{Cor.RESET}"
    else:
        classificacao = f"{Cor.OK}FORTE{Cor.RESET}"

    print(f"Classificação geral: {classificacao}")
    print(f"{Cor.NEGRITO}{'-' * 60}{Cor.RESET}")


def rodar_checagem(senha, usar_offline):
    """Executa uma checagem completa para uma senha e imprime o relatório."""
    if not senha:
        print("Nenhuma senha informada.\n")
        return

    vazamento_status = None
    quantidade = None
    fonte = ""

    if not usar_offline:
        vazamento_status, quantidade = checar_vazamento_online(senha)
        fonte = "API Have I Been Pwned"

    if vazamento_status is None:
        vazamento_status = checar_vazamento_offline(senha)
        fonte = "lista local de senhas comuns"

    problemas_forca, entropia = checar_forca(senha)

    imprimir_relatorio(vazamento_status, quantidade, fonte, problemas_forca, entropia)


def main():
    parser = argparse.ArgumentParser(
        description="Password Master - checador de senhas para iniciantes em segurança"
    )
    parser.add_argument(
        "--senha",
        help="senha a ser checada na primeira rodada (se não informado, será pedida de forma oculta)"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="não consultar a internet, usar só a lista local"
    )
    args = parser.parse_args()

    imprimir_banner()

    # Primeira rodada pode vir de --senha (linha de comando); as seguintes sempre pedem interativamente
    senha = args.senha

    while True:
        if not senha:
            senha = getpass.getpass("Digite a senha a ser checada (não vai aparecer na tela): ")

        rodar_checagem(senha, args.offline)

        print()
        continuar = input("Checar outra senha? (s/n): ").strip().lower()
        print()

        if continuar not in ("s", "sim", "y", "yes"):
            print("Até a próxima!")
            break

        senha = None  # força pedir de novo na próxima volta


if __name__ == "__main__":
    main()

#by MariaDB
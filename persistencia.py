import json
import os
from enums import TipoAtivo, Severidade, StatusTratamento
from modelos import Equipamento, Notebook, Servidor, Roteador, EstacaoTrabalho, Vulnerabilidade

ARQUIVO_INVENTARIO = "inventario_ativos.json"
ARQUIVO_DEPENDENCIAS = "dependencias_rede.json"

def instanciar_equipamento(dados: dict) -> Equipamento:
    """Factory function que instancia a subclasse correta baseada no tipo do ativo."""
    tipo_cod = dados.get("tipo_codigo")
    id_ativo = dados.get("id")
    hostname = dados.get("hostname")
    responsavel = dados.get("responsavel")
    localizacao = dados.get("localizacao")

    if tipo_cod == TipoAtivo.NOTEBOOK.value:
        equip = Notebook(id_ativo, hostname, responsavel, localizacao)
    elif tipo_cod == TipoAtivo.SERVIDOR.value:
        equip = Servidor(id_ativo, hostname, responsavel, localizacao)
    elif tipo_cod == TipoAtivo.ROTEADOR.value:
        equip = Roteador(id_ativo, hostname, responsavel, localizacao)
    elif tipo_cod == TipoAtivo.ESTACAO_TRABALHO.value:
        equip = EstacaoTrabalho(id_ativo, hostname, responsavel, localizacao)
    else:
        equip = Equipamento(id_ativo, hostname, responsavel, localizacao, TipoAtivo(tipo_cod))

    for v_dado in dados.get("vulnerabilidades", []):
        vuln = Vulnerabilidade(
            cve=v_dado["cve"],
            descricao=v_dado["descricao"],
            categoria=v_dado["categoria"],
            severidade=Severidade(v_dado["severidade"]),
            status=StatusTratamento(v_dado["status"]),
            cvss=v_dado.get("cvss")
        )
        equip.adicionar_vulnerabilidade(vuln)

    return equip


def salvar_inventario(ativos: list[Equipamento], caminho: str = ARQUIVO_INVENTARIO) -> bool:
    """Grava os ativos como um array de objetos JSON conforme Requisito 2."""
    try:
        dados_serializados = [ativo.to_dict() for ativo in ativos]
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump(dados_serializados, arquivo, indent=4, ensure_ascii=False)
        return True
    except IOError as erro:
        print(f"Erro ao salvar arquivo de inventario: {erro}")
        return False


def carregar_inventario(caminho: str = ARQUIVO_INVENTARIO) -> list[Equipamento]:
    """Le o array JSON e reconstrói as instancias de Equipamento na memoria."""
    if not os.path.exists(caminho):
        return []

    try:
        with open(caminho, "r", encoding="utf-8") as arquivo:
            conteudo = arquivo.read().strip()
            if not conteudo:
                return []
            dados_brutos = json.loads(conteudo)

            if isinstance(dados_brutos, list):
                return [instanciar_equipamento(item) for item in dados_brutos]
            return []
    except (json.JSONDecodeError, IOError) as erro:
        print(f"Aviso: Erro ao carregar inventario ({erro}). Iniciando base vazia.")
        return []


def salvar_dependencias(matriz_dep: list[list[float]], caminho: str = ARQUIVO_DEPENDENCIAS) -> bool:
    """Persiste a matriz de dependencias no formato JSON exigido na Secao 2."""
    try:
        with open(caminho, "w", encoding="utf-8") as arquivo:
            json.dump(matriz_dep, arquivo, indent=4)
        return True
    except IOError as erro:
        print(f"Erro ao salvar matriz de dependencias: {erro}")
        return False


def carregar_dependencias(caminho: str = ARQUIVO_DEPENDENCIAS) -> list[list[float]]:
    """Carrega a matriz de dependencias persistida em JSON."""
    if not os.path.exists(caminho):
        return []

    try:
        with open(caminho, "r", encoding="utf-8") as arquivo:
            conteudo = arquivo.read().strip()
            if not conteudo:
                return []
            return json.loads(conteudo)
    except (json.JSONDecodeError, IOError):
        return []
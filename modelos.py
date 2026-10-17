from enums import TipoAtivo, Severidade, StatusTratamento

class Vulnerabilidade:
    """Representa uma fragilidade de seguranca associada a um ativo de TI."""

    def __init__(
        self,
        cve: str,
        descricao: str,
        categoria: str,
        severidade: Severidade,
        status: StatusTratamento = StatusTratamento.ABERTA,
        cvss: float = None,
    ):
        self.cve = cve
        self.descricao = descricao
        self.categoria = categoria
        self.severidade = severidade
        self.status = status

        # Mapeamento deterministico de CVSS v3 baseado na mediana de cada faixa oficial
        scores_padrao = {
            Severidade.BAIXA: 2.0,
            Severidade.MEDIA: 5.5,
            Severidade.ALTA: 8.0,
            Severidade.CRITICA: 9.5,
        }
        self.cvss = cvss if cvss is not None else scores_padrao.get(severidade, 5.0)

    def atualizar_status(self, novo_status: StatusTratamento):
        """Regra de negocio: status Corrigida e terminal e nao pode ser alterado."""
        if self.status == StatusTratamento.CORRIGIDA:
            return False, "Vulnerabilidade ja corrigida. Status consolidado."
        self.status = novo_status
        return True, f"Status atualizado para {novo_status.value}."

    def to_dict(self):
        """Serializacao em dicionario para persistencia em JSON."""
        return {
            "cve": self.cve,
            "descricao": self.descricao,
            "categoria": self.categoria,
            "severidade": self.severidade.value,
            "status": self.status.value,
            "cvss": self.cvss,
        }


class Equipamento:
    """Classe base que representa um ativo de TI generico no inventario."""

    def __init__(
        self,
        id_ativo: int,
        hostname: str,
        responsavel: str,
        localizacao: str,
        tipo: TipoAtivo,
    ):
        self.id_ativo = id_ativo
        self.hostname = hostname
        self.responsavel = responsavel
        self.localizacao = localizacao
        self.tipo = tipo
        self.vulnerabilidades: list[Vulnerabilidade] = []

    def adicionar_vulnerabilidade(self, vulnerabilidade: Vulnerabilidade):
        self.vulnerabilidades.append(vulnerabilidade)

    def fator_exposicao(self) -> float:
        """Metodo polimorfico base para ponderacao de risco no modelo linear."""
        return 0.10

    def to_dict(self):
        """Serializacao compativel com o array JSON exigido no Requisito 2."""
        return {
            "id": self.id_ativo,
            "hostname": self.hostname,
            "responsavel": self.responsavel,
            "localizacao": self.localizacao,
            "tipo": self.tipo.name,
            "tipo_codigo": self.tipo.value,
            "vulnerabilidades": [v.to_dict() for v in self.vulnerabilidades],
        }


class Notebook(Equipamento):
    def __init__(self, id_ativo: int, hostname: str, responsavel: str, localizacao: str):
        super().__init__(id_ativo, hostname, responsavel, localizacao, TipoAtivo.NOTEBOOK)

    def fator_exposicao(self) -> float:
        return 0.05  # Dispositivo de borda: exposicao lateral contida


class Servidor(Equipamento):
    def __init__(self, id_ativo: int, hostname: str, responsavel: str, localizacao: str):
        super().__init__(id_ativo, hostname, responsavel, localizacao, TipoAtivo.SERVIDOR)

    def fator_exposicao(self) -> float:
        return 0.20  # Ativo central: alto impacto lateral


class Roteador(Equipamento):
    def __init__(self, id_ativo: int, hostname: str, responsavel: str, localizacao: str):
        super().__init__(id_ativo, hostname, responsavel, localizacao, TipoAtivo.ROTEADOR)

    def fator_exposicao(self) -> float:
        return 0.30  # Gateway: ponto critico de transmissao de dependencias


class EstacaoTrabalho(Equipamento):
    def __init__(self, id_ativo: int, hostname: str, responsavel: str, localizacao: str):
        super().__init__(id_ativo, hostname, responsavel, localizacao, TipoAtivo.ESTACAO_TRABALHO)

    def fator_exposicao(self) -> float:
        return 0.10  # Exposicao padrao de endpoint fixo